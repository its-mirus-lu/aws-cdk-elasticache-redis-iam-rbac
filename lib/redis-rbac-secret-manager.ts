/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import * as cdk from 'aws-cdk-lib';
import { 
  aws_kms as kms, 
  aws_iam as iam, 
  aws_ec2 as ec2,
  aws_lambda as lambda,
  aws_elasticache as elasticache, 
  aws_secretsmanager as secretsmanager,
  Duration} from 'aws-cdk-lib';
import { ISubnet } from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';
import path = require('path');

export interface RedisRbacUserProps {
  redisUserName: string;
  redisUserId: string;
  accessString?: string;
  kmsKey?: kms.Key;
  principals?: iam.IPrincipal[];
  redisRbacRotatorProps?: RedisRbacRotatorProps
}

export interface RedisRbacRotatorProps {
  vpc: ec2.Vpc;
  subnets: ec2.SubnetSelection
  securityGroups: [ec2.SecurityGroup];
  rotationSchedule: Duration;
  elasticacheReplicationGroup?: elasticache.CfnReplicationGroup;
  redisPyLayer?: lambda.LayerVersion;
  rotatorRole?: iam.Role
}

export class RedisRbacUser extends Construct {
  public readonly response: string;

  private rbacUserSecret: secretsmanager.Secret;
  private secretResourcePolicyStatement: iam.PolicyStatement;
  private rbacUserName: string;
  private rbacUserId: string;
  private kmsKey: kms.Key;

  public getSecret(): secretsmanager.Secret {
    return this.rbacUserSecret;
  }

  public getUserName(): string {
    return this.rbacUserName;
  }

  public getUserId(): string{
    return this.rbacUserId;
  }

  public getKmsKey(): kms.Key {
    return this.kmsKey;
  }

  public grantReadSecret(principal: iam.IPrincipal){
    if (this.secretResourcePolicyStatement == null) {
      this.secretResourcePolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
        resources: [this.rbacUserSecret.secretArn],
        principals: [principal]
      })

      this.rbacUserSecret.addToResourcePolicy(this.secretResourcePolicyStatement)

    } else {
      this.secretResourcePolicyStatement.addPrincipals(principal)
    }
    this.kmsKey.grantDecrypt(principal);
    this.rbacUserSecret.grantRead(principal)
  }

  constructor(scope: Construct, id: string, props: RedisRbacUserProps) {
    super(scope, id);

    this.rbacUserId = props.redisUserId
    this.rbacUserName = props.redisUserName

    if (!props.kmsKey) {
      this.kmsKey = new kms.Key(this, 'kmsForSecret', {
        alias: 'redisRbacUser/'+this.rbacUserName,
        enableKeyRotation: true
      });
    } else {
      this.kmsKey = props.kmsKey;
    }

    this.rbacUserSecret = new secretsmanager.Secret(this, 'secret', {
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: props.redisUserName }),
        generateStringKey: 'password',
        excludeCharacters: '@%*()_+=`~{}|[]\\:";\'?,./'
      },
      encryptionKey: this.kmsKey
    });

    const user = new elasticache.CfnUser(this, 'redisuser', {
      engine: 'redis',
      userName: props.redisUserName,
      accessString: props.accessString? props.accessString : "off +get ~keys*",
      userId: props.redisUserId,
      passwords: [this.rbacUserSecret.secretValueFromJson('password').unsafeUnwrap()]
    })

    user.node.addDependency(this.rbacUserSecret)

    if(props.principals){
      props.principals.forEach( (item) => {
          this.grantReadSecret(item)
      });
    }

    if(props.redisRbacRotatorProps){

      var redisPyLayer: lambda.LayerVersion;
      var rotatorRole: iam.Role;

      // if(props.redisRbacRotatorProps.redisPyLayer){
      //   redisPyLayer = props.redisRbacRotatorProps.redisPyLayer
      // } else {
      //   redisPyLayer = Singleton.getInstance(scope)
      // }

      // if(props.redisRbacRotatorProps.rotatorRole){
      //   rotatorRole = props.redisRbacRotatorProps.rotatorRole
      // } else {
      rotatorRole = new iam.Role(this, this.rbacUserName+"_secret_rotator_role", {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        description: 'Role to be assumed by secret rotator function for '+this.rbacUserName,
      })
      rotatorRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"));
      rotatorRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaVPCAccessExecutionRole"));
      rotatorRole.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: [this.rbacUserSecret.secretArn],
          actions: [
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecretVersionStage",
          ]
        })
      );
      rotatorRole.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: ["*"],
          actions: [
            "secretsmanager:GetRandomPassword"
          ]
        })
      );
      rotatorRole.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: ["arn:aws:elasticache:"+cdk.Stack.of(this).region+":"+cdk.Stack.of(this).account+":user:"+this.rbacUserId],
          actions: [
            "elasticache:DescribeUsers",
            "elasticache:ModifyUser"
          ]
        })
      );
      }

      const rotatorFunction = new lambda.Function(this, 'function', {
        runtime: lambda.Runtime.PYTHON_3_7,
        handler: 'lambda_handler.lambda_handler',
        code: lambda.Code.fromAsset(path.join(__dirname, 'lambda_rotator_rbac_user')),
        // layers: [redisPyLayer],
        role: rotatorRole,
        timeout: cdk.Duration.seconds(30),
        vpc: props.redisRbacRotatorProps.vpc,
        vpcSubnets: {subnetType: ec2.SubnetType.PRIVATE_ISOLATED},
        securityGroups: props.redisRbacRotatorProps.securityGroups,
        environment: {
          // replicationGroupId: props.redisRbacRotatorProps.elasticacheReplicationGroup.ref,
          // redis_endpoint: props.redisRbacRotatorProps.elasticacheReplicationGroup.attrPrimaryEndPointAddress,
          // redis_port: props.redisRbacRotatorProps.elasticacheReplicationGroup.attrPrimaryEndPointPort,
          EXCLUDE_CHARACTERS: '@%*()_+=`~{}|[]\\:";\'?,./',
          SECRETS_MANAGER_ENDPOINT: "https://secretsmanager."+cdk.Stack.of(this).region+".amazonaws.com",
          SECRET_ARN: this.rbacUserSecret.secretArn,
          USER_NAME: this.rbacUserName
        }
      });

      this.rbacUserSecret.addRotationSchedule(this.rbacUserName+"_rotation_schedule", {
        rotationLambda: rotatorFunction,
        automaticallyAfter: props.redisRbacRotatorProps.rotationSchedule, 
      })
  
    }

    
  };

}

class Singleton {
  private static instance: Singleton;
  private static layer: lambda.LayerVersion

  private constructor(scope: Construct) {
    this.createLayer(scope)
    
  }

  private createLayer(scope: Construct){
    Singleton.layer = new lambda.LayerVersion(scope, 'redispy_Layer', {
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/lib/redis_module/redis_py.zip')),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_8, lambda.Runtime.PYTHON_3_7],
      description: 'A layer that contains the redispy module',
      license: 'MIT License'
    });
    return Singleton.instance
  }

  // public static getLayer(): lambda.LayerVersion {
  //   return instance
  // }

  
  public static getInstance(scope: Construct): lambda.LayerVersion {

    if (!Singleton.instance) {

      Singleton.instance = new Singleton(scope);
    }

    return Singleton.layer;
  }
}
