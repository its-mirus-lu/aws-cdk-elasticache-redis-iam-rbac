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
import { PropagatedTagSource } from 'aws-cdk-lib/aws-ecs';
import { Construct } from 'constructs';
import internal = require('events');
import path = require('path');
import { print } from 'util';

export interface RedisRbacUserProps {
  redisUserName: string;
  redisUserId: string;
  accessString?: string;
  kmsKey?: kms.Key;
  principals?: iam.IPrincipal[];
  secretRotatorProps?: SecretRotatorProps;
  elasticacheVpcEndpoint?: ec2.InterfaceVpcEndpoint;
  secretsManagerVpcEndpoint?: ec2.InterfaceVpcEndpoint;
}

export interface SecretRotatorProps {
  vpc: ec2.Vpc;
  subnets: ec2.SubnetSelection
  rotationSchedule: Duration;
  elasticacheReplicationGroup?: elasticache.CfnReplicationGroup;
  rotatorSecurityGroups?: ec2.SecurityGroup[];
  redisPyLayer?: lambda.LayerVersion;
  rotatorRole?: iam.Role;
  rotatorTimeoutSeconds?: number
}

export class RedisRbacUser extends Construct {
  public readonly response: string;

  private rbacUserSecret: secretsmanager.Secret;
  private secretResourcePolicyStatement: iam.PolicyStatement;
  private secretsManagerVpcResourcePolicyStatement: iam.PolicyStatement;
  private rbacUserName: string;
  private rbacUserId: string;
  private kmsKey: kms.Key;
  private readerPrincipals: iam.IPrincipal[] = []
  private secretsManagerVpcEndpoint: ec2.InterfaceVpcEndpoint;
  private elasticacheVpcEndpoint: ec2.InterfaceVpcEndpoint;
  private secretsManagerVpcEndpointPolicyAdded = false

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


  constructor(scope: Construct, id: string, props: RedisRbacUserProps) {
    super(scope, id);

    this.rbacUserId = props.redisUserId
    this.rbacUserName = props.redisUserName

    if (props.secretsManagerVpcEndpoint){
      this.secretsManagerVpcEndpoint = props.secretsManagerVpcEndpoint
    }

    if(props.elasticacheVpcEndpoint){
      this.elasticacheVpcEndpoint = props.elasticacheVpcEndpoint
    }
    
    
    
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
        secretStringTemplate: JSON.stringify({ 
          username: props.redisUserName, 
          user_arn: "arn:aws:elasticache:"+cdk.Stack.of(this).region+":"+cdk.Stack.of(this).account+":user:"+this.rbacUserId }),
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

    if(props.secretRotatorProps){
      this.setSecretRotator(props.secretRotatorProps)
    }

  };


  public grantReadSecret(principal: iam.IPrincipal){
    if (this.secretsManagerVpcResourcePolicyStatement == null){
      this.secretsManagerVpcResourcePolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
        resources: [this.rbacUserSecret.secretArn],
        principals: [principal]
      })
      
      if(this.secretsManagerVpcEndpoint){
        this.secretsManagerVpcEndpoint.addToPolicy(this.secretsManagerVpcResourcePolicyStatement)
        this.secretsManagerVpcEndpointPolicyAdded = true
      }
    } else {
      this.secretsManagerVpcResourcePolicyStatement.addPrincipals(principal)
    }
    
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

  public setSecretRotator(secretRotatorProps:SecretRotatorProps){
    var rotatorRole: iam.Role;
    var rotatorTimeoutSeconds = secretRotatorProps.rotatorTimeoutSeconds ? secretRotatorProps.rotatorTimeoutSeconds: 30

    const rotatorSecurityGroup = new ec2.SecurityGroup(this, "RotatorSG", {
      vpc: secretRotatorProps.vpc,
      description: "SecurityGroup for rotator function",
    });

    // Mirus: do I need to do this?
    rotatorSecurityGroup.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.allTraffic(),
      "All port inbound"
    );

    rotatorRole = new iam.Role(this, "secret_rotator_role", {
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
    
    const rotatorFunction = new lambda.Function(this, 'rotator', {
      runtime: lambda.Runtime.PYTHON_3_7,
      handler: 'lambda_handler.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda_rotator_rbac_user')),
      role: rotatorRole,
      timeout: cdk.Duration.seconds(rotatorTimeoutSeconds),
      vpc: secretRotatorProps.vpc,
      vpcSubnets: {subnetType: ec2.SubnetType.PRIVATE_ISOLATED},
      securityGroups: [rotatorSecurityGroup],
      environment: {
        EXCLUDE_CHARACTERS: '@%*()_+=`~{}|[]\\:";\'?,./',
        SECRETS_MANAGER_ENDPOINT: "https://secretsmanager."+cdk.Stack.of(this).region+".amazonaws.com",
        ELASTICACHE_ENDPOINT: "https://elasticache."+cdk.Stack.of(this).region+".amazonaws.com",
        SECRET_ARN: this.rbacUserSecret.secretArn,
        USER_NAME: this.rbacUserName
      }
    });

    this.rbacUserSecret.grantRead(rotatorRole)
    this.rbacUserSecret.grantWrite(rotatorRole)

    this.rbacUserSecret.addRotationSchedule(this.rbacUserName+"_rotation_schedule", {
      rotationLambda: rotatorFunction,
      automaticallyAfter: secretRotatorProps.rotationSchedule, 
    })

    if(this.elasticacheVpcEndpoint){
      this.elasticacheVpcEndpoint.connections.allowTo(rotatorSecurityGroup, ec2.Port.tcp(443));
      this.elasticacheVpcEndpoint.connections.allowFrom(rotatorSecurityGroup, ec2.Port.tcp(443));
      
      this.elasticacheVpcEndpoint.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: ["arn:aws:elasticache:"+cdk.Stack.of(this).region+":"+cdk.Stack.of(this).account+":user:"+this.rbacUserId],
          actions: [
            "elasticache:DescribeUsers",
            "elasticache:ModifyUser"
          ],
          principals: [rotatorRole]
        })
      )
    }

    console.log("doesnsecretsmanager endpoint exist??"+String(this.secretsManagerVpcEndpoint))
    if(this.secretsManagerVpcEndpoint){
      console.log("secretsmanager endpoint exists")
      this.secretsManagerVpcEndpoint.connections.allowTo(rotatorSecurityGroup, ec2.Port.tcp(443));
      this.secretsManagerVpcEndpoint.connections.allowFrom(rotatorSecurityGroup, ec2.Port.tcp(443));
      
      this.secretsManagerVpcEndpoint.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: [this.rbacUserSecret.secretArn],
          actions: [
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecretVersionStage",
          ],
          principals: [rotatorRole]
        })
      );
      
      this.secretsManagerVpcEndpoint.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: ["*"],
          actions: [
            "secretsmanager:GetRandomPassword"
          ],
          principals: [rotatorRole]
        })
      );

      if (!this.secretsManagerVpcEndpointPolicyAdded){
        this.secretsManagerVpcEndpoint.addToPolicy(this.secretsManagerVpcResourcePolicyStatement)
        this.secretsManagerVpcEndpointPolicyAdded = true
      }
    }
  }
}

