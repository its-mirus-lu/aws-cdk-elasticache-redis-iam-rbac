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
import { IPrincipal } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import path = require('path');


export interface RedisRbacUserProps {
  /** Redis Username that will be used in as ElastiCache user's username -- used to authenticate against Redis RBAC */
  redisUserName: string;
  /** User ID that will be used as the ElastiCache user's ID */
  redisUserId: string;
  /** Redis RBAC Access String see {@link https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Clusters.RBAC.html} for details*/
  accessString?: string;
  /** Optional: AWS KMS key used to encrypt the password secret; if not supplied one will be created */
  kmsKey?: kms.Key;
  /** Optional: A list of iam.IPrincipal that will be granted read access to the username and password stored in Secrets Manager*/
  principals?: iam.IPrincipal[];
  /** Optional: Secret rotation properties, see {@link SecretRotatorProps} */
  secretRotatorProps?: SecretRotatorProps;
  /** Optional: The ElastiCache VPC endpoint to connect to -- required if resources are to be placed in a private-isolated subnet */
  elasticacheVpcEndpoint?: ec2.InterfaceVpcEndpoint; 
  /** Optional: The ElastiCache VPC endpoint to connect to -- required if resources are to be placed in a private-isolated subnet */
  secretsManagerVpcEndpoint?: ec2.InterfaceVpcEndpoint;
}

export interface SecretRotatorProps {
  /** The VPC where the rotator Lambda function will be deployed */
  vpc: ec2.Vpc;
  /** Subnets into which the rotator Lambda functions will be placed */
  subnetSelection: ec2.SubnetSelection
  /** The amount of time between automatic rotations */
  rotationPeriod: Duration;
  /** The rotator Lambda timeout in number of seconds -- limit is 15 minutes (900 seconds) */
  rotatorTimeoutSeconds?: number
}

export class RedisRbacUser extends Construct {

  /** The Amazon Secrets Manager Secret that will store the ElastiCache user credentials */
  private rbacUserSecret: secretsmanager.Secret;

  /** ElastiCache username that will be used in the CfnUser construct */
  private rbacUserName: string;

  /** ElastiCache user id that will be used in the CfnUser construct */
  private rbacUserId: string;

  /** AWS KMS key used to encrypt the secret */
  private kmsKey: kms.Key;

  // Endpoint definitions
  private secretsManagerVpcEndpoint: ec2.InterfaceVpcEndpoint;
  private elasticacheVpcEndpoint: ec2.InterfaceVpcEndpoint;

  // Policy statements
  private secretResourceReadPolicyStatement: iam.PolicyStatement;

  private secretsManagerVpcEndpointReadPolicyStatement: iam.PolicyStatement;
  private secretsManagerReadVpcEndpointPolicyAdded = false

  private secretsManagerVpcEndpointReadWritePolicyStatement: iam.PolicyStatement;
  private secretsManagerReadWriteVpcEndpointPolicyAdded: boolean = false;
  
  private elasticacheVpcEndpointModifyUserPolicyStatement: iam.PolicyStatement;
  private elasticacheVpcEndpointStatementAdded: boolean = false;

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
      props.principals.forEach((item) => {
          this.grantReadSecret(item)
      });
    }

    if(props.secretRotatorProps){
      this.setSecretRotation(props.secretRotatorProps)
    }
  };

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

  private grantReadThroughSecretManagerVpcEndpoint(principal: IPrincipal){

    if (this.secretsManagerVpcEndpointReadPolicyStatement == null){

      this.secretsManagerVpcEndpointReadPolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
        resources: [this.rbacUserSecret.secretArn],
        principals: [principal]
      })

    } else {

      this.secretsManagerVpcEndpointReadPolicyStatement.addPrincipals(principal)

    }

    if(this.secretsManagerVpcEndpoint && !this.secretsManagerReadVpcEndpointPolicyAdded){

      this.secretsManagerVpcEndpoint.addToPolicy(this.secretsManagerVpcEndpointReadPolicyStatement)
      this.secretsManagerReadVpcEndpointPolicyAdded = true

    }
  }

  private grantReadWriteThroughSecretManagerVpcEndpoint(principal: IPrincipal){

    if (this.secretsManagerVpcEndpointReadWritePolicyStatement == null){

      this.secretsManagerVpcEndpointReadWritePolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:UpdateSecretVersionStage', 'secretsmanager:PutSecretValue', 'secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
        resources: [this.rbacUserSecret.secretArn],
        principals: [principal]
      })
      
    } else {

      this.secretsManagerVpcEndpointReadWritePolicyStatement.addPrincipals(principal)

    }

    if(this.secretsManagerVpcEndpoint && !this.secretsManagerReadWriteVpcEndpointPolicyAdded){

      this.secretsManagerVpcEndpoint.addToPolicy(this.secretsManagerVpcEndpointReadWritePolicyStatement)
      this.secretsManagerReadVpcEndpointPolicyAdded = true

    }
  }

  private grantModifyUserThroughElastiCacheVpcEndpoint(principal: IPrincipal){
    
    if (this.elasticacheVpcEndpointModifyUserPolicyStatement == null){

      this.elasticacheVpcEndpointModifyUserPolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        resources: ["arn:aws:elasticache:"+cdk.Stack.of(this).region+":"+cdk.Stack.of(this).account+":user:"+this.rbacUserId],
        actions: [
          "elasticache:DescribeUsers",
          "elasticache:ModifyUser"
        ],
        principals: [principal]
      })

    }
    else{

      this.elasticacheVpcEndpointModifyUserPolicyStatement.addPrincipals(principal)

    }

    if(this.elasticacheVpcEndpoint && !this.elasticacheVpcEndpointStatementAdded){

      this.elasticacheVpcEndpoint.addToPolicy(this.elasticacheVpcEndpointModifyUserPolicyStatement)
      this.elasticacheVpcEndpointStatementAdded = true

    }  
  }

  public grantReadSecret(principal: iam.IPrincipal){
    
    this.grantReadThroughSecretManagerVpcEndpoint(principal)
    
    if (this.secretResourceReadPolicyStatement == null) {

      this.secretResourceReadPolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
        resources: [this.rbacUserSecret.secretArn],
        principals: [principal]
      })

      this.rbacUserSecret.addToResourcePolicy(this.secretResourceReadPolicyStatement)
      
    } else {
      this.secretResourceReadPolicyStatement.addPrincipals(principal)
    }

    this.kmsKey.grantDecrypt(principal);
    this.rbacUserSecret.grantRead(principal)
  }

  private grantReadWriteSecret(principal: iam.IPrincipal){
    
    this.grantReadWriteThroughSecretManagerVpcEndpoint(principal)
    
    if (this.secretResourceReadPolicyStatement == null) {

      this.secretResourceReadPolicyStatement = new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:UpdateSecretVersionStage', 'secretsmanager:PutSecretValue', 'secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
        resources: [this.rbacUserSecret.secretArn],
        principals: [principal]
      })

      this.rbacUserSecret.addToResourcePolicy(this.secretResourceReadPolicyStatement)

    } else {

      this.secretResourceReadPolicyStatement.addPrincipals(principal)

    }

    this.kmsKey.grantEncryptDecrypt(principal)

    this.rbacUserSecret.grantRead(principal)
    this.rbacUserSecret.grantWrite(principal)
  }

  public setSecretRotation(secretRotatorProps:SecretRotatorProps){
    var rotatorRole: iam.Role;
    var rotatorTimeoutSeconds = secretRotatorProps.rotatorTimeoutSeconds ? secretRotatorProps.rotatorTimeoutSeconds: 900

    // Security group for the Rotator function
    const rotatorSecurityGroup = new ec2.SecurityGroup(this, "RotatorSG", {
      vpc: secretRotatorProps.vpc,
      description: "SecurityGroup for rotator function",
    });

    // Rotator function's role
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
    
    // The rotator function
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

    this.grantReadWriteSecret(rotatorRole)

    this.rbacUserSecret.addRotationSchedule(this.rbacUserName+"_rotation_schedule", {
      rotationLambda: rotatorFunction,
      automaticallyAfter: secretRotatorProps.rotationPeriod, 
    })

    // If an ElastiCache VPC endpoint is defined, then configure it to accept a connection from the rotator security group
    if(this.elasticacheVpcEndpoint){
      this.elasticacheVpcEndpoint.connections.allowTo(rotatorSecurityGroup, ec2.Port.tcp(443));
      this.elasticacheVpcEndpoint.connections.allowFrom(rotatorSecurityGroup, ec2.Port.tcp(443));
      this.grantModifyUserThroughElastiCacheVpcEndpoint(rotatorRole)
    }

    // If an Secrets Manager VPC endpoint is defined, then configure it to accept a connection from the rotator security group
    if(this.secretsManagerVpcEndpoint){
      this.secretsManagerVpcEndpoint.connections.allowTo(rotatorSecurityGroup, ec2.Port.tcp(443));
      this.secretsManagerVpcEndpoint.connections.allowFrom(rotatorSecurityGroup, ec2.Port.tcp(443));
      this.grantReadWriteThroughSecretManagerVpcEndpoint(rotatorRole)
      
      this.secretsManagerVpcEndpoint.addToPolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          resources: ["*"],
          actions: [
            "secretsmanager:GetRandomPassword"
          ],
          principals: [rotatorRole]
        })
      )
    }
  }
}

