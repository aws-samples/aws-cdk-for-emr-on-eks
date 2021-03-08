# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import aws_ec2 as ec2, aws_eks as eks, core, aws_emrcontainers as emrc, aws_iam as iam, aws_s3 as s3, custom_resources as custom, aws_acmpca as acmpca

"""
This stack deploys the following:
- EMR Studio
"""
class StudioLiveStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, vpc: ec2.IVpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create S3 bucket for Studio
        bucket = s3.Bucket(self, "StudioBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned = True
        )

        # Create security groups
        eng_sg = ec2.SecurityGroup(self, "EngineSecurityGroup",
            vpc=vpc,
            description="EMR Studio Engine",
            allow_all_outbound=True
        )
        ws_sg = ec2.SecurityGroup(self, "WorkspaceSecurityGroup",
            vpc=vpc,
            description="EMR Studio Workspace",
            allow_all_outbound=False
        )
        ws_sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "allow egress on port 443")
        ws_sg.add_egress_rule(eng_sg, ec2.Port.tcp(18888), "allow egress on port 18888 to eng")
        eng_sg.add_ingress_rule(ws_sg, ec2.Port.tcp(18888), "allow ingress on port 18888 from ws")

        # Create Studio roles
        role = iam.Role(self, "StudioRole",
            assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com")
        )
        role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:CreateSecurityGroup",
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:CreateNetworkInterface",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:DeleteNetworkInterface",
                "ec2:DeleteNetworkInterfacePermission",
                "ec2:DescribeNetworkInterfaces",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:DescribeTags",
                "ec2:DescribeInstances",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "elasticmapreduce:ListInstances",
                "elasticmapreduce:DescribeCluster",
                "elasticmapreduce:ListSteps"],
            effect=iam.Effect.ALLOW
        ))
        string_eq = core.CfnJson(self, "ConditionJsonEq",
            value={
                "aws:TagKeys": ["aws:elasticmapreduce:editor-id","aws:elasticmapreduce:job-flow-id"]
            }
        )
        role.add_to_policy(iam.PolicyStatement(
            resources=["arn:aws:ec2:*:*:network-interface/*"],
            actions=["ec2:CreateTags"],
            effect=iam.Effect.ALLOW,
            conditions={"ForAllValues:StringEquals": string_eq}
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=["arn:aws:s3:::*"],
            actions=["s3:PutObject","s3:GetObject","s3:GetEncryptionConfiguration","s3:ListBucket","s3:DeleteObject"],
            effect=iam.Effect.ALLOW
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=["arn:aws:secretsmanager:*:*:secret:*"],
            actions=["secretsmanager:GetSecretValue"],
            effect=iam.Effect.ALLOW
        ))

        user_role = iam.Role(self, "StudioUserRole",
            assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com")
        )
        user_role.add_to_policy(iam.PolicyStatement(
            actions=["elasticmapreduce:CreateEditor",
                    "elasticmapreduce:DescribeEditor",
                    "elasticmapreduce:ListEditors",
                    "elasticmapreduce:StartEditor",
                    "elasticmapreduce:StopEditor",
                    "elasticmapreduce:DeleteEditor",
                    "elasticmapreduce:OpenEditorInConsole",
                    "elasticmapreduce:AttachEditor",
                    "elasticmapreduce:DetachEditor",
                    "elasticmapreduce:CreateRepository",
                    "elasticmapreduce:DescribeRepository",
                    "elasticmapreduce:DeleteRepository",
                    "elasticmapreduce:ListRepositories",
                    "elasticmapreduce:LinkRepository",
                    "elasticmapreduce:UnlinkRepository",
                    "elasticmapreduce:DescribeCluster",
                    "elasticmapreduce:ListInstanceGroups",
                    "elasticmapreduce:ListBootstrapActions",
                    "elasticmapreduce:ListClusters",
                    "elasticmapreduce:ListSteps",
                    "elasticmapreduce:CreatePersistentAppUI",
                    "elasticmapreduce:DescribePersistentAppUI",
                    "elasticmapreduce:GetPersistentAppUIPresignedURL",
                    "secretsmanager:CreateSecret",
                    "secretsmanager:ListSecrets",
                    "emr-containers:DescribeVirtualCluster",
                    "emr-containers:ListVirtualClusters",
                    "emr-containers:DescribeManagedEndpoint",
                    "emr-containers:ListManagedEndpoints",
                    "emr-containers:CreateAccessTokenForManagedEndpoint",
                    "emr-containers:DescribeJobRun",
                    "emr-containers:ListJobRuns"],
            resources=["*"],
            effect=iam.Effect.ALLOW
        ))
        user_role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["servicecatalog:DescribeProduct",
                    "servicecatalog:DescribeProductView",
                    "servicecatalog:DescribeProvisioningParameters",
                    "servicecatalog:ProvisionProduct",
                    "servicecatalog:SearchProducts",
                    "servicecatalog:UpdateProvisionedProduct",
                    "servicecatalog:ListProvisioningArtifacts",
                    "servicecatalog:DescribeRecord",
                    "cloudformation:DescribeStackResources"],
            effect=iam.Effect.ALLOW
        ))
        user_role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["elasticmapreduce:RunJobFlow"],
            effect=iam.Effect.ALLOW
        ))
        user_role.add_to_policy(iam.PolicyStatement(
            resources=[role.role_arn,
                    f"arn:aws:iam::{self.account}:role/EMR_DefaultRole",
                    f"arn:aws:iam::{self.account}:role/EMR_EC2_DefaultRole"],
            actions=["iam:PassRole"],
            effect=iam.Effect.ALLOW
        ))
        user_role.add_to_policy(iam.PolicyStatement(
            resources=["arn:aws:s3:::*"],
            actions=["s3:ListAllMyBuckets",
                    "s3:ListBucket",
                    "s3:GetBucketLocation"],
            effect=iam.Effect.ALLOW
        ))
        user_role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:s3:::{bucket.bucket_name}/*",
                    f"arn:aws:s3:::aws-logs-{self.account}-{self.region}/elasticmapreduce/*"],
            actions=["s3:GetObject"],
            effect=iam.Effect.ALLOW
        ))

        policy_document = {
          "Version": "2012-10-17T00:00:00.000Z",
          "Statement": [
            {
              "Action": [
                "elasticmapreduce:CreateEditor",
                "elasticmapreduce:DescribeEditor",
                "elasticmapreduce:ListEditors",
                "elasticmapreduce:StartEditor",
                "elasticmapreduce:StopEditor",
                "elasticmapreduce:DeleteEditor",
                "elasticmapreduce:OpenEditorInConsole",
                "elasticmapreduce:AttachEditor",
                "elasticmapreduce:DetachEditor",
                "elasticmapreduce:CreateRepository",
                "elasticmapreduce:DescribeRepository",
                "elasticmapreduce:DeleteRepository",
                "elasticmapreduce:ListRepositories",
                "elasticmapreduce:LinkRepository",
                "elasticmapreduce:UnlinkRepository",
                "elasticmapreduce:DescribeCluster",
                "elasticmapreduce:ListInstanceGroups",
                "elasticmapreduce:ListBootstrapActions",
                "elasticmapreduce:ListClusters",
                "elasticmapreduce:ListSteps",
                "elasticmapreduce:CreatePersistentAppUI",
                "elasticmapreduce:DescribePersistentAppUI",
                "elasticmapreduce:GetPersistentAppUIPresignedURL",
                "secretsmanager:CreateSecret",
                "secretsmanager:ListSecrets",
                "emr-containers:DescribeVirtualCluster",
                "emr-containers:ListVirtualClusters",
                "emr-containers:DescribeManagedEndpoint",
                "emr-containers:ListManagedEndpoints",
                "emr-containers:CreateAccessTokenForManagedEndpoint",
                "emr-containers:DescribeJobRun",
                "emr-containers:ListJobRuns"
              ],
              "Resource": "*",
              "Effect": "Allow",
              "Sid": "AllowBasicActions"
            },
            {
              "Action": [
                "servicecatalog:DescribeProduct",
                "servicecatalog:DescribeProductView",
                "servicecatalog:DescribeProvisioningParameters",
                "servicecatalog:ProvisionProduct",
                "servicecatalog:SearchProducts",
                "servicecatalog:UpdateProvisionedProduct",
                "servicecatalog:ListProvisioningArtifacts",
                "servicecatalog:DescribeRecord",
                "cloudformation:DescribeStackResources"
              ],
              "Resource": "*",
              "Effect": "Allow",
              "Sid": "AllowIntermediateActions"
            },
            {
              "Action": [
                "elasticmapreduce:RunJobFlow"
              ],
              "Resource": "*",
              "Effect": "Allow",
              "Sid": "AllowAdvancedActions"
            },
            {
              "Action": "iam:PassRole",
              "Resource": [
                role.role_arn,
                f"arn:aws:iam::{self.account}:role/EMR_DefaultRole",
                f"arn:aws:iam::{self.account}:role/EMR_EC2_DefaultRole"
              ],
              "Effect": "Allow",
              "Sid": "PassRolePermission"
            },
            {
              "Action": [
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "s3:GetBucketLocation"
              ],
              "Resource": "arn:aws:s3:::*",
              "Effect": "Allow",
              "Sid": "S3ListPermission"
            },
            {
              "Action": [
                "s3:GetObject"
              ],
              "Resource": [
                f"arn:aws:s3:::{bucket.bucket_name}/*",
                f"arn:aws:s3:::aws-logs-{self.account}-{self.region}/elasticmapreduce/*"
              ],
              "Effect": "Allow",
              "Sid": "S3GetObjectPermission"
            }
          ]
        }
        custom_policy_document = iam.PolicyDocument.from_json(policy_document)
        new_managed_policy = iam.ManagedPolicy(self, "LBControlPolicy",
            document=custom_policy_document
        )

        # Set up Studio
        custom_policy_document = iam.PolicyDocument(statements=[
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iam:PassRole"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["sso:*"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["sso-directory:*"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["emr:*"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:*"],
                resources=["*"]
            )
        ])
        managed_policy = iam.ManagedPolicy(self, "EmrPolicy",
            document=custom_policy_document
        )
        studio = custom.AwsCustomResource(self, "CreateStudio",
            on_create={
                "service": "EMR",
                "action": "createStudio",
                "parameters": {
                    "AuthMode": "SSO",
                    "EngineSecurityGroupId": eng_sg.security_group_id,
                    "Name": "EmrEksStudio",
                    "ServiceRole": role.role_arn,
                    "SubnetIds": [n.subnet_id for n in vpc.private_subnets],
                    "UserRole": user_role.role_arn,
                    "VpcId": vpc.vpc_id,
                    "WorkspaceSecurityGroupId": ws_sg.security_group_id,
                    "DefaultS3Location": f"s3://{bucket.bucket_name}/studio/",
                },
                "physical_resource_id": custom.PhysicalResourceId.from_response("StudioId")},
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(resources=custom.AwsCustomResourcePolicy.ANY_RESOURCE),
            function_name="CreateStudioFn",
            role = iam.Role(
                    scope=self,
                    id=f'{construct_id}-LambdaRole',
                    assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                        managed_policy
                    ]
                )
        )
        core.CfnOutput(
            self, "StudioUrl",
            value=studio.get_response_field("Url")
        )

        # Create session mapping
        studiosm = custom.AwsCustomResource(self, "CreateStudioSM",
            on_create={
                "service": "EMR",
                "action": "createStudioSessionMapping",
                "parameters": {
                    "StudioId": studio.get_response_field("StudioId"),
                    "IdentityType": "USER",
                    "SessionPolicyArn": new_managed_policy.managed_policy_arn,
                    "IdentityName": self.node.try_get_context("username")
                },
                "physical_resource_id": custom.PhysicalResourceId.of("StudioSM")},
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(resources=custom.AwsCustomResourcePolicy.ANY_RESOURCE),
            function_name="CreateStudioSMFn",
            role = iam.Role(
                    scope=self,
                    id=f'{construct_id}-SMLambdaRole',
                    assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                        managed_policy
                    ]
                )
        )
