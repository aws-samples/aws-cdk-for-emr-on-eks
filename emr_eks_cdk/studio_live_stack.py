# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import aws_ec2 as ec2, aws_eks as eks, core, aws_emrcontainers as emrc, aws_iam as iam, aws_s3 as s3, custom_resources as custom, aws_acmpca as acmpca, aws_emr as emr

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
        core.Tags.of(eng_sg).add("for-use-with-amazon-emr-managed-policies", "true")
        ws_sg = ec2.SecurityGroup(self, "WorkspaceSecurityGroup",
            vpc=vpc,
            description="EMR Studio Workspace",
            allow_all_outbound=False
        )
        core.Tags.of(ws_sg).add("for-use-with-amazon-emr-managed-policies", "true")
        ws_sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "allow egress on port 443")
        ws_sg.add_egress_rule(eng_sg, ec2.Port.tcp(18888), "allow egress on port 18888 to eng")
        eng_sg.add_ingress_rule(ws_sg, ec2.Port.tcp(18888), "allow ingress on port 18888 from ws")

        # Create Studio roles
        role = iam.Role(self, "StudioRole",
            assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess")
            ]
        )
        role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:CreateSecurityGroup",
                "ec2:CreateTags",
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
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
        core.Tags.of(role).add("for-use-with-amazon-emr-managed-policies", "true")

        user_role = iam.Role(self, "StudioUserRole",
            assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com")
        )
        core.Tags.of(role).add("for-use-with-amazon-emr-managed-policies", "true")
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
                    "secretsmanager:TagResource",
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
        studio = emr.CfnStudio(self, "MyEmrStudio", 
            auth_mode = "SSO", default_s3_location = f"s3://{bucket.bucket_name}/studio/", 
            engine_security_group_id = eng_sg.security_group_id, 
            name = "MyEmrEksStudio", 
            service_role = role.role_arn, 
            subnet_ids = [n.subnet_id for n in vpc.private_subnets], 
            user_role = user_role.role_arn, 
            vpc_id = vpc.vpc_id, 
            workspace_security_group_id = ws_sg.security_group_id, 
            description=None, 
            tags=None)
        core.CfnOutput(
            self, "StudioUrl",
            value=studio.attr_url
        )

        # Create session mapping
        studiosm = emr.CfnStudioSessionMapping(self, "MyStudioSM", 
            identity_name = self.node.try_get_context("username"), 
            identity_type = "USER", 
            session_policy_arn = new_managed_policy.managed_policy_arn, 
            studio_id = studio.attr_studio_id)