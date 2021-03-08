# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import core, aws_iam as iam, aws_s3 as s3, aws_s3_deployment as s3deploy, aws_mwaa as mwaa, custom_resources as custom, aws_ec2 as ec2
from typing import List

"""
This stack deploys the following:
- S3 bucket with dependencies uploaded
- MWAA role
- MWAA environment
"""
class MwaaStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, subnets: List[str], vpc: ec2.IVpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.env_name = "MwaaForEmrOnEks"
        self.prefix_list_id = self.node.try_get_context("prefix")

        # Create S3 bucket for MWAA
        bucket = s3.Bucket(self, "MwaaBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned = True
        )
        core.CfnOutput(
            self, "BucketName",
            value=bucket.bucket_name
        )

        # Create MWAA role
        role = iam.Role(self, "MwaaRole",
            assumed_by=iam.ServicePrincipal("airflow-env.amazonaws.com")
        )
        role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:airflow:{self.region}:{self.account}:environment/{self.env_name}"],
            actions=["airflow:PublishMetrics"],
            effect=iam.Effect.ALLOW
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:s3:::{bucket.bucket_name}",f"arn:aws:s3:::{bucket.bucket_name}/*"],
            actions=["s3:ListAllMyBuckets"],
            effect=iam.Effect.DENY
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:s3:::{bucket.bucket_name}",f"arn:aws:s3:::{bucket.bucket_name}/*"],
            actions=["s3:GetObject*","s3:GetBucket*","s3:List*"],
            effect=iam.Effect.ALLOW
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:airflow-{self.env_name}-*"],
            actions=["logs:CreateLogStream",
                "logs:CreateLogGroup",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:GetLogRecord",
                "logs:GetLogGroupFields",
                "logs:GetQueryResults",
                "logs:DescribeLogGroups"],
            effect=iam.Effect.ALLOW
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["cloudwatch:PutMetricData"],
            effect=iam.Effect.ALLOW
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=[
                "emr-containers:StartJobRun",
                "emr-containers:ListJobRuns",
                "emr-containers:DescribeJobRun",
                "emr-containers:CancelJobRun"
            ],
            effect=iam.Effect.ALLOW
        ))
        role.add_to_policy(iam.PolicyStatement(
            resources=[f"arn:aws:sqs:{self.region}:*:airflow-celery-*"],
            actions=["sqs:ChangeMessageVisibility",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes",
                "sqs:GetQueueUrl",
                "sqs:ReceiveMessage",
                "sqs:SendMessage"],
            effect=iam.Effect.ALLOW
        ))
        string_like = core.CfnJson(self, "ConditionJson",
            value={
                f"kms:ViaService": f"sqs.{self.region}.amazonaws.com"
            }
        )
        role.add_to_policy(iam.PolicyStatement(
            not_resources=[f"arn:aws:kms:*:{self.account}:key/*"],
            actions=["kms:Decrypt",
                "kms:DescribeKey",
                "kms:GenerateDataKey*",
                "kms:Encrypt"],
            effect=iam.Effect.ALLOW,
            conditions={"StringLike": string_like}
        ))

        # Upload MWAA pre-reqs
        s3deploy.BucketDeployment(self, "DeployPlugin",
            sources=[s3deploy.Source.asset("./emr_eks_cdk/mwaa_plugins", exclude= ['**', '!emr_containers_airflow_plugin.zip'])],
            destination_bucket=bucket,
            destination_key_prefix="plug-ins"
        )
        s3req = s3deploy.BucketDeployment(self, "DeployReq",
            sources=[s3deploy.Source.asset("./emr_eks_cdk/mwaa_plugins", exclude= ['**', '!requirements.txt'])],
            destination_bucket=bucket,
            destination_key_prefix="Requirements"
        )
        s3deploy.BucketDeployment(self, "DeployDag",
            sources=[s3deploy.Source.asset("./emr_eks_cdk/mwaa_plugins", exclude= ['**', '!emr_eks.py'])],
            destination_bucket=bucket,
            destination_key_prefix="DAG"
        )

        # Get object versions
        req_obj_version = custom.AwsCustomResource(self, "GetReqV",
            on_update={
                "service": "S3",
                "action": "headObject",
                "parameters": {
                    "Bucket": bucket.bucket_name,
                    "Key": "Requirements/requirements.txt"
                },
                "physical_resource_id": custom.PhysicalResourceId.from_response("VersionId")},
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(resources=custom.AwsCustomResourcePolicy.ANY_RESOURCE),
            role = iam.Role(
                    scope=self,
                    id=f'{construct_id}-LambdaRole',
                    assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                        iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess")
                    ]
                )
        )
        core.CfnOutput(
            self, "ReqObjVersion",
            value=req_obj_version.get_response_field("VersionId")
        )
        plugin_obj_version = custom.AwsCustomResource(self, "GetPluginV",
            on_update={
                "service": "S3",
                "action": "headObject",
                "parameters": {
                    "Bucket": bucket.bucket_name,
                    "Key": "plug-ins/emr_containers_airflow_plugin.zip"
                },
                "physical_resource_id": custom.PhysicalResourceId.from_response("VersionId")},
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(resources=custom.AwsCustomResourcePolicy.ANY_RESOURCE),
            role = iam.Role(
                    scope=self,
                    id=f'{construct_id}-LambdaRole-2',
                    assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                        iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess")
                    ]
                )
        )
        core.CfnOutput(
            self, "PluginObjVersion",
            value=plugin_obj_version.get_response_field("VersionId")
        )

        # Create security group
        mwaa_sg = ec2.SecurityGroup(self, "SecurityGroup",
            vpc=vpc,
            description="Allow inbound access to MWAA",
            allow_all_outbound=True
        )
        mwaa_sg.add_ingress_rule(ec2.Peer.prefix_list(self.prefix_list_id), ec2.Port.all_tcp(), "allow inbound access from the prefix list")
        mwaa_sg.add_ingress_rule(mwaa_sg, ec2.Port.all_traffic(), "allow inbound access from the SG")

        mwaa_env = mwaa.CfnEnvironment(self, "MWAAEnv", 
            name = self.env_name,
            dag_s3_path="DAG",
            environment_class="mw1.small",
            execution_role_arn=role.role_arn,
            logging_configuration = mwaa.CfnEnvironment.LoggingConfigurationProperty(
                dag_processing_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(enabled=True, log_level='INFO'),
                scheduler_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(enabled=True, log_level='INFO'),
                task_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(enabled=True, log_level='INFO'),
                webserver_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(enabled=True, log_level='INFO'),
                worker_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(enabled=True, log_level='INFO')
            ),
            network_configuration=mwaa.CfnEnvironment.NetworkConfigurationProperty(
                security_group_ids=[mwaa_sg.security_group_id],
                subnet_ids=subnets
            ),
            plugins_s3_path="plug-ins/emr_containers_airflow_plugin.zip",
            plugins_s3_object_version=plugin_obj_version.get_response_field("VersionId"),
            requirements_s3_path="Requirements/requirements.txt",
            requirements_s3_object_version=req_obj_version.get_response_field("VersionId"),
            source_bucket_arn=bucket.bucket_arn, 
            webserver_access_mode='PUBLIC_ONLY'
        )
        core.CfnOutput(
            self, "MWAA_NAME", value=self.env_name
        )
