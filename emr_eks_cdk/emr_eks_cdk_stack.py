# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import aws_ec2 as ec2, aws_eks as eks, core, aws_emrcontainers as emrc, aws_iam as iam, aws_logs as logs, custom_resources as custom

"""
This stack deploys the following:
- VPC
- EKS cluster
- EKS configuration to support EMR on EKS
- EMR on EKS virtual cluster
- CloudWatch log group
"""
class EmrEksCdkStack(core.Stack):


    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.emr_namespace = "sparkns"
        self.emr_namespace_fg = "sparkfg"
        self.emrsvcrolearn = f"arn:aws:iam::{self.account}:role/AWSServiceRoleForAmazonEMRContainers"
        self.instance_type = self.node.try_get_context("instance")

        # VPC
        self.vpc = ec2.Vpc(
            self,
            "EMR-EKS-VPC",
            max_azs=3
        )
        core.Tags.of(self.vpc).add("for-use-with-amazon-emr-managed-policies", "true")

        # EKS cluster
        self.cluster = eks.Cluster(self, "EksForSpark",
            version=eks.KubernetesVersion.V1_18,
            default_capacity=0,
            endpoint_access=eks.EndpointAccess.PUBLIC_AND_PRIVATE,
            vpc=self.vpc,
            vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)]
        )


        # Default node group
        self.ng = self.cluster.add_nodegroup_capacity("base-node-group",
            instance_types=[ec2.InstanceType(self.instance_type)],
            min_size=3,
            max_size=10,
            disk_size=50
        )

        # Create namespaces for EMR to use
        namespace = self.cluster.add_manifest(self.emr_namespace, {
            "apiVersion":"v1",
            "kind":"Namespace",
            "metadata":{"name": self.emr_namespace},
        })
        namespace_fg = self.cluster.add_manifest(self.emr_namespace_fg, {
            "apiVersion":"v1",
            "kind":"Namespace",
            "metadata":{"name": self.emr_namespace_fg},
        })

        # Fargate profile
        fgprofile = eks.FargateProfile(self, "SparkFargateProfile", cluster=self.cluster, 
            selectors=[{"namespace": self.emr_namespace_fg}]
        )

        # Create k8s cluster role for EMR
        emrrole = self.cluster.add_manifest("emrrole", {
            "apiVersion":"rbac.authorization.k8s.io/v1",
            "kind":"Role",
            "metadata":{"name": "emr-containers", "namespace": self.emr_namespace},
            "rules": [
                {"apiGroups": [""], "resources":["namespaces"],"verbs":["get"]},
                {"apiGroups": [""], "resources":["serviceaccounts", "services", "configmaps", "events", "pods", "pods/log"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "deletecollection", "annotate", "patch", "label"]},
                {"apiGroups": [""], "resources":["secrets"],"verbs":["create", "patch", "delete", "watch"]},
                {"apiGroups": ["apps"], "resources":["statefulsets", "deployments"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "annotate", "patch", "label"]},
                {"apiGroups": ["batch"], "resources":["jobs"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "annotate", "patch", "label"]},
                {"apiGroups": ["extensions"], "resources":["ingresses"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "annotate", "patch", "label"]},
                {"apiGroups": ["rbac.authorization.k8s.io"], "resources":["roles", "rolebindings"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "deletecollection", "annotate", "patch", "label"]}
            ]
        })
        emrrole.node.add_dependency(namespace)
        emrrole_fg = self.cluster.add_manifest("emrrole_fg", {
            "apiVersion":"rbac.authorization.k8s.io/v1",
            "kind":"Role",
            "metadata":{"name": "emr-containers", "namespace": self.emr_namespace_fg},
            "rules": [
                {"apiGroups": [""], "resources":["namespaces"],"verbs":["get"]},
                {"apiGroups": [""], "resources":["serviceaccounts", "services", "configmaps", "events", "pods", "pods/log"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "deletecollection", "annotate", "patch", "label"]},
                {"apiGroups": [""], "resources":["secrets"],"verbs":["create", "patch", "delete", "watch"]},
                {"apiGroups": ["apps"], "resources":["statefulsets", "deployments"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "annotate", "patch", "label"]},
                {"apiGroups": ["batch"], "resources":["jobs"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "annotate", "patch", "label"]},
                {"apiGroups": ["extensions"], "resources":["ingresses"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "annotate", "patch", "label"]},
                {"apiGroups": ["rbac.authorization.k8s.io"], "resources":["roles", "rolebindings"],"verbs":["get", "list", "watch", "describe", "create", "edit", "delete", "deletecollection", "annotate", "patch", "label"]}
            ]
        })
        emrrole_fg.node.add_dependency(namespace_fg)

        # Bind cluster role to user
        emrrolebind = self.cluster.add_manifest("emrrolebind", {
            "apiVersion":"rbac.authorization.k8s.io/v1",
            "kind":"RoleBinding",
            "metadata":{"name": "emr-containers", "namespace": self.emr_namespace},
            "subjects":[{"kind": "User","name":"emr-containers","apiGroup": "rbac.authorization.k8s.io"}],
            "roleRef":{"kind":"Role","name":"emr-containers","apiGroup": "rbac.authorization.k8s.io"}
        })
        emrrolebind.node.add_dependency(emrrole)
        emrrolebind_fg = self.cluster.add_manifest("emrrolebind_fg", {
            "apiVersion":"rbac.authorization.k8s.io/v1",
            "kind":"RoleBinding",
            "metadata":{"name": "emr-containers", "namespace": self.emr_namespace_fg},
            "subjects":[{"kind": "User","name":"emr-containers","apiGroup": "rbac.authorization.k8s.io"}],
            "roleRef":{"kind":"Role","name":"emr-containers","apiGroup": "rbac.authorization.k8s.io"}
        })
        emrrolebind_fg.node.add_dependency(emrrole_fg)

        # Map user to IAM role
        emrsvcrole = iam.Role.from_role_arn(self, "EmrSvcRole", self.emrsvcrolearn, mutable=False)
        self.cluster.aws_auth.add_role_mapping(emrsvcrole, groups=[], username="emr-containers")

         # Job execution role
        self.job_role = iam.Role(self, "EMR_EKS_Job_Role", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2FullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSGlueConsoleFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess")])
        core.CfnOutput(
            self, "JobRoleArn",
            value=self.job_role.role_arn
        )

        # Modify trust policy
        string_like = core.CfnJson(self, "ConditionJson",
            value={
                f"{self.cluster.cluster_open_id_connect_issuer}:sub": f"system:serviceaccount:emr:emr-containers-sa-*-*-{self.account}-*"
            }
        )
        self.job_role.assume_role_policy.add_statements(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["sts:AssumeRoleWithWebIdentity"],
                principals=[iam.OpenIdConnectPrincipal(self.cluster.open_id_connect_provider, conditions={"StringLike": string_like})]
            )
        )
        string_aud = core.CfnJson(self, "ConditionJsonAud",
            value={
                f"{self.cluster.cluster_open_id_connect_issuer}:aud": "sts.amazon.com"
            }
        )
        self.job_role.assume_role_policy.add_statements(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["sts:AssumeRoleWithWebIdentity"],
                principals=[iam.OpenIdConnectPrincipal(self.cluster.open_id_connect_provider, conditions={"StringEquals": string_aud})]
            )
        )

         # EMR virtual cluster
        self.emr_vc = emrc.CfnVirtualCluster(scope=self,
            id="EMRCluster",
            container_provider=emrc.CfnVirtualCluster.ContainerProviderProperty(id=self.cluster.cluster_name,
                info=emrc.CfnVirtualCluster.ContainerInfoProperty(eks_info=emrc.CfnVirtualCluster.EksInfoProperty(namespace=self.emr_namespace)),
                type="EKS"
            ),
            name="EMRCluster"
        )
        self.emr_vc.node.add_dependency(namespace) 
        self.emr_vc.node.add_dependency(emrrolebind) 
        emr_vc_fg = emrc.CfnVirtualCluster(scope=self,
            id="EMRClusterFG",
            container_provider=emrc.CfnVirtualCluster.ContainerProviderProperty(id=self.cluster.cluster_name,
                info=emrc.CfnVirtualCluster.ContainerInfoProperty(eks_info=emrc.CfnVirtualCluster.EksInfoProperty(namespace=self.emr_namespace_fg)),
                type="EKS"
            ),
            name="EMRClusterFG"
        )
        emr_vc_fg.node.add_dependency(namespace_fg) 
        emr_vc_fg.node.add_dependency(emrrolebind_fg) 
        core.CfnOutput(
            self, "VirtualClusterId",
            value=self.emr_vc.attr_id
        )
        core.CfnOutput(
            self, "FgVirtualClusterId",
            value=emr_vc_fg.attr_id
        )

        # Create log group
        log_group = logs.LogGroup(self, "LogGroup") 
        core.CfnOutput(
            self, "LogGroupName",
            value=log_group.log_group_name
        )

        # LB Controller role
        self.policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateServiceLinkedRole",
                        "ec2:DescribeAccountAttributes",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeInstances",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeTags",
                        "elasticloadbalancing:DescribeLoadBalancers",
                        "elasticloadbalancing:DescribeLoadBalancerAttributes",
                        "elasticloadbalancing:DescribeListeners",
                        "elasticloadbalancing:DescribeListenerCertificates",
                        "elasticloadbalancing:DescribeSSLPolicies",
                        "elasticloadbalancing:DescribeRules",
                        "elasticloadbalancing:DescribeTargetGroups",
                        "elasticloadbalancing:DescribeTargetGroupAttributes",
                        "elasticloadbalancing:DescribeTargetHealth",
                        "elasticloadbalancing:DescribeTags"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "cognito-idp:DescribeUserPoolClient",
                        "acm:ListCertificates",
                        "acm:DescribeCertificate",
                        "iam:ListServerCertificates",
                        "iam:GetServerCertificate",
                        "waf-regional:GetWebACL",
                        "waf-regional:GetWebACLForResource",
                        "waf-regional:AssociateWebACL",
                        "waf-regional:DisassociateWebACL",
                        "wafv2:GetWebACL",
                        "wafv2:GetWebACLForResource",
                        "wafv2:AssociateWebACL",
                        "wafv2:DisassociateWebACL",
                        "shield:GetSubscriptionState",
                        "shield:DescribeProtection",
                        "shield:CreateProtection",
                        "shield:DeleteProtection"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateSecurityGroup"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateTags"
                    ],
                    "Resource": "arn:aws:ec2:*:*:security-group/*",
                    "Condition": {
                        "StringEquals": {
                            "ec2:CreateAction": "CreateSecurityGroup"
                        },
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": False
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateTags",
                        "ec2:DeleteTags"
                    ],
                    "Resource": "arn:aws:ec2:*:*:security-group/*",
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": True,
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": False
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:DeleteSecurityGroup"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": False
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:CreateLoadBalancer",
                        "elasticloadbalancing:CreateTargetGroup"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": False
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:CreateListener",
                        "elasticloadbalancing:DeleteListener",
                        "elasticloadbalancing:CreateRule",
                        "elasticloadbalancing:DeleteRule"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:AddTags",
                        "elasticloadbalancing:RemoveTags"
                    ],
                    "Resource": [
                        "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": True,
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": False
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:ModifyLoadBalancerAttributes",
                        "elasticloadbalancing:SetIpAddressType",
                        "elasticloadbalancing:SetSecurityGroups",
                        "elasticloadbalancing:SetSubnets",
                        "elasticloadbalancing:DeleteLoadBalancer",
                        "elasticloadbalancing:ModifyTargetGroup",
                        "elasticloadbalancing:ModifyTargetGroupAttributes",
                        "elasticloadbalancing:DeleteTargetGroup"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": False
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:RegisterTargets",
                        "elasticloadbalancing:DeregisterTargets"
                    ],
                    "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:SetWebAcl",
                        "elasticloadbalancing:ModifyListener",
                        "elasticloadbalancing:AddListenerCertificates",
                        "elasticloadbalancing:RemoveListenerCertificates",
                        "elasticloadbalancing:ModifyRule"
                    ],
                    "Resource": "*"
                }
            ]
        }
        self.custom_policy_document = iam.PolicyDocument.from_json(self.policy_document)
        self.new_managed_policy = iam.ManagedPolicy(self, "LBControlPolicy",
            document=self.custom_policy_document
        )
        self.lb_role = iam.Role(self, "LBControllerRole", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                self.new_managed_policy
            ])
        string_eq = core.CfnJson(self, "ConditionJsonEq",
            value={
                f"{self.cluster.cluster_open_id_connect_issuer}:sub": f"system:serviceaccount:kube-system:aws-load-balancer-controller"
            }
        )
        self.lb_role.assume_role_policy.add_statements(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["sts:AssumeRoleWithWebIdentity"],
                principals=[iam.OpenIdConnectPrincipal(self.cluster.open_id_connect_provider, conditions={"StringEquals": string_eq})]
            )
        )

        # Service Account
        self.lb_svc_acct = self.cluster.add_manifest("lb_svc_acct", {
            "apiVersion":"v1",
            "kind":"ServiceAccount",
            "metadata":{
                "labels": {
                    "app.kubernetes.io/component": "controller",
                    "app.kubernetes.io/name": "aws-load-balancer-controller"
                },
                "name": "aws-load-balancer-controller", 
                "namespace": "kube-system",
                "annotations": {"eks.amazonaws.com/role-arn": self.lb_role.role_arn}
            },
        })

        # Helm chart
        self.cluster.add_helm_chart("lbcontroller", 
            chart="aws-load-balancer-controller",
            repository="https://aws.github.io/eks-charts",
            release="aws-load-balancer-controller",
            namespace="kube-system",
            values= {
                "clusterName": self.cluster.cluster_name,
                "region": self.region,
                "vpcId": self.vpc.vpc_id,
                "serviceAccount": {
                    "create": False,
                    "name": "aws-load-balancer-controller"
                }
            },
            wait=True
        ) 
