# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python3

from emr_eks_cdk.mwaa_stack import MwaaStack
from aws_cdk import core
from emr_eks_cdk.studio_stack import StudioStack
from emr_eks_cdk.studio_live_stack import StudioLiveStack
from emr_eks_cdk.emr_eks_cdk_stack import EmrEksCdkStack


app = core.App()
eks = EmrEksCdkStack(app, "emr-eks-cdk")
private_subnets = eks.vpc.private_subnets
private_subnet_ids = [n.subnet_id for n in private_subnets]

MwaaStack(app, "mwaa-cdk", private_subnet_ids, eks.vpc)
StudioStack(app, "studio-cdk", eks.job_role.role_arn, eks.emr_vc.attr_id)
StudioLiveStack(app, "studio-live-cdk", eks.vpc)

app.synth()
