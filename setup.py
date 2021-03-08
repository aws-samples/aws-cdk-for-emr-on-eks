# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="emr_eks_cdk",
    version="0.0.1",

    description="An empty CDK Python app",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="author",

    package_dir={"": "emr_eks_cdk"},
    packages=setuptools.find_packages(where="emr_eks_cdk"),

    install_requires=[
        "aws-cdk.core",
        "aws-cdk.aws-mwaa",
        "aws-cdk.aws-emrcontainers",
        "aws-cdk.aws-eks",
        "aws-cdk.aws-ec2",
        "aws-cdk.aws_acmpca",
        "aws-cdk.aws-s3-deployment",
        "pyOpenSSL",
        "boto3",
        "awscli"
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "License :: OSI Approved :: Apache Software License",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
