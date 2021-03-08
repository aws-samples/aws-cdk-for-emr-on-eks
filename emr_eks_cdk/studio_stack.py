# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import aws_ec2 as ec2, aws_eks as eks, core, aws_emrcontainers as emrc, aws_iam as iam, aws_logs as logs, custom_resources as custom, aws_acmpca as acmpca
from OpenSSL import crypto, SSL

"""
This stack deploys the following:
- EMR Studio Prerequisites
"""
class StudioStack(core.Stack):


    def __init__(self, scope: core.Construct, construct_id: str, executionRoleArn: str, virtualClusterId: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # policy to let Lambda invoke the api
        custom_policy_document = iam.PolicyDocument(statements=[
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["acm:*"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iam:PassRole"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["emr-containers:*"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:*"],
                resources=["*"]
            )
        ])
        managed_policy = iam.ManagedPolicy(self, "ACMPolicy",
            document=custom_policy_document
        )

        # cert for endpoint
        crt, pkey = self.cert_gen()
        mycert = custom.AwsCustomResource(self, "CreateCert",
            on_update={
                "service": "ACM",
                "action": "importCertificate",
                "parameters": {
                    "Certificate": crt.decode("utf-8"),
                    "PrivateKey": pkey.decode("utf-8")
                },
                "physical_resource_id": custom.PhysicalResourceId.from_response("CertificateArn")
            },
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(resources=custom.AwsCustomResourcePolicy.ANY_RESOURCE),
            function_name="CreateCertFn",
            role = iam.Role(
                    scope=self,
                    id=f'{construct_id}-AcmRole',
                    assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                        managed_policy
                    ]
                )
        )

        # Set up managed endpoint for Studio
        endpoint = custom.AwsCustomResource(self, "CreateEndpoint",
            on_create={
                "service": "EMRcontainers",
                "action": "createManagedEndpoint",
                "parameters": {
                    "certificateArn": mycert.get_response_field("CertificateArn"),
                    "executionRoleArn": executionRoleArn,
                    "name": "emr-endpoint-eks-spark",
                    "releaseLabel": "emr-6.2.0-latest",
                    "type": "JUPYTER_ENTERPRISE_GATEWAY",
                    "virtualClusterId": virtualClusterId,
                },
                "physical_resource_id": custom.PhysicalResourceId.from_response("arn")},
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(resources=custom.AwsCustomResourcePolicy.ANY_RESOURCE),
            function_name="CreateEpFn",
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
        endpoint.node.add_dependency(mycert)


    def cert_gen(self,
        emailAddress="emailAddress",
        commonName="emroneks.com",
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=1234,
        validityStartInSeconds=0,
        validityEndInSeconds=10*365*24*60*60,
        KEY_FILE = "private.key",
        CERT_FILE="selfsigned.crt"):
        #can look at generated file using openssl:
        #openssl x509 -inform pem -in selfsigned.crt -noout -text
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        return (crypto.dump_certificate(crypto.FILETYPE_PEM, cert), crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
