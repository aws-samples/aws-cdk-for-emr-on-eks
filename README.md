# EMR on EKS via SDK

This project helps you demonstrate EMR on EKS using the CDK for automation.

It deploys the following:

* An EKS cluster in a new VPC across 3 subnets
    * The Cluster has a default managed node group set to scale between 3 and 10 nodes.  This node group can use regular instances or Graviton2.
    * It also has a Fargate profile set to use the `sparkfg` namespace
* Two EMR virtual clusters on the EKS cluster
    * The first virtual cluster uses the `sparkns` namespace on a managed node group
    * The second virtual cluster uses the `sparkfg` namespace on a Fargate profile
    * All EMR on EKS configuration is done, including a cluster role bound to an IAM role
* A default job execution role that has full CloudWatch and S3 access
* A CloudWatch log group for use with Spark job runs
* Optionally, sets up Apache Airflow and EMR Studio

## Deployment

We tested this deployment using CDK version 1.90.1.

After cloning the repo, download the Airflow plugin zip file:

    wget https://elasticmapreduce.s3.amazonaws.com/emr-containers/airflow/plugins/emr_containers_airflow_plugin.zip
    mv emr_containers_airflow_plugin.zip emr_eks_cdk/mwaa_plugins/

Now run:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    cdk bootstrap aws://<account>/<region> --context prefix=<prefix list for inbound access to MWAA> --context instance=m5.xlarge --context username=<SSO user name>
    cdk synth --context prefix=<prefix list for inbound access to MWAA> --context instance=m5.xlarge --context username=<SSO user name>
    cdk ls --context prefix=<prefix list for inbound access to MWAA> --context instance=m5.xlarge --context username=<SSO user name> # list stacks
    cdk deploy <stack name> --context prefix=<prefix list for inbound access to MWAA> --context instance=m5.xlarge  --context username=<SSO user name>

If deployment fails due to an error creating the EKS cluster, just redeploy.  This is a [known issue](https://github.com/aws/aws-cdk/issues/9027) in the CDK.

Available stacks include:

* emr-eks-cdk: The base stack 
* mwaa-cdk: Adds Airflow
* studio-cdk: Adds EMR Studio prerequisites (requires SSO enabled in your account)
* studio-cdk-live: Adds EMR Studio (requires SSO enabled in your account)

Note that EMR Studio doesn't yet support Graviton2 nodes.  Do not choose a Graviton2 instance type if you want to use Studio.

## Register EKS in kube config

The CDK output should include the command you use to update your kube config to run commands on the cluster.  It'll look like this:

    emr-eks-cdk.EksForSparkConfigCommandB4B8E93B = aws eks update-kubeconfig --name EksForSparkCF45D836-7d1075f7618943f2b56095bcbdd13709 --region us-west-2 --role-arn arn:aws:iam::<account>:role/emr-eks-cdk-EksForSparkMastersRole19842074-1QPZ722TZ38S

If you run multiple k8s clusters, you can list and switch cluster contexts like this:

    kubectl config get-contexts
    kubectl config use-context "arn:aws:eks:us-west-2:<account>:cluster/EksForSparkCF45D836-7d1075f7618943f2b56095bcbdd13709"

The argument to `use-context` is the context name as reported by `get-contexts`.

## Test a job run

First, identify your virtual cluster ID:

    aws emr-containers list-virtual-clusters

The virtual cluster IDs are also in the CDK stack output.

You can run a test application with this command:

    aws emr-containers start-job-run \
        --virtual-cluster-id <virtual cluster ID> \
        --name sample-job-name \
        --execution-role-arn <job role ARN from CDK output> \
        --release-label emr-6.2.0-latest \
        --job-driver '{"sparkSubmitJobDriver": {"entryPoint": "local:///usr/lib/spark/examples/src/main/python/pi.py","sparkSubmitParameters": "--conf spark.executor.instances=2 --conf spark.executor.memory=2G --conf spark.executor.cores=2 --conf spark.driver.cores=1"}}' \
        --configuration-overrides '{"monitoringConfiguration": {"cloudWatchMonitoringConfiguration": {"logGroupName": "<log group from CDK output>", "logStreamNamePrefix": "SparkEMREKS"}}}'

You can track job completion in the EMR console.

## Testing with Airflow

Go to the MWAA console and open the Airflow UI.  Activate the DAG by moving the slider to `On`.  Add two Airflow variables:

    * cluster_id = your virtual cluster ID
    * role_arn = your job role ARN

Then trigger the DAG.

## Running on Graviton2 node group

Deploy the stack with `m6g.xlarge` as the instance type rather than `m5.xlarge`.  Then include a node selector when you start the job.

    aws emr-containers start-job-run \
        --virtual-cluster-id <virtual cluster ID> \
        --name sample-job-name \
        --execution-role-arn <job role ARN from CDK output> \
        --release-label emr-6.2.0-latest \
        --job-driver '{"sparkSubmitJobDriver": {"entryPoint": "local:///usr/lib/spark/examples/src/main/python/pi.py","sparkSubmitParameters": "--conf spark.executor.instances=2 --conf spark.executor.memory=2G --conf spark.executor.cores=2 --conf spark.driver.cores=1 --conf spark.kubernetes.node.selector.kubernetes.io/arch=arm64"}}' \
        --configuration-overrides '{"monitoringConfiguration": {"cloudWatchMonitoringConfiguration": {"logGroupName": "<log group from CDK output>", "logStreamNamePrefix": "SparkEMREKS"}}}'

## EMR Studio

Deploy the `studio-cdk` script.  Wait for it to deploy and check to make sure that the endpoint is active:

    aws emr-containers list-managed-endpoints --virtual-cluster-id <cluster ID> | jq '.endpoints[].state'

Now deploy the `studio-live-cdk` script.  The script will output the URL for your Studio environment.   

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
