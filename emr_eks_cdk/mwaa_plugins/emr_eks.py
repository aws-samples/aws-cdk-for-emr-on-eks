# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from airflow import DAG

from airflow.operators.bash_operator import BashOperator
from airflow.operators.emr_containers_airflow_plugin import EmrContainersStartJobRun
from airflow.sensors.emr_containers_airflow_plugin import EmrContainersJobRunSensor
from airflow.models import Variable

from airflow.utils.dates import days_ago
from datetime import timedelta
import os

DAG_ID = os.path.basename(__file__).replace(".py", "")

DEFAULT_ARGS = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email': ['you@amazon.com'],
    'email_on_failure': False,
    'email_on_retry': False,
}

JOB_DRIVER_ARG = {
    'sparkSubmitJobDriver': {"entryPoint": "local:///usr/lib/spark/examples/src/main/python/pi.py","sparkSubmitParameters": "--conf spark.executors.instances=2 --conf spark.executors.memory=2G --conf spark.executor.cores=2 --conf spark.driver.cores=1"}
}

CONFIGURATION_OVERRIDES_ARG = {
    'monitoringConfiguration': {"cloudWatchMonitoringConfiguration": {"logGroupName": "/emr-containers/jobs", "logStreamNamePrefix": "demo"}}
}

with DAG(
    dag_id=DAG_ID,
    default_args=DEFAULT_ARGS,
    dagrun_timeout=timedelta(hours=2),
    start_date=days_ago(1),
    schedule_interval='@once',
    tags=['emr_containers'],
    params={
        "cluster_id": "",
        "role_arn": ""
    },
) as dag:
   
    job_starter = EmrContainersStartJobRun(
        task_id='start_job', 
        virtual_cluster_id=Variable.get("cluster_id"),
        execution_role_arn=Variable.get("role_arn"),
        #virtual_cluster_id="{{ dag_run.conf['cluster_id'] }}",
        #execution_role_arn="{{ dag_run.conf['role_arn'] }}",
        release_label='emr-6.2.0-latest',
        job_driver=JOB_DRIVER_ARG,
        configuration_overrides=CONFIGURATION_OVERRIDES_ARG,
        name='pi.py',
        client_token='dummy'
    )

    job_checker = EmrContainersJobRunSensor(
        task_id='watch_job',
        virtual_cluster_id=Variable.get("cluster_id"),
        id="{{ task_instance.xcom_pull(task_ids='start_job', key='return_value') }}",
        aws_conn_id='aws_default'
    )

    job_starter >> job_checker
