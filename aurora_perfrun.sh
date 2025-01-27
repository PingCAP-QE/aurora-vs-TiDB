#!/bin/bash

# 设置环境变量
export MASTER_PASSWORD="admin123456"
export AWS_REGION="us-west-2"
# 这三个根据 https://pingcap.awsapps.com/start/#/ 第一次需要配置添加访问密钥，程序中会自动刷新临时token

TOOL_PATH="bin/aurora-vs-TiDB"
PERFTEST_CLUSTER_NAME="Aurora-v3060-perftest"
INITIAL_DB_INSTANCE_TYPE="db.r6g.4xlarge"
DB_INSTANCE_TYPE_GROUP="db.r7g.4xlarge db.r7g.8xlarge db.r7g.16xlarge"
EC2_CLIENT_INSTANCE_TYPE="m5.4xlarge"

# # 准备数据并输出日志
# echo -e "Start preparing Aurora cluster..."
# echo -e "Initial database instance type: $INITIAL_DB_INSTANCE_TYPE"

# echo -e "Executing data preparation command for restoring data from MySQL snapshot..."
# CMD="$TOOL_PATH --action=prepare-data --cluster-id=$PERFTEST_CLUSTER_NAME --restore --instance-class=$INITIAL_DB_INSTANCE_TYPE"
# echo -e "Running: $CMD"
# $CMD

# 创建客户端 EC2 实例
echo -e "Creating client EC2 instance with type $EC2_CLIENT_INSTANCE_TYPE..."
CMD="$TOOL_PATH --action=create-client --cluster-id=$PERFTEST_CLUSTER_NAME --ec2-instance-type=$EC2_CLIENT_INSTANCE_TYPE"
echo -e "Running: $CMD"
ec2_instance_id=$($TOOL_PATH --action=create-client --cluster-id="$PERFTEST_CLUSTER_NAME"  --ec2-instance-type="$EC2_CLIENT_INSTANCE_TYPE" 2>&1 | tee /dev/tty | awk -F': ' '/EC2 instance ID/ {print $2}')
ec2_instance_id=$(echo -n "$ec2_instance_id" | sed 's/\x1b\[[0-9;]*m//g')

echo -e "EC2 instance created with ID: $ec2_instance_id"

# 初始化性能测试环境
echo -e "Initializing performance test environment for EC2 instance ID: $ec2_instance_id..."
CMD="$TOOL_PATH --action=init-perftest-env --ec2-instance-id=$ec2_instance_id"
echo -e "Running: $CMD"
$CMD

# # 执行性能测试（只读、只写和读写）
# echo -e "Starting OLTP Read-Only test..."
# CMD="$TOOL_PATH --action=perftest-run --ec2-instance-id=$ec2_instance_id --cluster-id=$PERFTEST_CLUSTER_NAME --perf-type=oltp_read_only"
# echo -e "Running: $CMD"
# $CMD

# echo -e "Starting OLTP Write-Only test..."
# CMD="$TOOL_PATH --action=perftest-run --ec2-instance-id=$ec2_instance_id --cluster-id=$PERFTEST_CLUSTER_NAME --perf-type=oltp_write_only"
# echo -e "Running: $CMD"
# $CMD

# echo -e "Starting OLTP Read-Write test..."
# CMD="$TOOL_PATH --action=perftest-run --ec2-instance-id=$ec2_instance_id --cluster-id=$PERFTEST_CLUSTER_NAME --perf-type=oltp_read_write"
# echo -e "Running: $CMD"
# $CMD

# 循环处理数据库实例类型并输出
echo -e "Processing database instance types..."
for db_instance_type in $DB_INSTANCE_TYPE_GROUP; do
    DBINSTYPE=$(echo $db_instance_type | sed 's/\.//g')
    echo -e "Testing with DB instance type: $DBINSTYPE"
    
    echo -e "Modifying DB instance type to $DBINSTYPE"
    CMD="$TOOL_PATH --action=modify-dbinstance-type --cluster-id=$PERFTEST_CLUSTER_NAME  --instance-class=$db_instance_type"
    echo -e "Running: $CMD"
    $CMD

    sleep 30
    # 执行性能测试（只读、只写和读写）
    echo -e "Starting db-instance $db_instance_type OLTP Read-Only test..."
    CMD="$TOOL_PATH --action=perftest-run --ec2-instance-id=$ec2_instance_id --cluster-id=$PERFTEST_CLUSTER_NAME --perf-type=oltp_read_only"
    echo -e "Running: $CMD"
    $CMD

    echo -e "Starting db-instance $db_instance_type OLTP Write-Only test..."
    CMD="$TOOL_PATH --action=perftest-run --ec2-instance-id=$ec2_instance_id --cluster-id=$PERFTEST_CLUSTER_NAME --perf-type=oltp_write_only"
    echo -e "Running: $CMD"
    $CMD

    echo -e "Starting db-instance $db_instance_type OLTP Read-Write test..."
    CMD="$TOOL_PATH --action=perftest-run --ec2-instance-id=$ec2_instance_id --cluster-id=$PERFTEST_CLUSTER_NAME --perf-type=oltp_read_write"
    echo -e "Running: $CMD"
    $CMD

done

echo -e "Performance testing and instance processing completed."


# 清理测试环境，销毁测试资源
echo -e "Deleting client EC2 instance..."
CMD="$TOOL_PATH --action=delete-client --ec2-instance-id=$ec2_instance_id"
echo -e "Running: $CMD"
$CMD

echo -e "Deleting Aurora cluster/instance/paramter-group..."
CMD="$TOOL_PATH --action=delete-rds --cluster-id=$PERFTEST_CLUSTER_NAME --instance-id=$PERFTEST_CLUSTER_NAME-instance --param-group-name=my-custom-aurora-mysql80"
echo -e "Running: $CMD"
$CMD
echo -e "Clean testing resource and environment  completed."
