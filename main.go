package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2type "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstype "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/spf13/pflag"
)

func isValidParamGroupName(name string) bool {
	// 正则表达式验证参数组名称
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$`, name)
	return matched
}

func main() {
	// 定义命令行参数
	var action string
	var clusterID string
	var instanceID string
	var paramGroupName string
	var dbInstanceClass string
	var ec2InstanceType string
	var ec2ImageID string
	var ec2SecurityGroupID string
	var ec2KeyName string
	var ec2SubnetID string

	pflag.StringVarP(&action, "action", "a", "", "Action to perform: 'create', 'delete', or 'modify-params'")
	pflag.StringVarP(&clusterID, "cluster-id", "c", "", "Aurora cluster identifier")
	pflag.StringVarP(&instanceID, "instance-id", "i", "", "Aurora instance identifier")
	pflag.StringVarP(&paramGroupName, "param-group-name", "p", "", "Parameter group name")
	pflag.StringVarP(&dbInstanceClass, "instance-class", "d", "db.r6g.4xlarge", "Aurora instance class (default: db.r6g.4xlarge)")
	pflag.StringVarP(&ec2InstanceType, "ec2-instance-type", "t", "m5.2xlarge", "EC2 instance type (default: m5.2xlarge)")
	pflag.StringVarP(&ec2ImageID, "ec2-image-id", "m", "ami-0c55b159cbfafe1f0", "EC2 image ID (default: ami-0c55b159cbfafe1f0)")
	pflag.StringVarP(&ec2SubnetID, "ec2-subnet-id", "s", "", "EC2 subnet ID")
	pflag.StringVarP(&ec2SecurityGroupID, "ec2-security-group-id", "g", "", "EC2 security group ID")
	pflag.StringVarP(&ec2KeyName, "ec2-key-name", "k", "", "EC2 key pair name")
	pflag.Parse()

	if action == "" || clusterID == "" || instanceID == "" || paramGroupName == "" {
		log.Fatalf("All parameters --action, --cluster-id, --instance-id, and --param-group-name are required")
	}

	// 验证参数组名称是否符合要求
	if !isValidParamGroupName(paramGroupName) {
		log.Fatalf("Invalid DBClusterParameterGroupName: %s. Name must start with a letter, contain only ASCII letters, digits, and hyphens, and must not end with a hyphen or contain two consecutive hyphens or a period.", paramGroupName)
	}

	// 从环境变量中获取敏感信息
	masterPassword := os.Getenv("MASTER_PASSWORD")
	if masterPassword == "" {
		log.Fatalf("MASTER_PASSWORD environment variable is not set")
	}

	// 加载AWS配置
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load SDK config, %v", err)
	}

	// 创建RDS客户端
	client := rds.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)

	switch action {
	case "create":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Fatalf("For 'create' action, --cluster-id, --instance-id, and --param-group-name are required")
			return
		}
		createResources(client, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass)
	case "delete":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Fatalf("For 'delete' action, --cluster-id, --instance-id, and --param-group-name are required")
			return
		}
		deleteResources(client, clusterID, instanceID, paramGroupName)
	case "modify-params":
		if clusterID == "" || paramGroupName == "" {
			log.Fatalf("For 'modify-params' action, --cluster-id and --param-group-name are required")
			return
		}
		modifyClusterParameters(client, clusterID, paramGroupName)
	case "create-client-ec2":
		if ec2InstanceType == "" || ec2ImageID == "" || ec2SubnetID == "" || ec2SecurityGroupID == "" || ec2KeyName == "" {
			log.Fatalf("For 'create-client-ec2' action, --ec2-instance-type, --ec2-image-id, --ec2-subnet-id, --ec2-security-group-id, and --ec2-key-name are required")
			return
		}
		instanceID, err := createClientEC2(ec2Client, ec2InstanceType, ec2ImageID, ec2SubnetID, ec2SecurityGroupID, ec2KeyName)
		if err != nil {
			log.Fatalf("Failed to create client EC2 instance: %v", err)
		}
		fmt.Printf("Client EC2 instance created with ID: %s\n", instanceID)
	default:
		log.Fatalf("Invalid action: %s. Use 'create', 'delete', 'modify-params', or 'create-client-ec2'", action)
	}
}

func createResources(client *rds.Client, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass string) {
	var backupRetentionPeriod int32 = 1
	var publiclyAccessible bool = false

	// 定义Aurora集群和实例的参数
	masterUsername := "admin"
	dbName := "mydb"
	engineVersion := "8.0.mysql_aurora.3.06.0" // 使用正确的版本号
	engine := "aurora-mysql"
	parameterGroupFamily := "aurora-mysql8.0"
	paramterDescription := "Custom parameter group for Aurora MySQL 8.0"

	// 创建Aurora集群
	createClusterInput := &rds.CreateDBClusterInput{
		DBClusterIdentifier:   &clusterID,
		MasterUsername:        &masterUsername,
		MasterUserPassword:    &masterPassword,
		DatabaseName:          &dbName,
		Engine:                &engine,
		EngineVersion:         &engineVersion,
		BackupRetentionPeriod: &backupRetentionPeriod,
	}

	createClusterOutput, err := client.CreateDBCluster(context.TODO(), createClusterInput)
	if err != nil {
		log.Fatalf("Failed to create Aurora cluster, %v", err)
	}
	fmt.Printf("Aurora cluster created: %v\n", createClusterOutput)

	// 创建Aurora数据库实例
	createInstanceInput := &rds.CreateDBInstanceInput{
		DBInstanceIdentifier: &instanceID,
		DBInstanceClass:      &dbInstanceClass,
		Engine:               &engine,
		DBClusterIdentifier:  &clusterID,
		PubliclyAccessible:   &publiclyAccessible,
	}

	createInstanceOutput, err := client.CreateDBInstance(context.TODO(), createInstanceInput)
	if err != nil {
		log.Fatalf("Failed to create Aurora instance, %v", err)
	}
	fmt.Printf("Aurora instance created: %v\n", createInstanceOutput)

	// 创建新的参数组
	createParamGroupInput := &rds.CreateDBClusterParameterGroupInput{
		DBClusterParameterGroupName: &paramGroupName,
		Description:                 &paramterDescription,
		DBParameterGroupFamily:      &parameterGroupFamily,
	}

	_, err = client.CreateDBClusterParameterGroup(context.TODO(), createParamGroupInput)
	if err != nil {
		log.Fatalf("Failed to create DBClusterParameterGroup, %v", err)
	}
	fmt.Printf("DBClusterParameterGroup created: %s\n", paramGroupName)
}

func modifyClusterParameters(client *rds.Client, clusterID, paramGroupName string) {
	// 修改新参数组中的参数
	paramName := "max_prepared_stmt_count"
	paramValue := "1048576"
	modifyDBClusterParameterGroupInput := &rds.ModifyDBClusterParameterGroupInput{
		DBClusterParameterGroupName: &paramGroupName,
		Parameters: []rdstype.Parameter{
			{
				ParameterName:  &paramName,
				ParameterValue: &paramValue,
				ApplyMethod:    rdstype.ApplyMethodImmediate,
			},
		},
	}

	_, err := client.ModifyDBClusterParameterGroup(context.TODO(), modifyDBClusterParameterGroupInput)
	if err != nil {
		log.Fatalf("Failed to modify DBClusterParameterGroup, %v", err)
	}
	fmt.Printf("DBClusterParameterGroup modified: %s set to %s\n", paramName, paramValue)

	// 将新参数组关联到数据库集群
	modifyDBClusterInput := &rds.ModifyDBClusterInput{
		DBClusterIdentifier:         &clusterID,
		DBClusterParameterGroupName: &paramGroupName,
	}

	_, err = client.ModifyDBCluster(context.TODO(), modifyDBClusterInput)
	if err != nil {
		log.Fatalf("Failed to modify DBCluster, %v", err)
	}
	fmt.Printf("DBCluster modified to use new parameter group: %s\n", paramGroupName)
}

func deleteResources(client *rds.Client, clusterID, instanceID, paramGroupName string) {
	var skipFinalSnapshot bool = true

	// 删除Aurora数据库实例
	deleteInstanceInput := &rds.DeleteDBInstanceInput{
		DBInstanceIdentifier: &instanceID,
		SkipFinalSnapshot:    &skipFinalSnapshot,
	}

	_, err := client.DeleteDBInstance(context.TODO(), deleteInstanceInput)
	if err != nil {
		log.Fatalf("Failed to delete Aurora instance, %v", err)
	}
	fmt.Printf("Aurora instance deleted: %v\n", instanceID)

	// 删除Aurora集群
	deleteClusterInput := &rds.DeleteDBClusterInput{
		DBClusterIdentifier: &clusterID,
		SkipFinalSnapshot:   &skipFinalSnapshot,
	}

	_, err = client.DeleteDBCluster(context.TODO(), deleteClusterInput)
	if err != nil {
		log.Fatalf("Failed to delete Aurora cluster, %v", err)
	}
	fmt.Printf("Aurora cluster deleted: %v\n", clusterID)

	// 删除参数组
	deleteParamGroupInput := &rds.DeleteDBClusterParameterGroupInput{
		DBClusterParameterGroupName: &paramGroupName,
	}

	_, err = client.DeleteDBClusterParameterGroup(context.TODO(), deleteParamGroupInput)
	if err != nil {
		log.Fatalf("Failed to delete DBClusterParameterGroup, %v", err)
	}
	fmt.Printf("DBClusterParameterGroup deleted: %s\n", paramGroupName)
}

func createClientEC2(client *ec2.Client, instanceType, imageID, subnetID, securityGroupID, keyName string) (string, error) {
	var instancenum int32 = 1
	// 创建EC2实例
	runInstancesInput := &ec2.RunInstancesInput{
		ImageId:      &imageID,
		InstanceType: ec2type.InstanceType(instanceType),
		KeyName:      &keyName,
		MinCount:     &instancenum,
		MaxCount:     &instancenum,
		SubnetId:     &subnetID,
		SecurityGroupIds: []string{
			securityGroupID,
		},
	}

	runInstancesOutput, err := client.RunInstances(context.TODO(), runInstancesInput)
	if err != nil {
		return "", fmt.Errorf("failed to create EC2 instance: %v", err)
	}
	fmt.Printf("EC2 instance created: %v\n", runInstancesOutput)

	// 获取实例ID
	instanceID := runInstancesOutput.Instances[0].InstanceId
	fmt.Printf("EC2 instance ID: %s\n", *instanceID)

	// 等待实例运行
	waiter := ec2.NewInstanceRunningWaiter(client)
	err = waiter.Wait(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{*instanceID},
	}, 10*time.Minute)
	if err != nil {
		return "", fmt.Errorf("failed to wait for EC2 instance to run: %v", err)
	}
	fmt.Printf("EC2 instance is running: %s\n", *instanceID)

	return *instanceID, nil
}
