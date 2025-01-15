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
	pflag.StringVarP(&paramGroupName, "param-group-name", "p", "my-custom-aurora-mysql80", "Parameter group name(default: my-custom-aurora-mysql80)")
	pflag.StringVarP(&dbInstanceClass, "instance-class", "d", "db.r6g.4xlarge", "Aurora instance class (default: db.r6g.4xlarge)")
	pflag.StringVarP(&ec2InstanceType, "ec2-instance-type", "t", "m5.2xlarge", "EC2 instance type (default: m5.2xlarge)")
	pflag.StringVarP(&ec2ImageID, "ec2-image-id", "m", "ami-0c55b159cbfafe1f0", "EC2 image ID (default: ami-0c55b159cbfafe1f0)")
	pflag.StringVarP(&ec2SubnetID, "ec2-subnet-id", "s", "", "EC2 subnet ID")
	pflag.StringVarP(&ec2SecurityGroupID, "ec2-security-group-id", "g", "", "EC2 security group ID")
	pflag.StringVarP(&ec2KeyName, "ec2-key-name", "k", "", "EC2 key pair name")
	pflag.Parse()

	// 验证参数组名称是否符合要求
	if !isValidParamGroupName(paramGroupName) {
		fmt.Printf("groupname is %s\n", paramGroupName)
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
	rdsClient := rds.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)

	switch action {
	case "create":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Fatalf("For 'create' action, --cluster-id, --instance-id, and --param-group-name are required")
		}
		createResources(rdsClient, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass)
	case "delete":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Fatalf("For 'delete' action, --cluster-id, --instance-id, and --param-group-name are required")
		}
		deleteResources(rdsClient, clusterID, instanceID, paramGroupName)
	case "modify-params":
		if clusterID == "" || paramGroupName == "" {
			log.Fatalf("For 'modify-params' action, --cluster-id and --param-group-name are required")
		}
		modifyClusterParameters(rdsClient, clusterID, paramGroupName)
	case "create-client-ec2":
		if clusterID == "" || ec2ImageID == "" || ec2InstanceType == "" || ec2KeyName == "" {
			log.Fatalf("For 'create-client-ec2' action, --cluster-id is required")
		}
		instanceID, err := createClientEC2(rdsClient, ec2Client, clusterID, ec2InstanceType, ec2ImageID, ec2KeyName)
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

func createClientEC2(rdsClient *rds.Client, ec2Client *ec2.Client, clusterID, instanceType, imageID, keyName string) (string, error) {
	var ec2count int32 = 1
	// 获取Aurora集群的VPC ID
	vpcID, err := getAuroraClusterVPC(rdsClient, clusterID)
	if err != nil {
		return "", fmt.Errorf("failed to get Aurora cluster VPC: %v", err)
	}

	// 创建新的安全组
	securityGroupID, err := createSecurityGroup(ec2Client, vpcID)
	if err != nil {
		return "", fmt.Errorf("failed to create security group: %v", err)
	}

	// 获取默认子网
	subnetID, err := getDefaultSubnet(ec2Client, vpcID)
	if err != nil {
		return "", fmt.Errorf("failed to get default subnet: %v", err)
	}

	// 创建EC2实例
	runInstancesInput := &ec2.RunInstancesInput{
		ImageId:      &imageID,
		InstanceType: ec2type.InstanceType(instanceType),
		KeyName:      &keyName,
		MinCount:     &ec2count,
		MaxCount:     &ec2count,
		SubnetId:     &subnetID,
		SecurityGroupIds: []string{
			securityGroupID,
		},
	}

	runInstancesOutput, err := ec2Client.RunInstances(context.TODO(), runInstancesInput)
	if err != nil {
		return "", fmt.Errorf("failed to create EC2 instance: %v", err)
	}
	fmt.Printf("EC2 instance created: %v\n", runInstancesOutput)

	// 获取实例ID
	instanceID := runInstancesOutput.Instances[0].InstanceId
	fmt.Printf("EC2 instance ID: %s\n", *instanceID)

	// 等待实例运行
	waiter := ec2.NewInstanceRunningWaiter(ec2Client)
	err = waiter.Wait(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{*instanceID},
	}, 10*time.Minute)
	if err != nil {
		return "", fmt.Errorf("failed to wait for EC2 instance to run: %v", err)
	}
	fmt.Printf("EC2 instance is running: %s\n", *instanceID)

	return *instanceID, nil
}

func getAuroraClusterVPC(client *rds.Client, clusterID string) (string, error) {
	// 获取Aurora集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := client.DescribeDBClusters(context.TODO(), describeDBClustersInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe DBClusters: %v", err)
	}
	if len(dbClustersOutput.DBClusters) == 0 {
		return "", fmt.Errorf("no DBCluster found with ID %s", clusterID)
	}

	// 获取DBSubnetGroup名称
	dbSubnetGroupName := dbClustersOutput.DBClusters[0].DBSubnetGroup
	if dbSubnetGroupName == nil {
		return "", fmt.Errorf("DBSubnetGroup name not found for DBCluster %s", clusterID)
	}

	// 使用子网组名称获取子网组的详细信息
	describeDBSubnetGroupsInput := &rds.DescribeDBSubnetGroupsInput{
		DBSubnetGroupName: dbSubnetGroupName,
	}
	dbSubnetGroupsOutput, err := client.DescribeDBSubnetGroups(context.TODO(), describeDBSubnetGroupsInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe DBSubnetGroups: %v", err)
	}
	if len(dbSubnetGroupsOutput.DBSubnetGroups) == 0 {
		return "", fmt.Errorf("no DBSubnetGroup found with name %s", *dbSubnetGroupName)
	}

	// 获取VPC ID
	vpcID := dbSubnetGroupsOutput.DBSubnetGroups[0].VpcId
	if vpcID == nil {
		return "", fmt.Errorf("VPC ID not found for DBSubnetGroup %s", *dbSubnetGroupName)
	}

	return *vpcID, nil
}

func createSecurityGroup(client *ec2.Client, vpcID string) (string, error) {
	var securityDesc string = "Security group for EC2 client instance"
	var sgname string = "ec2-client-sg"
	// 创建新的安全组
	createSecurityGroupInput := &ec2.CreateSecurityGroupInput{
		Description: &securityDesc,
		GroupName:   &sgname,
		VpcId:       &vpcID,
	}
	securityGroupOutput, err := client.CreateSecurityGroup(context.TODO(), createSecurityGroupInput)
	if err != nil {
		return "", fmt.Errorf("failed to create security group: %v", err)
	}
	return *securityGroupOutput.GroupId, nil
}

func getDefaultSubnet(client *ec2.Client, vpcID string) (string, error) {
	var vpcid string = "vpc-id"
	var vpconfig string = "default-for-az"
	// 获取默认子网
	describeSubnetsInput := &ec2.DescribeSubnetsInput{
		Filters: []ec2type.Filter{
			{
				Name:   &vpcid,
				Values: []string{vpcID},
			},
			{
				Name:   &vpconfig,
				Values: []string{"true"},
			},
		},
	}
	subnetsOutput, err := client.DescribeSubnets(context.TODO(), describeSubnetsInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe subnets: %v", err)
	}
	if len(subnetsOutput.Subnets) == 0 {
		return "", fmt.Errorf("no default subnet found in VPC %s", vpcID)
	}
	return *subnetsOutput.Subnets[0].SubnetId, nil
}
