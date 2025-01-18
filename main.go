package main

import (
	"context"
	"errors"
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
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"

	"github.com/spf13/pflag"
)

func isValidParamGroupName(name string) bool {
	// 正则表达式验证参数组名称
	matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$`, name)
	return matched
}

func main() {
	var (
		action             string
		clusterID          string
		instanceID         string
		paramGroupName     string
		dbInstanceClass    string
		ec2InstanceType    string
		ec2ImageID         string
		ec2InstanceID      string
		ec2SecurityGroupID string
		ec2KeyName         string
		perfType           string
		restore            bool
	)

	pflag.StringVarP(&action, "action", "a", "", "Action to perform: 'create-rds', 'delete-rds', 'modify-params', 'create-client', 'delete-client','init-perftest-env','prepare-data'")
	pflag.StringVarP(&clusterID, "cluster-id", "c", "", "Aurora cluster identifier")
	pflag.StringVarP(&instanceID, "instance-id", "i", "", "Aurora instance identifier")
	pflag.StringVarP(&paramGroupName, "param-group-name", "p", "my-custom-aurora-mysql80", "Parameter group name(default: my-custom-aurora-mysql80)")
	pflag.StringVarP(&dbInstanceClass, "instance-class", "d", "db.r6g.4xlarge", "Aurora instance class (default: db.r6g.4xlarge)")
	pflag.StringVarP(&ec2InstanceType, "ec2-instance-type", "t", "m5.2xlarge", "EC2 instance type (default: m5.2xlarge)")
	pflag.StringVarP(&ec2ImageID, "ec2-image-id", "m", "ami-0afb6e8e0625142bc", "EC2 image ID (default: ami-0afb6e8e0625142bc)") // amazone linux 2023 ami-id:ami-046d7944dd9e73a61 for default
	pflag.StringVarP(&ec2InstanceID, "ec2-instance-id", "e", "", "EC2 instance ID")                                              // like  i-0596d9ed0e24f825d
	pflag.StringVarP(&ec2SecurityGroupID, "ec2-security-group-id", "g", "", "EC2 security group ID")
	pflag.StringVarP(&ec2KeyName, "ec2-key-name", "k", "pub-st-rsa", "EC2 key pair name(default: pub-st-rsa)")
	pflag.BoolVarP(&restore, "restore", "s", false, "Restore data from S3 instead of preparing data with Sysbench, create a new cluster")
	pflag.StringVarP(&perfType, "perf-type", "o", "", "Sysbench oltp perf type:oltp_read_only/oltp_read_write/oltp_write_only")

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
		log.Fatalf("Unable to load aws config(~/.aws/config), %v", err)
	}

	// 创建RDS/ec2/ssm客户端
	rdsClient := rds.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)
	ssmClient := ssm.NewFromConfig(cfg)

	switch action {
	case "create-rds":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Fatalf("For 'create-rds' action, --cluster-id, --instance-id, and --param-group-name are required")
		}
		createResources(rdsClient, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass)
	case "delete-rds":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Fatalf("For 'delete-rds' action, --cluster-id, --instance-id, and --param-group-name are required")
		}
		deleteResources(rdsClient, clusterID, instanceID, paramGroupName)
	case "modify-params":
		if clusterID == "" || paramGroupName == "" {
			log.Fatalf("For 'modify-params' action, --cluster-id and --param-group-name are required")
		}
		modifyClusterParameters(rdsClient, clusterID, paramGroupName)
	case "get-rds-endpoint":
		if clusterID == "" {
			log.Fatalf("For 'get-rds-endpoint' action, --cluster-id and -is required")
		}
		loginInfo, err := getRDSLoginInfo(rdsClient, clusterID, masterPassword)
		if err != nil {
			log.Fatalf("Failed to get RDS login information")
		}
		fmt.Printf("RDS login command: %s\n", loginInfo)
	case "create-client":
		if clusterID == "" || ec2ImageID == "" || ec2InstanceType == "" || ec2KeyName == "" {
			log.Fatalf("For 'create-client' action, --cluster-id is required")
		}
		instanceID, publicDNS, err := createClientEC2(rdsClient, ec2Client, clusterID, ec2InstanceType, ec2ImageID, ec2KeyName)
		if err != nil {
			log.Fatalf("Failed to create client EC2 instance: %v", err)
		}
		fmt.Printf("Client EC2 instance created with ID: %s\n", instanceID)
		fmt.Printf("Public DNS: %s\n", publicDNS)
		fmt.Printf("Login command: ssh -i %s.pem ec2-user@%s\n", ec2KeyName, publicDNS)
	case "delete-client":
		if ec2InstanceID == "" {
			log.Fatalf("For 'create-client' action, --ec2-instance-id is required")
		}
		err := deleteClientEC2(ec2Client, ec2InstanceID)
		if err != nil {
			log.Fatalf("Failed to delete client EC2 instance %s: %v", ec2ImageID, err)
		}
	case "init-perftest-env":
		if ec2InstanceID == "" {
			log.Fatalf("For 'init-perftest-env' action, --ec2-instance-id is required")
		}
		err := initPerfTestEnv(ec2Client, ec2InstanceID, ec2KeyName)
		if err != nil {
			log.Fatalf("Failed to initialize performance test environment: %v", err)
		}
		fmt.Println("Performance test environment initialized successfully")
	case "prepare-data":
		if ec2InstanceID == "" || clusterID == "" {
			log.Fatalf("For 'prepare-data' action, --ec2-instance-id and --cluster-id are required")
		}
		if restore {
			err := RestoreAuroraClusterFromS3("qa-drill-bkt", "", clusterID, "arn:aws:iam::986330900858:role/asystest")
			if err != nil {
				log.Fatalf("Prapare data from s3 failed: %v", err)
			}

		} else {
			err := prepareSysbenchData(rdsClient, ec2InstanceID, clusterID, ec2KeyName)
			if err != nil {
				log.Fatalf("Prepare data from sysbench preapare Error: %v", err)
			}
		}

	case "perftest-run":
		if ec2InstanceID == "" || clusterID == "" || perfType == "" {
			log.Fatalf("For 'perftest-run' action, --ec2-instance-id,--cluster-id and --perf-type are required")
		}
		err := RunSysbenchPerftest(rdsClient, ssmClient, ec2InstanceID, clusterID, ec2KeyName, perfType)
		if err != nil {
			log.Fatalf("Run sysbench perftest Error: %v", err)
		}
	default:
		log.Fatalf("Invalid action: %s. Use 'create-rds', 'delete-rds', 'modify-params', 'create-client','init-perftest-env','prepare-data','perftest-run'", action)
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
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "DBClusterParameterGroupAlreadyExistsFault" {
				fmt.Printf("Parameter group %s already exists.\n", paramGroupName)
			}
			return
		}
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

func createClientEC2(rdsClient *rds.Client, ec2Client *ec2.Client, clusterID, instanceType, imageID, keyName string) (string, string, error) {
	var ec2Count int32 = 1
	var ec2NameKey string = "Name"
	var ec2NameValue string = "aurora-perftest-client"
	// 获取Aurora集群的VPC ID
	vpcID, err := getAuroraClusterVPC(rdsClient, clusterID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get Aurora cluster VPC: %v", err)
	}

	// 创建新的安全组
	sgname := "ec2-client-sg"
	securityGroupID, err := createSecurityGroup(ec2Client, vpcID, sgname)
	if err != nil {
		return "", "", fmt.Errorf("failed to create security group: %v", err)
	}

	// 获取默认子网

	subnetID, err := getDefaultSubnet(ec2Client, vpcID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get default subnet: %v", err)
	}

	// 创建EC2实例
	runInstancesInput := &ec2.RunInstancesInput{
		ImageId:      &imageID,
		InstanceType: ec2type.InstanceType(instanceType),
		KeyName:      &keyName,
		MinCount:     &ec2Count,
		MaxCount:     &ec2Count,
		SubnetId:     &subnetID,
		SecurityGroupIds: []string{
			securityGroupID,
		},
		TagSpecifications: []ec2type.TagSpecification{
			{
				ResourceType: "instance",
				Tags: []ec2type.Tag{
					{
						Key:   &ec2NameKey,
						Value: &ec2NameValue,
					},
				},
			},
		},
	}

	runInstancesOutput, err := ec2Client.RunInstances(context.TODO(), runInstancesInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to create EC2 instance: %v", err)
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
		return "", "", fmt.Errorf("failed to wait for EC2 instance to run: %v", err)
	}
	fmt.Printf("EC2 instance is running: %s\n", *instanceID)

	// 获取实例的公有DNS名称
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{*instanceID},
	}
	instancesOutput, err := ec2Client.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to describe instances: %v", err)
	}
	publicDNS := instancesOutput.Reservations[0].Instances[0].PublicDnsName
	if publicDNS == nil {
		return "", "", fmt.Errorf("public DNS name not found for instance %s", *instanceID)
	}

	return *instanceID, *publicDNS, nil
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

func createSecurityGroup(ec2Client *ec2.Client, vpcID, groupName string) (string, error) {
	var vpcid string = "vpc-id"
	var grpname string = "group-name"
	var sgdescirbe = "Security group for EC2 client instance"
	// 检查安全组是否已存在
	describeSecurityGroupsInput := &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2type.Filter{
			{
				Name:   &vpcid,
				Values: []string{vpcID},
			},
			{
				Name:   &grpname,
				Values: []string{groupName},
			},
		},
	}
	securityGroupsOutput, err := ec2Client.DescribeSecurityGroups(context.TODO(), describeSecurityGroupsInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe security groups: %v", err)
	}

	if len(securityGroupsOutput.SecurityGroups) > 0 {
		existingSecurityGroup := securityGroupsOutput.SecurityGroups[0]
		return *existingSecurityGroup.GroupId, nil
	}

	// 创建新的安全组
	createSecurityGroupInput := &ec2.CreateSecurityGroupInput{
		Description: &sgdescirbe,
		GroupName:   &groupName,
		VpcId:       &vpcID,
	}
	securityGroupOutput, err := ec2Client.CreateSecurityGroup(context.TODO(), createSecurityGroupInput)
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

func deleteClientEC2(ec2Client *ec2.Client, instanceID string) error {
	// 终止EC2实例
	terminateInstancesInput := &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	}

	terminateInstancesOutput, err := ec2Client.TerminateInstances(context.TODO(), terminateInstancesInput)
	if err != nil {
		return fmt.Errorf("failed to terminate EC2 instance: %v", err)
	}
	fmt.Printf("EC2 instance terminated: %v\n", terminateInstancesOutput)

	// 等待实例终止
	waiter := ec2.NewInstanceTerminatedWaiter(ec2Client)
	err = waiter.Wait(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to wait for EC2 instance to terminate: %v", err)
	}
	fmt.Printf("EC2 instance is terminated: %s\n", instanceID)

	return nil
}

func getRDSLoginInfo(rdsClient *rds.Client, clusterID string, passwd string) (string, error) {
	// 获取Aurora集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(context.TODO(), describeDBClustersInput)
	if err != nil {
		log.Fatalf("Failed to describe DBClusters: %v", err)
		return "", err
	}
	if len(dbClustersOutput.DBClusters) == 0 {
		log.Fatalf("No DBCluster found with ID %s", clusterID)
		return "", err
	}

	// 获取Cluster Endpoint
	clusterEndpoint := dbClustersOutput.DBClusters[0].Endpoint
	clusterPort := dbClustersOutput.DBClusters[0].Port
	loginCommand := fmt.Sprintf("mysql -h %s -P %d -u admin -p%s", *clusterEndpoint, *clusterPort, passwd)
	return loginCommand, nil
}
