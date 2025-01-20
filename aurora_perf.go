package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/smithy-go"
)

func initPerfTestEnv(ec2Client *ec2.Client, ec2InstanceID, ec2KeyName string) error {
	// 检查实例状态
	instanceState, err := getInstanceState(ec2Client, ec2InstanceID)
	if err != nil {
		return fmt.Errorf("failed to get instance state: %v", err)
	}
	if instanceState != "running" {
		return fmt.Errorf("instance %s is not in a valid state: %s", ec2InstanceID, instanceState)
	}
	fmt.Printf("current instance status: %s\n", instanceState)
	// 安装mysql-client和sysbench的命令
	command := `
sudo yum update -y &&
sudo yum install -y git make automake libtool pkgconfig libaio-devel openssl-devel mysql-devel yum-utils mariadb.x86_64 &&
sudo git clone https://github.com/akopytov/sysbench.git &&
cd sysbench &&
sudo sh autogen.sh &&
sudo sh configure &&
sudo make -j4 &&
sudo make install
`
	// 使用单引号包裹命令
	command = fmt.Sprintf("'%s'", strings.ReplaceAll(command, "'", "'\"'\"'"))
	keypair := fmt.Sprintf("./%s.pem", ec2KeyName)

	err = sshCommandRealtime(ec2InstanceID, keypair, command, nil)
	if err != nil {
		return fmt.Errorf("failed to run command: %v", err)
	}

	fmt.Printf("mysql-client and sysbench installed on EC2 instance %s\n", ec2InstanceID)
	return nil
}

func getPublicDNS(ec2Client *ec2.Client, ec2InstanceID string) (string, error) {
	// 获取EC2实例的详细信息
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{ec2InstanceID},
	}
	instancesOutput, err := ec2Client.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe instances: %v", err)
	}
	if len(instancesOutput.Reservations) == 0 || len(instancesOutput.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no instance found with ID %s", ec2InstanceID)
	}

	// 获取公共IP地址
	publicDNS := instancesOutput.Reservations[0].Instances[0].PublicDnsName
	if publicDNS == nil {
		return "", fmt.Errorf("public DNS name not found for instance %s", ec2InstanceID)
	}
	return *publicDNS, nil
}

func runSSMCommand(ssmClient *ssm.Client, instanceID, command string) (*ssm.SendCommandOutput, error) {
	var shellcmddescribe string = "AWS-RunShellScript"
	// 使用SSM运行命令
	sendCommandInput := &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: &shellcmddescribe,
		Parameters: map[string][]string{
			"commands": {command},
		},
	}
	sendCommandOutput, err := ssmClient.SendCommand(context.TODO(), sendCommandInput)
	if err != nil {
		return nil, fmt.Errorf("failed to send SSM command: %v", err)
	}
	return sendCommandOutput, nil
}

func getInstanceState(ec2Client *ec2.Client, instanceID string) (string, error) {
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}
	instancesOutput, err := ec2Client.DescribeInstances(context.TODO(), describeInstancesInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe instances: %v", err)
	}
	if len(instancesOutput.Reservations) == 0 || len(instancesOutput.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no instance found with ID %s", instanceID)
	}

	instance := instancesOutput.Reservations[0].Instances[0]
	return string(instance.State.Name), nil
}

// attachPolicyToRole 函数将指定的IAM策略附加到指定的IAM角色。
// 参数:
// - roleName: IAM角色的名称。
// - policyArn: 要附加的IAM策略的ARN。
// 返回:
// - error: 如果操作失败，则返回错误信息。
func attachPolicyToRole(roleName, policyArn string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	iamClient := iam.NewFromConfig(cfg)

	_, err = iamClient.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
		RoleName:  &roleName,
		PolicyArn: &policyArn,
	})
	if err != nil {
		return fmt.Errorf("failed to attach policy %s to role %s, %v", policyArn, roleName, err)
	}

	fmt.Printf("Policy %s attached to role %s successfully\n", policyArn, roleName)
	return nil
}

// associateIamInstanceProfile 函数将指定的IAM实例配置文件（角色）关联到EC2实例。
// 参数:
// - instanceID: EC2实例的ID。
// - roleARN: IAM角色的ARN。
// 返回:
// - error: 如果操作失败，则返回错误信息。
func associateIamInstanceProfile(instanceID, roleARN string) error {
	// 加载AWS配置
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	// 创建EC2客户端
	ec2Client := ec2.NewFromConfig(cfg)

	// 创建关联IAM实例配置文件的输入参数
	input := &ec2.AssociateIamInstanceProfileInput{
		IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{
			Arn: &roleARN,
		},
		InstanceId: &instanceID,
	}

	// 关联IAM实例配置文件
	_, err = ec2Client.AssociateIamInstanceProfile(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to associate IAM instance profile %s to instance %s, %v", roleARN, instanceID, err)
	}

	fmt.Printf("IAM instance profile %s associated with instance %s successfully\n", roleARN, instanceID)
	return nil
}

func prepareSysbenchData(rdsClient *rds.Client, ec2instanceID, clusterID, ec2KeyName string) error {

	// 获取Aurora集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(context.TODO(), describeDBClustersInput)
	if err != nil {
		log.Fatalf("Failed to describe DBClusters: %v", err)
		return err
	}
	if len(dbClustersOutput.DBClusters) == 0 {
		log.Fatalf("No DBCluster found with ID %s", clusterID)
		return err
	}

	// 获取Cluster Endpoint
	clusterEndpoint := dbClustersOutput.DBClusters[0].Endpoint
	clusterPort := dbClustersOutput.DBClusters[0].Port
	keypair := fmt.Sprintf("./%s.pem", ec2KeyName)

	// 构建sbtest create SQL 命令
	dropCmd := fmt.Sprintf(
		"mysql -u admin -p%s -h %s -P %d -e 'DROP DATABASE IF EXISTS sbtest; CREATE DATABASE sbtest;'",
		os.Getenv("MASTER_PASSWORD"), *clusterEndpoint, *clusterPort,
	)
	fmt.Printf("Drop cmd: %s\n", dropCmd)

	err = sshCommandRealtime(ec2instanceID, keypair, dropCmd, nil)
	if err != nil {
		return fmt.Errorf("failed to run sysbench prepare with SSH remote exec: %v", err)
	}

	// 构建 sysbench 命令
	prepareCmd := fmt.Sprintf(
		"sysbench oltp_common --report-interval=20 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --threads=50 --tables=50 --table-size=100000000 prepare",
		*clusterEndpoint, *clusterPort, os.Getenv("MASTER_PASSWORD"),
	)

	fmt.Printf("Prepare cmd: %s\n", prepareCmd)

	err = sshCommandRealtime(ec2instanceID, keypair, prepareCmd, nil)
	if err != nil {
		return fmt.Errorf("failed to run sysbench prepare with SSH remote exec: %v", err)
	}

	fmt.Println("sysbench prepare completed successfully")
	return nil
}

// pollCommandInvocation 轮询命令的执行状态并获取输出。
// 参数:
// - ssmClient: SSM 客户端
// - commandID: 命令的 ID
// - instanceID: EC2 实例的 ID
// 返回:
// - error: 如果操作失败，则返回错误信息

func pollCommandInvocation(ssmClient *ssm.Client, commandID, instanceID string) error {
	timeout := 2 * time.Hour // 设置超时时间为 2h
	startTime := time.Now()
	lastOutputLength := 0

	for {
		getCommandInvocationInput := &ssm.GetCommandInvocationInput{
			CommandId:  &commandID,
			InstanceId: &instanceID,
		}
		getCommandInvocationOutput, err := ssmClient.GetCommandInvocation(context.TODO(), getCommandInvocationInput)
		if err != nil {
			return fmt.Errorf("failed to get command invocation: %v", err)
		}

		status := getCommandInvocationOutput.Status
		stdOut := *getCommandInvocationOutput.StandardOutputContent
		stdErr := *getCommandInvocationOutput.StandardErrorContent

		// 打印当前状态
		fmt.Printf("Status: %s\n", status)

		// 获取新的输出内容
		if len(stdOut) > lastOutputLength {
			newOutput := stdOut[lastOutputLength:]
			fmt.Print(newOutput) // 实时打印新的输出内容
			lastOutputLength = len(stdOut)
		}

		if stdErr != "" {
			fmt.Printf("StandardErrorContent: %s\n", stdErr)
		}

		if status == "Success" || status == "Failed" || status == "Cancelled" {
			break
		}

		if time.Since(startTime) > timeout {
			return fmt.Errorf("command execution timed out after %v", timeout)
		}

		time.Sleep(2 * time.Second) // 每 2 秒轮询一次
	}
	return nil
}

func sshCommandRealtime(instanceID, sshKeyPath, command string, resultsFile *os.File) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)
	publicNDS, err := getPublicDNS(ec2Client, instanceID)
	if err != nil {
		return fmt.Errorf("failed to get public IP: %v", err)
	}

	sshUser := "ec2-user" // 默认的 EC2 用户名，根据您的 AMI 可能需要调整
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no %s@%s %s", sshKeyPath, sshUser, publicNDS, command)
	fmt.Printf("Exec cmd: %s\n", sshCmd)

	cmd := exec.Command("bash", "-c", sshCmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			output := fmt.Sprintf("[%s STDOUT]: %s", timestamp, scanner.Text())
			if resultsFile != nil {
				fmt.Println(output)
				resultsFile.WriteString(output + "\n")
			} else {
				fmt.Println(output)
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			timestamp := time.Now().Format("2006-01-02 15:04:05")
			output := fmt.Sprintf("[%s STDERR]: %s", timestamp, scanner.Text())
			if resultsFile != nil {
				fmt.Println(output)
				resultsFile.WriteString(output + "\n")
			} else {
				fmt.Println(output)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("command execution failed: %v", err)
	}

	return nil
}

func RunSysbenchPerftest(rdsClient *rds.Client, ssmClient *ssm.Client, ec2instanceID, clusterID, ec2KeyName, testtype string) error {
	// 获取 Aurora 集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(context.TODO(), describeDBClustersInput)
	if err != nil {
		return fmt.Errorf("failed to describe DBClusters: %v", err)
	}
	if len(dbClustersOutput.DBClusters) == 0 {
		return fmt.Errorf("no DBCluster found with ID %s", clusterID)
	}

	// 获取 Cluster intancecluss Endpoint 和 Port
	dbinstanceClass, err := getFirstAuroraInstanceClass(rdsClient, clusterID)
	if err != nil {
		return fmt.Errorf("failed to get aurora instance class: %v", err)

	}
	fmt.Printf("dbinstanceClass: %s\n", dbinstanceClass)

	clusterEndpoint := dbClustersOutput.DBClusters[0].Endpoint
	clusterPort := dbClustersOutput.DBClusters[0].Port

	// 把命令测试结果放到results 目录夹下
	testFile, err := createResultsFile(dbinstanceClass, testtype)
	if err != nil {
		return fmt.Errorf("faild to create test results file: %v", err)
	}

	threadsValues := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}

	for _, threads := range threadsValues {
		runCMD := fmt.Sprintf(
			"sysbench %s run --time=300 --threads=%d --report-interval=10 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --tables=50 --table-size=100000000 --mysql-ignore-errors=1062,2013,8028,9007",
			testtype, threads, *clusterEndpoint, *clusterPort, os.Getenv("MASTER_PASSWORD"),
		)

		fmt.Printf("Run cmd: %s\n", runCMD)
		keypair := fmt.Sprintf("./%s.pem", ec2KeyName)

		err = sshCommandRealtime(ec2instanceID, keypair, runCMD, testFile)
		if err != nil {
			return fmt.Errorf("failed to run sysbench with SSH remote exec: %v", err)
		}
		fmt.Printf("sysbench run completed successfully for threads=%d\n", threads)
	}

	fmt.Println("sysbench run totally completed successfully")
	return nil
}

func getFirstAuroraInstanceClass(rdsClient *rds.Client, clusterID string) (string, error) {
	// 获取 Aurora 集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(context.TODO(), describeDBClustersInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe DBClusters: %v", err)
	}
	if len(dbClustersOutput.DBClusters) == 0 {
		return "", fmt.Errorf("no DBCluster found with ID %s", clusterID)
	}

	// 获取集群中的第一个实例 ID
	dbCluster := dbClustersOutput.DBClusters[0]
	if len(dbCluster.DBClusterMembers) == 0 {
		return "", fmt.Errorf("no DB instances found in cluster %s", clusterID)
	}
	firstInstanceID := dbCluster.DBClusterMembers[0].DBInstanceIdentifier
	if firstInstanceID == nil {
		return "", fmt.Errorf("first DB instance identifier is nil in cluster %s", clusterID)
	}

	// 获取第一个实例的详细信息
	describeDBInstancesInput := &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: firstInstanceID,
	}
	dbInstancesOutput, err := rdsClient.DescribeDBInstances(context.TODO(), describeDBInstancesInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe DB instance %s: %v", *firstInstanceID, err)
	}
	if len(dbInstancesOutput.DBInstances) == 0 {
		return "", fmt.Errorf("no DB instance found with ID %s", *firstInstanceID)
	}

	// 获取第一个实例的机型信息
	firstInstance := dbInstancesOutput.DBInstances[0]
	instanceClass := firstInstance.DBInstanceClass
	if instanceClass == nil {
		return "", fmt.Errorf("DB instance class is nil for instance %s", *firstInstanceID)
	}

	return *instanceClass, nil
}

// RestoreAuroraClusterFromS3 从S3还原数据到已有的Aurora集群
func RestoreAuroraClusterFromS3(s3BucketName, s3Prefix, clusterID, roleARN, paramGroupName string) error {
	masterUserpassword := os.Getenv("MASTER_PASSWORD")
	parameterGroupFamily := "aurora-mysql8.0"
	paramterDescription := "Custom parameter group for Aurora MySQL 8.0"

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load aws config(~/.aws/config), %v", err)
	}
	rdsSvc := rds.NewFromConfig(cfg)

	params := &rds.RestoreDBClusterFromS3Input{
		DBClusterIdentifier: aws.String(clusterID),
		S3BucketName:        aws.String(s3BucketName),
		S3IngestionRoleArn:  aws.String(roleARN),
		S3Prefix:            aws.String(s3Prefix),
		SourceEngine:        aws.String("mysql"),
		SourceEngineVersion: aws.String("8.0.34"),
		Engine:              aws.String("aurora-mysql"),
		//EngineVersion:       aws.String("8.0.mysql_aurora.3.06.1"),
		MasterUsername:     aws.String("admin"),
		MasterUserPassword: aws.String(masterUserpassword),
		StorageEncrypted:   aws.Bool(true),
		KmsKeyId:           aws.String("arn:aws:kms:us-west-2:986330900858:key/0211dfe7-9583-408b-bd10-3d339906c08a"),
	}

	// 发送还原请求
	resp, err := rdsSvc.RestoreDBClusterFromS3(context.TODO(), params)
	if err != nil {
		return fmt.Errorf("failed to restore data to Aurora %s: %v", clusterID, err)
	}

	// 轮询集群状态，直到恢复完成, 超时时间2h
	retries := 0
	startTime := time.Now()
	for {
		clusterStatus, err := CheckClusterStatus(clusterID)
		if err != nil {
			return fmt.Errorf("error checking cluster status: %v", err)
		}
		fmt.Printf("Cluster %s status: %s\n", clusterID, clusterStatus)

		if clusterStatus == "available" || retries == 240 {
			duration := time.Since(startTime)
			fmt.Printf("Cluster %s is available and ready to use, cost time: %s\n", clusterID, duration)
			break
		}
		retries++
		time.Sleep(30 * time.Second)
	}
	fmt.Printf("successfully restore data to Aurora %s: %v\n", clusterID, resp)

	// 创建 paramtergroup
	rdsClient := rds.NewFromConfig(cfg)
	err = CreateDBClusterParameterGroup(rdsClient, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		log.Fatalf("Failed to create Aurora cluster parameter group, %v", err)
	}
	fmt.Printf("DBClusterParameterGroup created: %s\n", paramGroupName)

	// 绑定 paramtergroup 并修改参数到restore的集群
	modifyClusterParameters(rdsClient, clusterID, paramGroupName)

	return nil
}

// CheckClusterStatus 检查 Aurora 集群的状态
func CheckClusterStatus(clusterID string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config (~/.aws/config), %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 请求获取 DB 集群信息
	resp, err := rdsClient.DescribeDBClusters(context.TODO(), &rds.DescribeDBClustersInput{
		DBClusterIdentifier: aws.String(clusterID),
	})
	if err != nil {
		var opErr *smithy.OperationError
		if errors.As(err, &opErr) && strings.Contains(opErr.Error(), "DBClusterNotFoundFault") {
			return "deleted", nil
		}
		return "", fmt.Errorf("failed to describe DB cluster: %v", err)
	}

	if len(resp.DBClusters) == 0 {
		return "", fmt.Errorf("no DB cluster found with ID: %s", clusterID)
	}

	// 获取集群状态
	clusterStatus := aws.StringValue(resp.DBClusters[0].Status)
	return clusterStatus, nil
}

// CheckDBInstanceStatus 检查 DB 实例的状态
func CheckDBInstanceStatus(dbInstanceID string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config (~/.aws/config), %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)
	resp, err := rdsClient.DescribeDBInstances(context.TODO(), &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(dbInstanceID),
	})

	if err != nil {
		var opErr *smithy.OperationError
		if errors.As(err, &opErr) && strings.Contains(opErr.Error(), "DBInstanceNotFound") {
			return "deleted", nil
		}

		return "", fmt.Errorf("failed to describe DB instance %s: %v", dbInstanceID, err)
	}

	if len(resp.DBInstances) == 0 {
		return "", fmt.Errorf("no DB instance found with identifier: %s", dbInstanceID)
	}

	instanceStatus := aws.StringValue(resp.DBInstances[0].DBInstanceStatus)

	return instanceStatus, nil
}

// ModifyAuroraClusterPassword 修改Aurora MySQL集群的主用户密码
func ModifyAuroraClusterPassword(rdsSvc *rds.Client, clusterID, newMasterPassword string) error {
	params := &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(clusterID),
		MasterUserPassword:  aws.String(newMasterPassword),
	}
	_, err := rdsSvc.ModifyDBCluster(context.TODO(), params)
	if err != nil {
		return fmt.Errorf("failed to modify Aurora cluster %s password: %v", clusterID, err)
	}
	fmt.Printf("Successfully modified password for Aurora cluster %s\n", clusterID)
	return nil
}

// RestoreAuroraClusterFromSnapshot 从database snapshot还原数据到新建的Aurora集群
func RestoreAuroraClusterFromSnapshot(clusterID, snapshotID, dbInstanceClass, paramGroupName string) error {
	masterUserpassword := os.Getenv("MASTER_PASSWORD")
	parameterGroupFamily := "aurora-mysql8.0"
	paramterDescription := "Custom parameter group for Aurora MySQL 8.0"

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load aws config(~/.aws/config), %v", err)
	}
	rdsSvc := rds.NewFromConfig(cfg)

	params := &rds.RestoreDBClusterFromSnapshotInput{
		DBClusterIdentifier: aws.String(clusterID),
		Engine:              aws.String("aurora-mysql"),
		EngineVersion:       aws.String("8.0.mysql_aurora.3.06.1"),
		SnapshotIdentifier:  aws.String(snapshotID),
		KmsKeyId:            aws.String("arn:aws:kms:us-west-2:986330900858:key/fba177a3-e2d3-45bb-848e-79c586376a45"),
		//DBClusterInstanceClass: aws.String(dbInstanceClass),
	}

	// 发送还原请求，然后创建cluster的instance
	resp, err := rdsSvc.RestoreDBClusterFromSnapshot(context.TODO(), params)
	if err != nil {
		return fmt.Errorf("failed to restore from snapshot %s to Aurora cluster %s: %v", snapshotID, clusterID, err)
	}
	dbInstanceID := fmt.Sprintf("%s-instance", clusterID)
	err = CreateDBInstanceForCluster(clusterID, dbInstanceID, dbInstanceClass)
	if err != nil {
		log.Fatalf("failed to create database instance: %v\n", err)
	}

	// 轮询集群状态，直到恢复完成, 超时时间2h
	retries := 0
	startTime := time.Now()
	for {
		clusterStatus, err := CheckClusterStatus(clusterID)
		if err != nil {
			return fmt.Errorf("error checking cluster status: %v", err)
		}
		fmt.Printf("Cluster %s status: %s\n", clusterID, clusterStatus)

		if clusterStatus == "available" || retries == 240 {
			duration := time.Since(startTime)
			fmt.Printf("Cluster %s is available and ready to use, cost time: %s\n", clusterID, duration)
			break
		}
		retries++
		time.Sleep(30 * time.Second)
	}
	fmt.Printf("successfully restore data to Aurora %s: %v\n", clusterID, resp)

	// 修改主用户密码
	err = ModifyAuroraClusterPassword(rdsSvc, clusterID, masterUserpassword)
	if err != nil {
		return fmt.Errorf("failed to modify master user password: %v", err)
	}

	// 创建 paramtergroup
	rdsClient := rds.NewFromConfig(cfg)
	err = CreateDBClusterParameterGroup(rdsClient, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		log.Fatalf("Failed to create Aurora cluster parameter group, %v", err)
	}
	fmt.Printf("DBClusterParameterGroup created: %s\n", paramGroupName)

	// 绑定 paramtergroup 并修改参数到restore的集群
	modifyClusterParameters(rdsClient, clusterID, paramGroupName)

	return nil
}
