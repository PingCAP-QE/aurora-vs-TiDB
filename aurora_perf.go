package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
)

func initPerfTestEnv(ctx context.Context, ec2Client *ec2.Client, ec2InstanceID, ec2KeyName string) error {
	// 检查实例状态
	instanceState, err := getInstanceState(ctx, ec2Client, ec2InstanceID)
	if err != nil {
		return fmt.Errorf("failed to get instance state: %v", err)
	}
	if instanceState != "running" {
		return fmt.Errorf("instance %s is not in a valid state: %s", ec2InstanceID, instanceState)
	}
	log.Infof("current instance status: %s", instanceState)
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

	err = sshCommandRealtime(ctx, ec2InstanceID, keypair, command, nil)
	if err != nil {
		return fmt.Errorf("failed to run command: %v", err)
	}

	log.Infof("mysql-client and sysbench installed on EC2 instance %s", ec2InstanceID)
	return nil
}

func getPublicDNS(ctx context.Context, ec2Client *ec2.Client, ec2InstanceID string) (string, error) {
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

func getInstanceState(ctx context.Context, ec2Client *ec2.Client, instanceID string) (string, error) {
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}
	instancesOutput, err := ec2Client.DescribeInstances(ctx, describeInstancesInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe instances: %v", err)
	}
	if len(instancesOutput.Reservations) == 0 || len(instancesOutput.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no instance found with ID %s", instanceID)
	}

	instance := instancesOutput.Reservations[0].Instances[0]
	return string(instance.State.Name), nil
}

// attachPolicyToRole 将指定的IAM策略附加到指定的IAM角色。
func attachPolicyToRole(ctx context.Context, roleName, policyArn string) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	iamClient := iam.NewFromConfig(cfg)

	_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  &roleName,
		PolicyArn: &policyArn,
	})
	if err != nil {
		return fmt.Errorf("failed to attach policy %s to role %s, %v", policyArn, roleName, err)
	}

	log.Infof("Policy %s attached to role %s successfully", policyArn, roleName)
	return nil
}

// associateIamInstanceProfile 将指定的IAM实例配置文件（角色）关联到EC2实例。
func associateIamInstanceProfile(ctx context.Context, instanceID, roleARN string) error {
	// 加载AWS配置
	cfg, err := config.LoadDefaultConfig(ctx)
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
	_, err = ec2Client.AssociateIamInstanceProfile(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to associate IAM instance profile %s to instance %s, %v", roleARN, instanceID, err)
	}

	log.Infof("IAM instance profile %s associated with instance %s successfully", roleARN, instanceID)
	return nil
}

func prepareSysbenchData(ctx context.Context, rdsClient *rds.Client, ec2instanceID, clusterID, ec2KeyName string) error {
	// 获取Aurora集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(ctx, describeDBClustersInput)
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
	log.Infof("Drop cmd: %s", dropCmd)

	err = sshCommandRealtime(ctx, ec2instanceID, keypair, dropCmd, nil)
	if err != nil {
		return fmt.Errorf("failed to run sysbench prepare with SSH remote exec: %v", err)
	}

	// 构建 sysbench 命令
	prepareCmd := fmt.Sprintf(
		"sysbench oltp_common --report-interval=20 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --threads=50 --tables=50 --table-size=100000000 prepare",
		*clusterEndpoint, *clusterPort, os.Getenv("MASTER_PASSWORD"),
	)

	log.Infof("Prepare cmd: %s", prepareCmd)

	err = sshCommandRealtime(ctx, ec2instanceID, keypair, prepareCmd, nil)
	if err != nil {
		return fmt.Errorf("failed to run sysbench prepare with SSH remote exec: %v", err)
	}

	fmt.Println("sysbench prepare completed successfully")
	return nil
}

// pollCommandInvocation 轮询命令的执行状态并获取输出。
func pollCommandInvocation(ctx context.Context, ssmClient *ssm.Client, commandID, instanceID string) error {
	timeout := 2 * time.Hour // 设置超时时间为 2h
	startTime := time.Now()
	lastOutputLength := 0

	for {
		getCommandInvocationInput := &ssm.GetCommandInvocationInput{
			CommandId:  &commandID,
			InstanceId: &instanceID,
		}
		getCommandInvocationOutput, err := ssmClient.GetCommandInvocation(ctx, getCommandInvocationInput)
		if err != nil {
			return fmt.Errorf("failed to get command invocation: %v", err)
		}

		status := getCommandInvocationOutput.Status
		stdOut := *getCommandInvocationOutput.StandardOutputContent
		stdErr := *getCommandInvocationOutput.StandardErrorContent

		// 打印当前状态
		log.Infof("Status: %s", status)

		// 获取新的输出内容
		if len(stdOut) > lastOutputLength {
			newOutput := stdOut[lastOutputLength:]
			fmt.Print(newOutput) // 实时打印新的输出内容
			lastOutputLength = len(stdOut)
		}

		if stdErr != "" {
			log.Infof("StandardErrorContent: %s", stdErr)
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

func sshCommandRealtime(ctx context.Context, instanceID, sshKeyPath, command string, resultsFile *os.File) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)
	publicNDS, err := getPublicDNS(ctx, ec2Client, instanceID)
	if err != nil {
		return fmt.Errorf("failed to get public IP: %v", err)
	}

	sshUser := "ec2-user" // 默认的 EC2 用户名，根据您的 AMI 可能需要调整
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no %s@%s %s", sshKeyPath, sshUser, publicNDS, command)
	log.Infof("Exec cmd: %s", sshCmd)

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

	// 启动处理 stdout 的 goroutine
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				log.Infof("SSH command execution cancelled")
				return
			default:
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				output := fmt.Sprintf("[%s STDOUT]: %s", timestamp, scanner.Text())
				if resultsFile != nil {
					fmt.Println(output)
					resultsFile.WriteString(output + "\n")
				} else {
					fmt.Println(output)
				}
			}
		}
	}()

	// 启动处理 stderr 的 goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				log.Infof("SSH command execution cancelled")
				return
			default:
				timestamp := time.Now().Format("2006-01-02 15:04:05")
				output := fmt.Sprintf("[%s STDERR]: %s", timestamp, scanner.Text())
				if resultsFile != nil {
					fmt.Println(output)
					resultsFile.WriteString(output + "\n")
				} else {
					fmt.Println(output)
				}
			}
		}
	}()

	// 等待命令执行完毕，检查是否取消
	err = cmd.Wait()
	if err != nil {
		select {
		case <-ctx.Done():
			return fmt.Errorf("SSH command execution cancelled: %v", ctx.Err())
		default:
			return fmt.Errorf("command execution failed: %v", err)
		}
	}
	return nil
}

func RunSysbenchPerftest(ctx context.Context, rdsClient *rds.Client, ssmClient *ssm.Client, ec2instanceID, clusterID, ec2KeyName, testtype string) error {
	// 获取 Aurora 集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(ctx, describeDBClustersInput)
	if err != nil {
		return fmt.Errorf("failed to describe DBClusters: %v", err)
	}
	if len(dbClustersOutput.DBClusters) == 0 {
		return fmt.Errorf("no DBCluster found with ID %s", clusterID)
	}

	// 获取 Cluster intancecluss Endpoint 和 Port
	dbinstanceClass, err := getFirstAuroraInstanceClass(ctx, rdsClient, clusterID)
	if err != nil {
		return fmt.Errorf("failed to get aurora instance class: %v", err)
	}
	log.Infof("dbinstanceClass: %s", dbinstanceClass)

	clusterEndpoint := dbClustersOutput.DBClusters[0].Endpoint
	clusterPort := dbClustersOutput.DBClusters[0].Port

	// 把命令测试结果放到results 目录夹下
	testFile, err := createResultsFile(dbinstanceClass, testtype)
	if err != nil {
		return fmt.Errorf("failed to create test results file: %v", err)
	}

	threadsValues := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}

	// 在开始前检查 ctx 是否已被取消
	select {
	case <-ctx.Done():
		return fmt.Errorf("operation cancelled before starting Sysbench tests: %v", ctx.Err())
	default:
	}

	for _, threads := range threadsValues {
		select {
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled before completing threads=%d: %v", threads, ctx.Err())
		default:
		}

		runCMD := fmt.Sprintf(
			"sysbench %s run --time=300 --threads=%d --report-interval=10 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --tables=50 --table-size=100000000 --mysql-ignore-errors=1062,2013,8028,9007",
			testtype, threads, *clusterEndpoint, *clusterPort, os.Getenv("MASTER_PASSWORD"),
		)

		log.Infof("Run cmd: %s", runCMD)
		keypair := fmt.Sprintf("./%s.pem", ec2KeyName)

		// 在执行命令前再次检查 ctx 状态
		err = sshCommandRealtime(ctx, ec2instanceID, keypair, runCMD, testFile)
		if err != nil {
			return fmt.Errorf("failed to run sysbench with SSH remote exec: %v", err)
		}
		log.Infof("sysbench run completed successfully for threads=%d", threads)
	}

	// 如果所有循环完成, 但ctx取消, 仍然可能是个问题
	select {
	case <-ctx.Done():
		return fmt.Errorf("operation cancelled after completing sysbench: %v", ctx.Err())
	default:
	}

	fmt.Println("sysbench run totally completed successfully")
	return nil
}

func getFirstAuroraInstanceClass(ctx context.Context, rdsClient *rds.Client, clusterID string) (string, error) {
	// 获取 Aurora 集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(ctx, describeDBClustersInput)
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
	dbInstancesOutput, err := rdsClient.DescribeDBInstances(ctx, describeDBInstancesInput)
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
func RestoreAuroraClusterFromS3(ctx context.Context, s3BucketName, s3Prefix, clusterID, roleARN, paramGroupName string) error {
	masterUserpassword := os.Getenv("MASTER_PASSWORD")
	parameterGroupFamily := "aurora-mysql8.0"
	paramterDescription := "Custom parameter group for Aurora MySQL 8.0"

	cfg, err := config.LoadDefaultConfig(ctx)
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
	resp, err := rdsSvc.RestoreDBClusterFromS3(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to restore data to Aurora %s: %v", clusterID, err)
	}

	// 轮询集群状态，直到恢复完成, 超时时间2h
	retries := 0
	startTime := time.Now()
	for {
		clusterStatus, err := CheckClusterStatus(ctx, clusterID)
		if err != nil {
			return fmt.Errorf("error checking cluster status: %v", err)
		}
		log.Infof("Cluster %s status: %s", clusterID, clusterStatus)

		if clusterStatus == "available" || retries == 240 {
			duration := time.Since(startTime)
			log.Infof("Cluster %s is available and ready to use, cost time: %s", clusterID, duration)
			break
		}
		retries++
		time.Sleep(30 * time.Second)
	}
	log.Infof("successfully restore data to Aurora %s: %v", clusterID, resp)

	// 创建 paramtergroup
	rdsClient := rds.NewFromConfig(cfg)
	err = CreateDBClusterParameterGroup(ctx, rdsClient, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		log.Fatalf("Failed to create Aurora cluster parameter group, %v", err)
	}
	log.Infof("DBClusterParameterGroup created: %s", paramGroupName)

	// 绑定 paramtergroup 并修改参数到restore的集群
	modifyClusterParameters(ctx, rdsClient, clusterID, paramGroupName)

	return nil
}

// CheckClusterStatus 检查 Aurora 集群的状态
func CheckClusterStatus(ctx context.Context, clusterID string) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config (~/.aws/config), %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 请求获取 DB 集群信息
	resp, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
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

	return *resp.DBClusters[0].Status, nil
}

// CheckDBInstanceStatus 检查 DB 实例的状态
func CheckDBInstanceStatus(ctx context.Context, dbInstanceID string) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config (~/.aws/config), %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)
	resp, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
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

	return *resp.DBInstances[0].DBInstanceStatus, nil
}

// ModifyAuroraClusterPassword 修改Aurora MySQL集群的主用户密码
func ModifyAuroraClusterPassword(ctx context.Context, rdsSvc *rds.Client, clusterID, newMasterPassword string) error {
	params := &rds.ModifyDBClusterInput{
		DBClusterIdentifier: aws.String(clusterID),
		MasterUserPassword:  aws.String(newMasterPassword),
	}
	_, err := rdsSvc.ModifyDBCluster(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to modify Aurora cluster %s password: %v", clusterID, err)
	}
	log.Infof("Successfully modified password for Aurora cluster %s", clusterID)
	return nil
}

// RestoreAuroraClusterFromSnapshot 从database snapshot还原数据到新建的Aurora集群
func RestoreAuroraClusterFromSnapshot(ctx context.Context, clusterID, snapshotID, dbInstanceClass, paramGroupName string) error {
	masterUserpassword := os.Getenv("MASTER_PASSWORD")
	parameterGroupFamily := "aurora-mysql8.0"
	paramterDescription := "Custom parameter group for Aurora MySQL 8.0"

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsSvc := rds.NewFromConfig(cfg)

	params := &rds.RestoreDBClusterFromSnapshotInput{
		DBClusterIdentifier: aws.String(clusterID),
		Engine:              aws.String("aurora-mysql"),
		EngineVersion:       aws.String("8.0.mysql_aurora.3.06.1"),
		SnapshotIdentifier:  aws.String(snapshotID),
		KmsKeyId:            aws.String("arn:aws:kms:us-west-2:986330900858:key/fba177a3-e2d3-45bb-848e-79c586376a45"),
		StorageType:         aws.String("aurora-iopt1"), // aurora i-o optimized type
		//DBClusterInstanceClass: aws.String(dbInstanceClass),
	}

	// 发送还原请求，然后创建cluster的instance
	resp, err := rdsSvc.RestoreDBClusterFromSnapshot(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to restore from snapshot %s to Aurora cluster %s: %v", snapshotID, clusterID, err)
	}
	dbInstanceID := fmt.Sprintf("%s-instance", clusterID)
	err = CreateDBInstanceForCluster(ctx, clusterID, dbInstanceID, dbInstanceClass)
	if err != nil {
		return fmt.Errorf("failed to create database instance: %v", err)
	}
	startTime := time.Now()

	// 轮询集群状态，直到恢复完成, 超时时间3h
	err = PollResourceStatus(ctx, clusterID, ResourceTypeAuroraCluster, "available", 3*time.Hour, CheckClusterStatus)
	if err != nil {
		return fmt.Errorf("Failed to create restore aurora cluster %s: %v", clusterID, err)
	}

	// 继续轮询实例状态，直到状态为 available 表示migrate完成，超时时间1h
	err = PollResourceStatus(ctx, dbInstanceID, ResourceTypeAuroraInstance, "available", 3*time.Hour, CheckDBInstanceStatus)
	if err != nil {
		return fmt.Errorf("Failed to create restore aurora instance %s: %v", dbInstanceID, err)
	}

	GreenInfof("successfully restore data to Aurora %s: %v, total restore cost time: %v", clusterID, resp, time.Since(startTime))

	// 修改主用户密码
	err = ModifyAuroraClusterPassword(ctx, rdsSvc, clusterID, masterUserpassword)
	if err != nil {
		return fmt.Errorf("failed to modify master user password: %v", err)
	}

	// 创建 paramtergroup
	rdsClient := rds.NewFromConfig(cfg)
	err = CreateDBClusterParameterGroup(ctx, rdsClient, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		return fmt.Errorf("Failed to create Aurora cluster parameter group, %v", err)
	}
	log.Infof("DBClusterParameterGroup created: %s", paramGroupName)

	// 绑定 paramtergroup 并修改参数到restore的集群
	modifyClusterParameters(ctx, rdsClient, clusterID, paramGroupName)

	// 重启实例
	err = RestartDBInstance(ctx, dbInstanceID)
	if err != nil {
		return fmt.Errorf("failed to restart database instance: %v", err)
	}

	return nil
}

// RestartDBInstance 重启指定的数据库实例
func RestartDBInstance(ctx context.Context, instanceID string) error {
	// 加载默认配置
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Unable to load aws config(~/.aws/config), %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 构建重启实例请求参数
	params := &rds.RebootDBInstanceInput{
		DBInstanceIdentifier: aws.String(instanceID),
	}

	// 发送重启实例请求
	_, err = rdsClient.RebootDBInstance(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to reboot DB instance %s: %v", instanceID, err)
	}

	log.Infof("Successfully rebooted DB instance %s", instanceID)
	return nil
}

func ModifyAuroraInstanceType(ctx context.Context, clusterID, instanceType string) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS configuration: %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 获取集群中的实例列表
	describeOutput, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		Filters: []rdstypes.Filter{
			{
				Name:   aws.String("db-cluster-id"),
				Values: []string{clusterID},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to describe DB instances: %v", err)
	}

	// 修改每个实例的类型
	for _, dbInstance := range describeOutput.DBInstances {
		instanceID := *dbInstance.DBInstanceIdentifier
		log.Infof("Modifying instance %s to type %s", instanceID, instanceType)

		_, err := rdsClient.ModifyDBInstance(ctx, &rds.ModifyDBInstanceInput{
			DBInstanceIdentifier: aws.String(instanceID),
			DBInstanceClass:      aws.String(instanceType),
			ApplyImmediately:     aws.Bool(true),
		})
		if err != nil {
			return fmt.Errorf("failed to modify instance %s: %v", instanceID, err)
		}
		// 轮询每个实例状态，直到状态为 available 表示更改完成，超时时间1h
		err = PollResourceStatus(ctx, instanceID, ResourceTypeAuroraInstance, "available", 1*time.Hour, CheckDBInstanceStatus)
		if err != nil {
			return fmt.Errorf("Failed to modify Aurora instance %s to type %s: %v", instanceID, instanceType, err)
		}
		log.Infof("Modification of instance %s to type %s initiated successfully", instanceID, instanceType)
	}
	// 轮询集群状态，直到恢复完成, 超时时间1h
	err = PollResourceStatus(ctx, clusterID, ResourceTypeAuroraCluster, "available", 1*time.Hour, CheckClusterStatus)
	if err != nil {
		return fmt.Errorf("Failed to get Aurora cluster %s status to available: %v", clusterID, err)
	}
	log.Infof("Modification cluster %s all instances to type %s successfully", clusterID, instanceType)
	return nil
}
