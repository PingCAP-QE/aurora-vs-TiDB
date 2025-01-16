package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func initPerfTestEnv(ec2Client *ec2.Client, ssmClient *ssm.Client, instanceID string) error {
	var inforkey = "InstanceIds"
	// 检查实例状态
	instanceState, err := getInstanceState(ec2Client, instanceID)
	if err != nil {
		return fmt.Errorf("failed to get instance state: %v", err)
	}
	if instanceState != "running" {
		return fmt.Errorf("instance %s is not in a valid state: %s", instanceID, instanceState)
	}
	fmt.Printf("current instance status: %s\n", instanceState)

	// 获取EC2实例的公共IP地址
	publicIP, err := getPublicIP(ec2Client, instanceID)
	if err != nil {
		return fmt.Errorf("failed to get public IP: %v", err)
	}
	fmt.Printf("ec2 instance public IP: %s\n", publicIP)

	// 检查 SSM Agent 状态
	ssmInfo, err := ssmClient.DescribeInstanceInformation(context.TODO(), &ssm.DescribeInstanceInformationInput{
		Filters: []types.InstanceInformationStringFilter{
			{
				Key:    &inforkey,
				Values: []string{instanceID},
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to describe instance information: %v", err)
	}

	// 如果 SSM Agent 未运行，尝试启动它
	if len(ssmInfo.InstanceInformationList) == 0 {
		// 给instance 实例附加上 SSM-role
		roleARN := "arn:aws:iam::986330900858:instance-profile/ec2-ssm-role"

		// 调用函数修改EC2实例的IAM角色
		err := associateIamInstanceProfile(instanceID, roleARN)
		if err != nil {
			log.Fatalf("Failed to attach SSM role to %s: %v", instanceID, err)
		}
		fmt.Println("SSM Agent is not running. Attempting to start it...")
		sshCommand := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no ec2-user@%s 'sudo systemctl start amazon-ssm-agent'", "./pub-st-rsa.pem", publicIP)
		cmd := exec.Command("bash", "-c", sshCommand)
		err = cmd.Run()
		if err != nil {
			log.Fatalf("Failed to start SSM Agent: %v", err)
		}
		fmt.Println("SSM Agent started successfully. Waiting for 30 seconds to ensure it's running...")
		time.Sleep(30 * time.Second)
	}
	// 检查 SSM Agent 服务状态
	statusCommand := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no ec2-user@%s 'sudo systemctl status amazon-ssm-agent'", "./pub-st-rsa.pem", publicIP)
	statusCmd := exec.Command("bash", "-c", statusCommand)
	output, err := statusCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check SSM Agent status: %v", err)
	}
	fmt.Println(string(output))

	// 安装mysql-client和sysbench的命令
	command := `
sudo yum update -y &&
sudo yum -y install git make automake libtool pkgconfig libaio-devel openssl-devel mysql-devel yum-utils mariadb.x86_64 -y &&
sudo git clone https://github.com/akopytov/sysbench.git &&
cd sysbench &&
sudo sh autogen.sh &&
sudo sh configure &&
sudo make -j4 &&
sudo make install
`
	_, err = runSSMCommand(ssmClient, instanceID, command)
	if err != nil {
		return fmt.Errorf("failed to run SSM command: %v", err)
	}

	fmt.Printf("mysql-client and sysbench installed on instance %s with IP %s\n", instanceID, publicIP)
	return nil
}

func getPublicIP(ec2Client *ec2.Client, instanceID string) (string, error) {
	// 获取EC2实例的详细信息
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

	// 获取公共IP地址
	publicIP := instancesOutput.Reservations[0].Instances[0].PublicIpAddress
	if publicIP == nil {
		return "", fmt.Errorf("public IP address not found for instance %s", instanceID)
	}
	return *publicIP, nil
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

func prepareSysbenchDataWithSSM(rdsClient *rds.Client, ssmClient *ssm.Client, ec2instanceID, clusterID, ec2KeyName string) error {

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

	// 构建sbtest create SQL 命令
	sqlCmd := fmt.Sprintf(
		"mysql -u admin -p%s -h %s -P %d -e 'DROP DATABASE IF EXISTS sbtest; CREATE DATABASE sbtest;'",
		os.Getenv("MASTER_PASSWORD"), *clusterEndpoint, *clusterPort,
	)
	fmt.Printf("Drop cmd: %s\n", sqlCmd)

	sendCommandOutput, err := runSSMCommand(ssmClient, ec2instanceID, sqlCmd)
	if err != nil {
		return fmt.Errorf("failed to run SQL commands with SSM: %v", err)
	}
	commandID := *sendCommandOutput.Command.CommandId
	err = pollCommandInvocation(ssmClient, commandID, ec2instanceID)
	if err != nil {
		return fmt.Errorf("error polling command invocation: %v", err)
	}

	// 构建 sysbench 命令
	prepareCmd := fmt.Sprintf(
		"sysbench oltp_common --report-interval=20 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --threads=50 --tables=50 --table-size=100000000 prepare",
		*clusterEndpoint, *clusterPort, os.Getenv("MASTER_PASSWORD"),
	)

	fmt.Printf("Prepare cmd: %s\n", prepareCmd)
	keypair := fmt.Sprintf("./%s.pem", ec2KeyName)

	err = sshCommandRealtime(ec2instanceID, keypair, prepareCmd)
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

func sshCommandRealtime(instanceID, sshKeyPath, command string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load SDK config, %v", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)
	publicIP, err := getPublicIP(ec2Client, instanceID)
	if err != nil {
		return fmt.Errorf("failed to get public IP: %v", err)
	}

	sshUser := "ec2-user" // 默认的 EC2 用户名，根据您的 AMI 可能需要调整
	sshCmd := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no %s@%s %s", sshKeyPath, sshUser, publicIP, command)
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
			fmt.Println("STDOUT:", scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println("STDERR:", scanner.Text())
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

	// 获取 Cluster Endpoint 和 Port
	clusterEndpoint := dbClustersOutput.DBClusters[0].Endpoint
	clusterPort := dbClustersOutput.DBClusters[0].Port

	// 获取环境变量中的密码
	masterPassword := os.Getenv("MASTER_PASSWORD")
	if masterPassword == "" {
		return fmt.Errorf("MASTER_PASSWORD environment variable is not set")
	}

	threadsValues := []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}

	for _, threads := range threadsValues {
		runCMD := fmt.Sprintf(
			"sysbench %s run --time=3600 --threads=%d --report-interval=10 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --tables=50 --table-size=100000000 --mysql-ignore-errors=1062,2013,8028,9007",
			testtype, threads, *clusterEndpoint, *clusterPort, masterPassword,
		)

		fmt.Printf("Run cmd: %s\n", runCMD)
		keypair := fmt.Sprintf("./%s.pem", ec2KeyName)

		err = sshCommandRealtime(ec2instanceID, keypair, runCMD)
		if err != nil {
			return fmt.Errorf("failed to run sysbench with SSH remote exec: %v", err)
		}
		fmt.Printf("sysbench run completed successfully for threads=%d\n", threads)
	}

	fmt.Println("sysbench run totally completed successfully")
	return nil
}
