package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func initPerfTestEnv(ctx context.Context, ec2InstanceID, ec2KeyName string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("unable to load AWS config: %v", err)
	}
	ec2Client := ec2.NewFromConfig(cfg)

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

func runSSMCommand(ctx context.Context, ssmClient *ssm.Client, instanceID, command string) (*ssm.SendCommandOutput, error) {
	var shellcmddescribe string = "AWS-RunShellScript"
	// 使用SSM运行命令
	sendCommandInput := &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: &shellcmddescribe,
		Parameters: map[string][]string{
			"commands": {command},
		},
	}
	sendCommandOutput, err := ssmClient.SendCommand(ctx, sendCommandInput)
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

func prepareSysbenchData(ctx context.Context, ec2instanceID, clusterID, ec2KeyName string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		log.Fatalf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

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
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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

func RunSysbenchPerftest(ctx context.Context, ec2instanceID, clusterID, ec2KeyName, testtype string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		log.Fatalf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

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
			"sysbench %s run --time=600 --threads=%d --report-interval=10 --rand-type=uniform --mysql-db=sbtest --mysql-host=%s --mysql-port=%d --mysql-user=admin --mysql-password=%s --tables=50 --table-size=100000000 --mysql-ignore-errors=1062,2013,8028,9007",
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
