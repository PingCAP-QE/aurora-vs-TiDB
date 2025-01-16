package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
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
		fmt.Println("SSM Agent is not running. Attempting to start it...")
		sshCommand := fmt.Sprintf("ssh -i %s -o StrictHostKeyChecking=no ec2-user@%s 'sudo systemctl start amazon-ssm-agent'", "./pub-st-rsa.pem", publicIP)
		cmd := exec.Command("bash", "-c", sshCommand)
		err := cmd.Run()
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
