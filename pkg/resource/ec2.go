package resource

import (
	"context"
	"fmt"
	"time"

	credentials "aurora-vs-TiDB/pkg/credentials"
	util "aurora-vs-TiDB/pkg/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	log "github.com/sirupsen/logrus"
)

func CreateClientEC2(ctx context.Context, clusterID, instanceType, imageID, keyName string) (string, string, error) {
	cfg, err := credentials.GetAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return "", "", fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)
	// 获取Aurora集群的VPC-ID
	vpcID, err := getAuroraClusterVPC(ctx, rdsClient, clusterID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get Aurora cluster VPC: %v", err)
	}

	// 创建新的安全组
	sgname := "ec2-client-sg"
	securityGroupID, err := createSecurityGroup(ctx, ec2Client, vpcID, sgname)
	if err != nil {
		return "", "", fmt.Errorf("failed to create security group: %v", err)
	}

	// 获取默认子网
	subnetID, err := getAuroraClusterFirstInstanceSubnet(ctx, rdsClient, clusterID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get RDS instance subnet: %v", err)
	}

	log.Infof("begin to create ec2 instance, type %s", instanceType)
	// 创建EC2实例
	runInstancesInput := &ec2.RunInstancesInput{
		ImageId:      aws.String(imageID),
		InstanceType: types.InstanceType(instanceType),
		KeyName:      aws.String(keyName),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		SubnetId:     aws.String(subnetID),
		SecurityGroupIds: []string{
			securityGroupID,
		},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "instance",
				Tags: []types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String("aurora-perftest-client"),
					},
				},
			},
		},
	}

	runInstancesOutput, err := ec2Client.RunInstances(ctx, runInstancesInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to create EC2 instance: %v", err)
	}
	log.Infof("EC2 instance created: %v", runInstancesOutput)

	// 获取实例ID
	ec2InstanceID := aws.ToString(runInstancesOutput.Instances[0].InstanceId)
	log.Infof("EC2 instance ID: %s", ec2InstanceID)

	// 等待实例运行
	err = util.PollResourceStatus(ctx, ec2InstanceID, util.ResourceTypeEC2Instance, "running", 10*time.Minute, CheckEC2InstanceStatus)
	if err != nil {
		return "", "", fmt.Errorf("EC2 instance %s created failed", ec2InstanceID)
	}

	log.Infof("EC2 instance is running: %s", ec2InstanceID)

	// 获取实例的公有DNS名称
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{ec2InstanceID},
	}
	instancesOutput, err := ec2Client.DescribeInstances(ctx, describeInstancesInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to describe instances: %v", err)
	}
	publicDNS := aws.ToString(instancesOutput.Reservations[0].Instances[0].PublicDnsName)
	if publicDNS == "" {
		return "", "", fmt.Errorf("public DNS name not found for instance %s", ec2InstanceID)
	}

	return ec2InstanceID, publicDNS, nil
}

func createSecurityGroup(ctx context.Context, ec2Client *ec2.Client, vpcID, groupName string) (string, error) {
	var vpcid string = "vpc-id"
	var grpname string = "group-name"
	var sgdescirbe = "Security group for EC2 client instance"
	// 检查安全组是否已存在
	describeSecurityGroupsInput := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
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
	securityGroupsOutput, err := ec2Client.DescribeSecurityGroups(ctx, describeSecurityGroupsInput)
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
	securityGroupOutput, err := ec2Client.CreateSecurityGroup(ctx, createSecurityGroupInput)
	if err != nil {
		return "", fmt.Errorf("failed to create security group: %v", err)
	}
	return *securityGroupOutput.GroupId, nil
}

func getDefaultSubnet(ctx context.Context, client *ec2.Client, vpcID string) (string, error) {
	var vpcid string = "vpc-id"
	var vpconfig string = "default-for-az"
	// 获取默认子网
	describeSubnetsInput := &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
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
	subnetsOutput, err := client.DescribeSubnets(ctx, describeSubnetsInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe subnets: %v", err)
	}
	if len(subnetsOutput.Subnets) == 0 {
		return "", fmt.Errorf("no default subnet found in VPC %s", vpcID)
	}
	return *subnetsOutput.Subnets[0].SubnetId, nil
}

// CheckEC2InstanceStatus 检查 EC2 实例的状态
func CheckEC2InstanceStatus(ctx context.Context, ec2InstanceID string) (string, error) {
	cfg, err := credentials.GetAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to load AWS config: %v", err)
	}
	ec2Client := ec2.NewFromConfig(cfg)

	// 调用 DescribeInstances 获取实例状态
	resp, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{ec2InstanceID},
	})
	if err != nil {
		return "", fmt.Errorf("failed to describe EC2 instance %s: %v", ec2InstanceID, err)
	}

	if len(resp.Reservations) == 0 || len(resp.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("no EC2 instance found with ID: %s", ec2InstanceID)
	}

	instance := resp.Reservations[0].Instances[0]
	state := string(instance.State.Name)

	return state, nil
}

func DeleteClientEC2(ctx context.Context, ec2InstanceID string) error {
	cfg, err := credentials.GetAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	ec2Client := ec2.NewFromConfig(cfg)

	// 终止EC2实例
	terminateInstancesInput := &ec2.TerminateInstancesInput{
		InstanceIds: []string{ec2InstanceID},
	}

	terminateInstancesOutput, err := ec2Client.TerminateInstances(ctx, terminateInstancesInput)
	if err != nil {
		return fmt.Errorf("failed to terminate EC2 instance: %v", err)
	}
	log.Infof("Begin to delete EC2 instance: %v", terminateInstancesOutput)

	// 等待实例终止，超时10分钟
	err = util.PollResourceStatus(ctx, ec2InstanceID, util.ResourceTypeEC2Instance, "terminated", 10*time.Minute, CheckEC2InstanceStatus)
	if err != nil {
		return fmt.Errorf("EC2 instance %s deleted failed", ec2InstanceID)
	}
	log.Infof("EC2 instance is terminated: %s", ec2InstanceID)

	return nil
}

func GetPublicDNS(ctx context.Context, ec2Client *ec2.Client, ec2InstanceID string) (string, error) {
	// 获取EC2实例的详细信息
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{ec2InstanceID},
	}
	instancesOutput, err := ec2Client.DescribeInstances(ctx, describeInstancesInput)
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
