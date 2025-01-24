package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/smithy-go"
	log "github.com/sirupsen/logrus"
)

func CreateAuroraResources(ctx context.Context, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	var backupRetentionPeriod int32 = 1
	var publiclyAccessible bool = false

	// 定义Aurora集群和实例的参数
	masterUsername := "admin"
	dbName := "mydb"
	engineVersion := "8.0.mysql_aurora.3.06.1" // 使用正确的版本号
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

	createClusterOutput, err := rdsClient.CreateDBCluster(ctx, createClusterInput)
	if err != nil {
		return fmt.Errorf("Failed to exec Aurora cluster create command, %v", err)
	}

	// 轮询集群状态，直到状态为 available 表示创建完成，超时时间10分钟
	err = PollResourceStatus(ctx, clusterID, ResourceTypeAuroraCluster, "available", 10*time.Minute, CheckClusterStatus)
	if err != nil {
		return fmt.Errorf("Failed to wait Aurora cluster %s to available status: %v", clusterID, err)
	}

	log.Infof("Aurora cluster created: %v", createClusterOutput)

	// 创建Aurora数据库实例
	createInstanceInput := &rds.CreateDBInstanceInput{
		DBInstanceIdentifier: &instanceID,
		DBInstanceClass:      &dbInstanceClass,
		Engine:               &engine,
		DBClusterIdentifier:  &clusterID,
		PubliclyAccessible:   &publiclyAccessible,
	}

	createInstanceOutput, err := rdsClient.CreateDBInstance(ctx, createInstanceInput)
	if err != nil {
		return fmt.Errorf("Failed to exec Aurora instance create command, %v", err)
	}

	// 轮询实例状态，直到状态为 available 表示创建完成，超时时间10分钟
	err = PollResourceStatus(ctx, instanceID, ResourceTypeAuroraInstance, "available", 10*time.Minute, CheckDBInstanceStatus)
	if err != nil {
		return fmt.Errorf("Failed to create Aurora instance %s: %v", instanceID, err)
	}

	log.Infof("Aurora instance created: %v", createInstanceOutput)

	err = CreateDBClusterParameterGroup(ctx, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		return fmt.Errorf("Failed to create Aurora cluster parameter group, %v", err)
	}
	log.Infof("DBClusterParameterGroup created: %s", paramGroupName)
	return nil
}

func CreateDBInstanceForCluster(ctx context.Context, clusterID, instanceID, instanceClass string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 构建创建实例请求参数
	params := &rds.CreateDBInstanceInput{
		DBInstanceIdentifier: aws.String(instanceID),
		DBClusterIdentifier:  aws.String(clusterID),
		DBInstanceClass:      aws.String(instanceClass),
		Engine:               aws.String("aurora-mysql"),
	}

	// 发送创建实例请求
	resp, err := rdsClient.CreateDBInstance(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to create DB instance %s for cluster %s: %v", instanceID, clusterID, err)
	}

	log.Infof("Successfully created DB instance %s for cluster %s: %v", instanceID, clusterID, resp)
	return nil
}

// CreateDBClusterParameterGroup 创建 DBCluster 参数组
func CreateDBClusterParameterGroup(ctx context.Context, paramGroupName, paramterDescription, parameterGroupFamily string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	createParamGroupInput := &rds.CreateDBClusterParameterGroupInput{
		DBClusterParameterGroupName: aws.String(paramGroupName),
		Description:                 aws.String(paramterDescription),
		DBParameterGroupFamily:      aws.String(parameterGroupFamily),
	}
	_, err = rdsClient.CreateDBClusterParameterGroup(ctx, createParamGroupInput)
	if err != nil {
		// 处理错误，检查是否已经存在
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "DBClusterParameterGroupAlreadyExistsFault" {
				log.Warnf("Parameter group %s already exists, retcode: %s", paramGroupName, apiErr.ErrorCode())
				return nil // 如果已存在，直接返回
			}
		}
		return err
	}
	GreenInfof("Aurora-Parameter-Group %s created successfully", paramGroupName)
	return nil
}

func ModifyClusterParameters(ctx context.Context, clusterID, paramGroupName string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 修改新参数组中的参数
	paramName := "max_prepared_stmt_count"
	paramValue := "1048576"
	modifyDBClusterParameterGroupInput := &rds.ModifyDBClusterParameterGroupInput{
		DBClusterParameterGroupName: &paramGroupName,
		Parameters: []types.Parameter{
			{
				ParameterName:  &paramName,
				ParameterValue: &paramValue,
				ApplyMethod:    types.ApplyMethodImmediate,
			},
		},
	}

	_, err = rdsClient.ModifyDBClusterParameterGroup(ctx, modifyDBClusterParameterGroupInput)
	if err != nil {
		log.Errorf("Failed to modify DBClusterParameterGroup, %v", err)
		return err
	}
	log.Infof("DBClusterParameterGroup modified: %s set to %s", paramName, paramValue)

	// 将新参数组关联到数据库集群
	modifyDBClusterInput := &rds.ModifyDBClusterInput{
		DBClusterIdentifier:         &clusterID,
		DBClusterParameterGroupName: &paramGroupName,
	}

	_, err = rdsClient.ModifyDBCluster(ctx, modifyDBClusterInput)
	if err != nil {
		log.Errorf("Failed to modify DBCluster, %v", err)
		return err
	}
	log.Infof("DBCluster modified to use new parameter group: %s", paramGroupName)
	return nil
}

func DeleteAuroraResources(ctx context.Context, clusterID, instanceID, paramGroupName string) error {
	var apiErr smithy.APIError

	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 删除Aurora数据库实例
	deleteInstanceInput := &rds.DeleteDBInstanceInput{
		DBInstanceIdentifier: aws.String(instanceID),
		SkipFinalSnapshot:    aws.Bool(true),
	}

	_, err = rdsClient.DeleteDBInstance(ctx, deleteInstanceInput)
	if err != nil {
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() != "DBInstanceNotFound" {
				return fmt.Errorf("Failed to delete Aurora instance, %v", err)
			}
			log.Warnf("Aurora db-instance %s already deleted, retcode: %s", instanceID, apiErr.ErrorCode())
		}
	}

	// 轮询实例状态，直到状态为 deleted 表示创建完成，超时时间20分钟
	err = PollResourceStatus(ctx, instanceID, ResourceTypeAuroraInstance, "deleted", 20*time.Minute, CheckDBInstanceStatus)
	if err != nil {
		log.Errorf("Failed to delete Aurora instance %s: %v", instanceID, err)
		return fmt.Errorf("Failed to delete Aurora instance %s: %v", instanceID, err)
	}

	log.Infof("Aurora instance deleted: %v", instanceID)

	// 删除Aurora集群
	deleteClusterInput := &rds.DeleteDBClusterInput{
		DBClusterIdentifier: &clusterID,
		SkipFinalSnapshot:   aws.Bool(true),
	}

	_, err = rdsClient.DeleteDBCluster(ctx, deleteClusterInput)
	if err != nil {
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() != "DBClusterNotFoundFault" {
				log.Errorf("Failed to delete Aurora cluster, %v", err)
				return fmt.Errorf("Failed to delete Aurora cluster, %v", err)
			}
			log.Warnf("Aurora cluster %s already deleted, retcode: %s", clusterID, apiErr.ErrorCode())
		}
	}

	// 轮询集群状态，直到状态为 deleted 表示创建完成，超时时间10分钟
	err = PollResourceStatus(ctx, clusterID, ResourceTypeAuroraCluster, "deleted", 10*time.Minute, CheckClusterStatus)
	if err != nil {
		log.Errorf("Failed to delete Aurora cluster %s: %v", clusterID, err)
		return fmt.Errorf("Failed to delete Aurora cluster %s: %v", clusterID, err)
	}
	log.Infof("Aurora cluster deleted: %v", clusterID)

	// 删除参数组
	deleteParamGroupInput := &rds.DeleteDBClusterParameterGroupInput{
		DBClusterParameterGroupName: &paramGroupName,
	}

	_, err = rdsClient.DeleteDBClusterParameterGroup(ctx, deleteParamGroupInput)
	if err != nil {
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() != "DBParameterGroupNotFound" {
				log.Errorf("Failed to delete DBClusterParameterGroup, %v", err)
				return fmt.Errorf("Failed to delete DBClusterParameterGroup, %v", err)
			}
			log.Warnf("Aurora cluster parameter group %s already deleted, retcode: %s", paramGroupName, apiErr.ErrorCode())
		}
	}
	log.Infof("DBClusterParameterGroup deleted: %s", paramGroupName)
	return nil
}

func GetRDSLoginInfo(ctx context.Context, clusterID string, passwd string) (string, error) {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("Unable to load aws config, %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 获取Aurora集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := rdsClient.DescribeDBClusters(ctx, describeDBClustersInput)
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

func getAuroraClusterVPC(ctx context.Context, client *rds.Client, clusterID string) (string, error) {
	// 获取Aurora集群的详细信息
	describeDBClustersInput := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	dbClustersOutput, err := client.DescribeDBClusters(ctx, describeDBClustersInput)
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
	dbSubnetGroupsOutput, err := client.DescribeDBSubnetGroups(ctx, describeDBSubnetGroupsInput)
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

// getAuroraClusterFirstInstanceSubnet 获取Aurora集群中第一个实例的子网ID
func getAuroraClusterFirstInstanceSubnet(ctx context.Context, rdsClient *rds.Client, clusterID string) (string, error) {
	// 获取Aurora集群的详细信息
	clusterParams := &rds.DescribeDBClustersInput{
		DBClusterIdentifier: &clusterID,
	}
	clusterResp, err := rdsClient.DescribeDBClusters(ctx, clusterParams)
	if err != nil {
		return "", fmt.Errorf("failed to describe DBClusters: %v", err)
	}

	// 获取集群中的第一个数据库实例详细信息
	if len(clusterResp.DBClusters) == 0 {
		return "", fmt.Errorf("Aurora cluster %s not found", clusterID)
	}
	dbCluster := clusterResp.DBClusters[0]

	// 获取集群中的第一个数据库实例ID
	if len(dbCluster.DBClusterMembers) == 0 {
		return "", fmt.Errorf("No database instances found in cluster %s", clusterID)
	}
	firstInstanceID := *dbCluster.DBClusterMembers[0].DBInstanceIdentifier

	// 获取第一个数据库实例的详细信息
	instanceParams := &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: &firstInstanceID,
	}
	instanceResp, err := rdsClient.DescribeDBInstances(ctx, instanceParams)
	if err != nil {
		return "", fmt.Errorf("failed to describe DB instance %s: %v", firstInstanceID, err)
	}

	// 提取子网ID
	if len(instanceResp.DBInstances) == 0 {
		return "", fmt.Errorf("DB instance %s not found", firstInstanceID)
	}
	subnetID := *instanceResp.DBInstances[0].DBSubnetGroup.Subnets[0].SubnetIdentifier

	return subnetID, nil
}

func ModifyAuroraInstanceType(ctx context.Context, clusterID, instanceType string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS configuration: %v", err)
	}
	rdsClient := rds.NewFromConfig(cfg)

	// 获取集群中的实例列表
	describeOutput, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		Filters: []types.Filter{
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

// RestartDBInstance 重启指定的数据库实例
func RestartDBInstance(ctx context.Context, instanceID string) error {
	// 加载默认配置
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		return fmt.Errorf("Unable to load aws config, %v", err)
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

	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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
	err = CreateDBClusterParameterGroup(ctx, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		log.Fatalf("Failed to create Aurora cluster parameter group, %v", err)
	}
	log.Infof("DBClusterParameterGroup created: %s", paramGroupName)

	// 绑定 paramtergroup 并修改参数到restore的集群
	ModifyClusterParameters(ctx, clusterID, paramGroupName)

	return nil
}

// CheckClusterStatus 检查 Aurora 集群的状态
func CheckClusterStatus(ctx context.Context, clusterID string) (string, error) {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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

// RestoreAuroraClusterFromSnapshot 从database snapshot还原数据到新建的Aurora集群
func RestoreAuroraClusterFromSnapshot(ctx context.Context, clusterID, snapshotID, dbInstanceClass, paramGroupName string) error {
	masterUserpassword := os.Getenv("MASTER_PASSWORD")
	parameterGroupFamily := "aurora-mysql8.0"
	paramterDescription := "Custom parameter group for Aurora MySQL 8.0"

	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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
	err = CreateDBClusterParameterGroup(ctx, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		return fmt.Errorf("Failed to create Aurora cluster parameter group, %v", err)
	}
	log.Infof("DBClusterParameterGroup created: %s", paramGroupName)

	// 绑定 paramtergroup 并修改参数到restore的集群
	ModifyClusterParameters(ctx, clusterID, paramGroupName)

	// 重启实例
	err = RestartDBInstance(ctx, dbInstanceID)
	if err != nil {
		return fmt.Errorf("failed to restart database instance: %v", err)
	}

	return nil
}
