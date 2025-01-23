package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/aws"
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

type CustomFormatter struct {
	log.TextFormatter
}

func (f *CustomFormatter) Format(entry *log.Entry) ([]byte, error) {
	var levelColor string
	switch entry.Level {
	case log.InfoLevel:
		levelColor = "\033[0m" // 默认
		//levelColor = "\033[1;34m" // 蓝色
	case log.WarnLevel:
		levelColor = "\033[1;33m" // 黄色
	case log.ErrorLevel:
		levelColor = "\033[0;31m" // 普通红色
	case log.FatalLevel:
		levelColor = "\033[1;31m" // 加粗红色
	case log.DebugLevel:
		levelColor = "\033[1;36m" // 青色
	default:
		levelColor = "\033[0m" // 默认
	}

	// 特殊字段着色逻辑
	for key, value := range entry.Data {
		if key == "successField" {
			greenColor := "\033[1;32m"
			resetColor := "\033[0m"
			entry.Data[key] = fmt.Sprintf("%s%s%s", greenColor, value, resetColor)
		}
		if key == "failField" {
			redColor := "\033[0;31m"
			resetColor := "\033[0m"
			entry.Data[key] = fmt.Sprintf("%s%s%s", redColor, value, resetColor)
		}
		if key == "processingFiled" {
			blueColor := "\033[1;34m"
			resetColor := "\033[0m"
			entry.Data[key] = fmt.Sprintf("%s%s%s", blueColor, value, resetColor)
		}
	}

	entry.Message = fmt.Sprintf("%s%s\033[0m", levelColor, entry.Message)
	return f.TextFormatter.Format(entry)
}

func GreenInfof(format string, args ...interface{}) {
	// 使用 Infof 打印并加上绿色的转义字符
	log.Infof("\033[1;32m"+format+"\033[0m", args...)
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
		roleARN            string
		restore            bool
		//tokenExpiration    int32
		roleSession string
	)

	pflag.StringVarP(&action, "action", "a", "", "Action to perform: 'create-rds', 'delete-rds', 'modify-params', 'create-client', 'delete-client','init-perftest-env','prepare-data','perftest-run','modify-dbinstance-type'")
	pflag.StringVarP(&clusterID, "cluster-id", "c", "", "Aurora cluster identifier")
	pflag.StringVarP(&instanceID, "instance-id", "i", "", "Aurora instance identifier")
	pflag.StringVarP(&paramGroupName, "param-group-name", "p", "my-custom-aurora-mysql80", "Parameter group name(default: my-custom-aurora-mysql80)")
	pflag.StringVarP(&dbInstanceClass, "instance-class", "d", "db.r6g.4xlarge", "Aurora instance class (default: db.r6g.4xlarge)")
	pflag.StringVarP(&ec2InstanceType, "ec2-instance-type", "t", "m5.2xlarge", "EC2 instance type (default: m5.2xlarge)")
	pflag.StringVarP(&ec2ImageID, "ec2-image-id", "m", "ami-0afb6e8e0625142bc", "EC2 image ID, default os image is centos7 (default: ami-0afb6e8e0625142bc)") // amazone linux 2023 ami-id:ami-046d7944dd9e73a61 for default
	pflag.StringVarP(&ec2InstanceID, "ec2-instance-id", "e", "", "EC2 instance ID")                                                                           // like  i-0596d9ed0e24f825d
	pflag.StringVarP(&ec2SecurityGroupID, "ec2-security-group-id", "g", "", "EC2 security group ID")
	pflag.StringVarP(&ec2KeyName, "ec2-key-name", "k", "pub-st-rsa", "EC2 key pair name(default: pub-st-rsa)")
	pflag.BoolVarP(&restore, "restore", "s", false, "Restore data from S3 instead of preparing data with Sysbench, create a new cluster and restore data from mysql-snapshot")
	pflag.StringVarP(&perfType, "perf-type", "o", "", "Sysbench oltp perf type:oltp_read_only/oltp_read_write/oltp_write_only")
	pflag.StringVarP(&roleARN, "role-arn", "r", "arn:aws:iam::986330900858:role/full-manager-service-role", "aws login account roleARN (default: arn:aws:iam::986330900858:role/full-manager-service-role)")
	pflag.StringVarP(&roleSession, "role-session", "n", "full-manager-service-role", "aws login account role session name (default: full-manager-service-role)")
	pflag.Parse()

	// set log-level and format
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&CustomFormatter{
		TextFormatter: log.TextFormatter{
			FullTimestamp: true,
			ForceColors:   true,
		},
	})

	// 验证参数组名称是否符合要求
	if !isValidParamGroupName(paramGroupName) {
		log.Infof("dbGroupname is %s", paramGroupName)
		log.Fatalf("Invalid DBClusterParameterGroupName: %s. Name must start with a letter, contain only ASCII letters, digits, and hyphens, and must not end with a hyphen or contain two consecutive hyphens or a period.", paramGroupName)
	}

	// 从环境变量中获取敏感信息
	masterPassword := os.Getenv("MASTER_PASSWORD")
	if masterPassword == "" {
		log.Fatalf("MASTER_PASSWORD environment variable is not set")
	}

	// 加载AWS配置并获取ak/sk/token，然后起 assume-role 协程一直刷新token，保证程序不会中断，程序运行前需要配置 ak/sk/token到 ~/.aws/creditial
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Unable to load aws config, %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	defer cancel()
	wg.Add(1)

	go func() {
		startAssumeRoleProcess(ctx, &wg, roleARN, roleSession, 3600)
	}()

	// 创建RDS/ec2/ssm客户端
	rdsClient := rds.NewFromConfig(cfg)
	ec2Client := ec2.NewFromConfig(cfg)
	ssmClient := ssm.NewFromConfig(cfg)

	switch action {
	case "create-rds":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Errorf("For 'create-rds' action, --cluster-id, --instance-id, and --param-group-name are required")
		} else {
			err := createResources(ctx, rdsClient, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass)
			if err != nil {
				log.Errorf("Failed to create Aurora cluster: %v", err)
			}
		}
	case "delete-rds":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Errorf("For 'delete-rds' action, --cluster-id, --instance-id, and --param-group-name are required")
		} else {
			err = deleteResources(ctx, rdsClient, clusterID, instanceID, paramGroupName)
			if err != nil {
				log.Errorf("Failed to delete Aurora cluster and instance: %v", err)
			}
		}
	case "modify-params":
		if clusterID == "" || paramGroupName == "" {
			log.Errorf("For 'modify-params' action, --cluster-id and --param-group-name are required")
		} else {
			err = modifyClusterParameters(ctx, rdsClient, clusterID, paramGroupName)
			if err != nil {
				log.Errorf("Failed to modify Aurora cluster parameters %v", err)
			}
		}
	case "get-rds-endpoint":
		if clusterID == "" {
			log.Errorf("For 'get-rds-endpoint' action, --cluster-id and -is required")
		} else {
			loginInfo, err := getRDSLoginInfo(ctx, rdsClient, clusterID, masterPassword)
			if err != nil {
				log.Errorf("Failed to get RDS login information")

			} else {
				log.Infof("RDS login command: %s", loginInfo)
			}
		}
	case "create-client":
		if clusterID == "" || ec2ImageID == "" || ec2InstanceType == "" || ec2KeyName == "" {
			log.Errorf("For 'create-client' action, --cluster-id is required")
		} else {
			instanceID, publicDNS, err := createClientEC2(ctx, rdsClient, ec2Client, clusterID, ec2InstanceType, ec2ImageID, ec2KeyName)
			if err != nil {
				log.Errorf("Failed to create client EC2 instance: %v", err)

			} else {
				log.Infof("Client EC2 instance created with ID: %s", instanceID)
				log.Infof("Public DNS: %s", publicDNS)
				log.Infof("Login command: ssh -i %s.pem ec2-user@%s", ec2KeyName, publicDNS)
			}
		}
	case "delete-client":
		if ec2InstanceID == "" {
			log.Errorf("For 'create-client' action, --ec2-instance-id is required")
		} else {
			err := deleteClientEC2(ctx, ec2Client, ec2InstanceID)
			if err != nil {
				log.Errorf("Failed to delete client EC2 instance %s: %v", ec2ImageID, err)
			}
		}
	case "init-perftest-env":
		if ec2InstanceID == "" {
			log.Errorf("For 'init-perftest-env' action, --ec2-instance-id is required")
		} else {
			err := initPerfTestEnv(ctx, ec2Client, ec2InstanceID, ec2KeyName)
			if err != nil {
				log.Errorf("Failed to initialize performance test environment: %v", err)
			} else {
				fmt.Println("Performance test environment initialized successfully")
			}
		}
	case "prepare-data":
		if restore {
			if clusterID == "" {
				log.Errorf("For 'prepare-data --restore' action,  --cluster-id is required")
			} else {
				//err := RestoreAuroraClusterFromS3("qa-drill-bkt", "mysql-snapshot-sysbench-3000w", clusterID, "arn:aws:iam::986330900858:role/asystest", paramGroupName)
				err := RestoreAuroraClusterFromSnapshot(ctx, clusterID, "arn:aws:rds:us-west-2:986330900858:snapshot:snapshot-msyql-sysbench-1e1t", dbInstanceClass, paramGroupName)
				if err != nil {
					log.Errorf("Prapare data from snapshot failed: %v", err)
				}
			}
		} else {
			if ec2InstanceID == "" || clusterID == "" {
				log.Errorf("For 'prepare-data' action, --ec2-instance-id and --cluster-id are required")
				return
			}
			err := prepareSysbenchData(ctx, rdsClient, ec2InstanceID, clusterID, ec2KeyName)
			if err != nil {
				log.Errorf("Prepare data from sysbench preapare Error: %v", err)
			}
		}

	case "perftest-run":
		if ec2InstanceID == "" || clusterID == "" || perfType == "" {
			log.Errorf("For 'perftest-run' action, --ec2-instance-id,--cluster-id and --perf-type are required")
		} else {
			err := RunSysbenchPerftest(ctx, rdsClient, ssmClient, ec2InstanceID, clusterID, ec2KeyName, perfType)
			if err != nil {
				log.Errorf("Run sysbench perftest Error: %v", err)
			}
		}
	case "modify-dbinstance-type":
		if clusterID == "" || dbInstanceClass == "" {
			log.Errorf("For 'modify-dbinstance-type action', --cluster-id and --ec2InstanceType are required")
		} else {
			err := ModifyAuroraInstanceType(ctx, clusterID, dbInstanceClass)
			if err != nil {
				log.Errorf("Change Aurora cluster %s db-instance to %s failed: %v", clusterID, ec2InstanceType, err)
			}
		}
	case "assume-role":
		// 每隔20分钟调用AssumeRole获取新的临时凭证
		ticker := time.NewTicker(20 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// 获取新的临时凭证,将新的临时凭证1h写入 ~/.aws/credentials 文件
				creds, err := assumeRole(roleARN, roleSession, 3600)
				if err != nil {
					log.Printf("Error renewing credentials: %v", err)
					continue
				}
				err = WriteCredentialsToFile(creds)
				if err != nil {
					log.Printf("Error writing credentials to file: %v", err)
					continue
				}
				log.Printf("Credentials renewed. New expiration: %s", creds.Expiration)
			}
		}
	default:
		log.Errorf("Invalid action: %s. Use 'create-rds', 'delete-rds', 'modify-params', 'create-client','init-perftest-env','prepare-data','perftest-run','modify-dbinstance-type','assume-role'", action)
	}
	cancelAndWait(cancel, &wg)
}

func createResources(ctx context.Context, client *rds.Client, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass string) error {
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

	createClusterOutput, err := client.CreateDBCluster(ctx, createClusterInput)
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

	createInstanceOutput, err := client.CreateDBInstance(ctx, createInstanceInput)
	if err != nil {
		return fmt.Errorf("Failed to exec Aurora instance create command, %v", err)
	}

	// 轮询实例状态，直到状态为 available 表示创建完成，超时时间10分钟
	err = PollResourceStatus(ctx, instanceID, ResourceTypeAuroraInstance, "available", 10*time.Minute, CheckDBInstanceStatus)
	if err != nil {
		return fmt.Errorf("Failed to create Aurora instance %s: %v", instanceID, err)
	}

	log.Infof("Aurora instance created: %v", createInstanceOutput)

	err = CreateDBClusterParameterGroup(ctx, client, paramGroupName, paramterDescription, parameterGroupFamily)
	if err != nil {
		return fmt.Errorf("Failed to create Aurora cluster parameter group, %v", err)
	}
	log.Infof("DBClusterParameterGroup created: %s", paramGroupName)
	return nil
}

func CreateDBInstanceForCluster(ctx context.Context, clusterID, instanceID, instanceClass string) error {
	// 加载默认配置
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Unable to load aws config(~/.aws/config), %v", err)
	}
	rdsSvc := rds.NewFromConfig(cfg)

	// 构建创建实例请求参数
	params := &rds.CreateDBInstanceInput{
		DBInstanceIdentifier: aws.String(instanceID),
		DBClusterIdentifier:  aws.String(clusterID),
		DBInstanceClass:      aws.String(instanceClass),
		Engine:               aws.String("aurora-mysql"),
	}

	// 发送创建实例请求
	resp, err := rdsSvc.CreateDBInstance(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to create DB instance %s for cluster %s: %v", instanceID, clusterID, err)
	}

	log.Infof("Successfully created DB instance %s for cluster %s: %v", instanceID, clusterID, resp)
	return nil
}

// CreateDBClusterParameterGroup 创建 DBCluster 参数组
func CreateDBClusterParameterGroup(ctx context.Context, client *rds.Client, paramGroupName, paramterDescription, parameterGroupFamily string) error {
	createParamGroupInput := &rds.CreateDBClusterParameterGroupInput{
		DBClusterParameterGroupName: aws.String(paramGroupName),
		Description:                 aws.String(paramterDescription),
		DBParameterGroupFamily:      aws.String(parameterGroupFamily),
	}
	_, err := client.CreateDBClusterParameterGroup(ctx, createParamGroupInput)
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

func modifyClusterParameters(ctx context.Context, client *rds.Client, clusterID, paramGroupName string) error {
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

	_, err := client.ModifyDBClusterParameterGroup(ctx, modifyDBClusterParameterGroupInput)
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

	_, err = client.ModifyDBCluster(ctx, modifyDBClusterInput)
	if err != nil {
		log.Errorf("Failed to modify DBCluster, %v", err)
		return err
	}
	log.Infof("DBCluster modified to use new parameter group: %s", paramGroupName)
	return nil
}

func deleteResources(ctx context.Context, client *rds.Client, clusterID, instanceID, paramGroupName string) error {
	var skipFinalSnapshot bool = true
	var apiErr smithy.APIError
	//var aerr awserr.Error

	// 删除Aurora数据库实例
	deleteInstanceInput := &rds.DeleteDBInstanceInput{
		DBInstanceIdentifier: &instanceID,
		SkipFinalSnapshot:    &skipFinalSnapshot,
	}

	_, err := client.DeleteDBInstance(ctx, deleteInstanceInput)
	if err != nil {
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() != "DBInstanceNotFound" {
				log.Fatalf("Failed to delete Aurora instance, %v", err)
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
		SkipFinalSnapshot:   &skipFinalSnapshot,
	}

	_, err = client.DeleteDBCluster(ctx, deleteClusterInput)
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

	_, err = client.DeleteDBClusterParameterGroup(ctx, deleteParamGroupInput)
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

func createClientEC2(ctx context.Context, rdsClient *rds.Client, ec2Client *ec2.Client, clusterID, instanceType, imageID, keyName string) (string, string, error) {
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

	// 创建EC2实例
	runInstancesInput := &ec2.RunInstancesInput{
		ImageId:      aws.String(imageID),
		InstanceType: ec2type.InstanceType(instanceType),
		KeyName:      aws.String(keyName),
		MinCount:     aws.Int32(1),
		MaxCount:     aws.Int32(1),
		SubnetId:     aws.String(subnetID),
		SecurityGroupIds: []string{
			securityGroupID,
		},
		TagSpecifications: []ec2type.TagSpecification{
			{
				ResourceType: "instance",
				Tags: []ec2type.Tag{
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
	err = PollResourceStatus(ctx, ec2InstanceID, ResourceTypeEC2Instance, "running", 10*time.Minute, CheckEC2InstanceStatus)
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

func createSecurityGroup(ctx context.Context, ec2Client *ec2.Client, vpcID, groupName string) (string, error) {
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
	subnetsOutput, err := client.DescribeSubnets(ctx, describeSubnetsInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe subnets: %v", err)
	}
	if len(subnetsOutput.Subnets) == 0 {
		return "", fmt.Errorf("no default subnet found in VPC %s", vpcID)
	}
	return *subnetsOutput.Subnets[0].SubnetId, nil
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

// CheckEC2InstanceStatus 检查 EC2 实例的状态
func CheckEC2InstanceStatus(ctx context.Context, ec2InstanceID string) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
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

func deleteClientEC2(ctx context.Context, ec2Client *ec2.Client, ec2InstanceID string) error {
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
	err = PollResourceStatus(ctx, ec2InstanceID, ResourceTypeEC2Instance, "terminated", 10*time.Minute, CheckEC2InstanceStatus)
	if err != nil {
		return fmt.Errorf("EC2 instance %s deleted failed", ec2InstanceID)
	}
	log.Infof("EC2 instance is terminated: %s", ec2InstanceID)

	return nil
}

func getRDSLoginInfo(ctx context.Context, rdsClient *rds.Client, clusterID string, passwd string) (string, error) {
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
