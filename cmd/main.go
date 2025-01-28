package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"aurora-vs-TiDB/perftest"
	"aurora-vs-TiDB/pkg/credentials"
	"aurora-vs-TiDB/pkg/resource"
	"aurora-vs-TiDB/pkg/util"

	"aurora-vs-TiDB/pkg/splog"

	log "github.com/sirupsen/logrus"

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
		roleARN            string
		rstPath            string
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
	pflag.StringVarP(&rstPath, "results-path", "l", "results", "pertests results path (default: results)")

	pflag.Parse()

	// set log-level and format
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&splog.CustomFormatter{
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
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	err := credentials.InitializeCredentials(ctx, roleARN, roleSession)
	if err != nil {
		log.Fatalf("AWS ak/sk/token not config, exit")
	}

	// 协程一直刷新token，保证程序不会中断，20分钟刷新一次，每次+1h
	defer cancel()
	wg.Add(1)
	initDone := make(chan bool)

	go func() {
		credentials.RefreshCredentials(ctx, &wg, roleARN, roleSession, 5*time.Minute, initDone)
	}()
	<-initDone

	switch action {
	case "create-rds":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Errorf("For 'create-rds' action, --cluster-id, --instance-id, and --param-group-name are required")
		} else {
			err := resource.CreateAuroraResources(ctx, clusterID, instanceID, paramGroupName, masterPassword, dbInstanceClass)
			if err != nil {
				log.Errorf("Failed to create Aurora cluster: %v", err)
			}
		}
	case "delete-rds":
		if clusterID == "" || instanceID == "" || paramGroupName == "" {
			log.Errorf("For 'delete-rds' action, --cluster-id, --instance-id, and --param-group-name are required")
		} else {
			err = resource.DeleteAuroraResources(ctx, clusterID, instanceID, paramGroupName)
			if err != nil {
				log.Errorf("Failed to delete Aurora cluster and instance: %v", err)
			}
		}
	case "modify-params":
		if clusterID == "" || paramGroupName == "" {
			log.Errorf("For 'modify-params' action, --cluster-id and --param-group-name are required")
		} else {
			err = resource.ModifyClusterParameters(ctx, clusterID, paramGroupName)
			if err != nil {
				log.Errorf("Failed to modify Aurora cluster parameters %v", err)
			}
		}
	case "get-rds-endpoint":
		if clusterID == "" {
			log.Errorf("For 'get-rds-endpoint' action, --cluster-id and -is required")
		} else {
			loginInfo, err := resource.GetRDSLoginInfo(ctx, clusterID, masterPassword)
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
			instanceID, publicDNS, err := resource.CreateClientEC2(ctx, clusterID, ec2InstanceType, ec2ImageID, ec2KeyName)
			if err != nil {
				log.Errorf("Failed to create client EC2 instance: %v", err)

			} else {
				splog.GreenInfof("Client EC2 instance created with ID: %s", instanceID)
				log.Infof("Public DNS: %s", publicDNS)
				log.Infof("Login command: ssh -i %s.pem ec2-user@%s", ec2KeyName, publicDNS)
			}
		}
	case "delete-client":
		if ec2InstanceID == "" {
			log.Errorf("For 'create-client' action, --ec2-instance-id is required")
		} else {
			err := resource.DeleteClientEC2(ctx, ec2InstanceID)
			if err != nil {
				log.Errorf("Failed to delete client EC2 instance %s: %v", ec2ImageID, err)
			}
		}
	case "init-perftest-env":
		if ec2InstanceID == "" {
			log.Errorf("For 'init-perftest-env' action, --ec2-instance-id is required")
		} else {
			err := perftest.InitPerfTestEnv(ctx, ec2InstanceID, ec2KeyName)
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
				err := resource.RestoreAuroraClusterFromSnapshot(ctx, clusterID, "arn:aws:rds:us-west-2:986330900858:snapshot:snapshot-msyql-sysbench-1e1t", dbInstanceClass, paramGroupName)
				if err != nil {
					log.Errorf("Prapare data from snapshot failed: %v", err)
				}
			}
		} else {
			if ec2InstanceID == "" || clusterID == "" {
				log.Errorf("For 'prepare-data' action, --ec2-instance-id and --cluster-id are required")
				return
			}
			err := perftest.PrepareSysbenchData(ctx, ec2InstanceID, clusterID, ec2KeyName)
			if err != nil {
				log.Errorf("Prepare data from sysbench preapare Error: %v", err)
			}
		}

	case "perftest-run":
		if ec2InstanceID == "" || clusterID == "" || perfType == "" {
			log.Errorf("For 'perftest-run' action, --ec2-instance-id,--cluster-id and --perf-type are required")
		} else {
			err := perftest.RunSysbenchPerftest(ctx, ec2InstanceID, clusterID, ec2KeyName, perfType)
			if err != nil {
				log.Errorf("Run sysbench perftest Error: %v", err)
			}
		}
	case "modify-dbinstance-type":
		if clusterID == "" || dbInstanceClass == "" {
			log.Errorf("For 'modify-dbinstance-type action', --cluster-id and --ec2InstanceType are required")
		} else {
			err := resource.ModifyAuroraInstanceType(ctx, clusterID, dbInstanceClass)
			if err != nil {
				log.Errorf("Change Aurora cluster %s db-instance to %s failed: %v", clusterID, ec2InstanceType, err)
			}
		}
	case "assume-role":
		// 每隔20分钟调用AssumeRole获取新的临时凭证
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				log.Printf("Get lastest credentials. New expiration: %s", credentials.GlCredentialsData.Expires)
			}
		}
	case "parse-results":
		err := perftest.ParseAndPrintAllResults(rstPath)
		if err != nil {
			log.Errorf("failed to parser and print aurora performance test result, %v", err)
		}
	default:
		log.Errorf("Invalid action: %s. Use 'create-rds', 'delete-rds', 'modify-params', 'create-client','init-perftest-env','prepare-data','perftest-run','modify-dbinstance-type','assume-role'", action)
	}
	util.CancelAndWait(cancel, &wg)
}
