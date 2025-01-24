package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// 自定义凭证提供者
type DynamicProvider struct{}

// 全局共享的凭证变量
var (
	gCredsProvider   *aws.CredentialsCache
	gCredentialsData aws.Credentials
	mutex            = sync.RWMutex{} // 用于保护凭证的线程安全
)

// 初始化全局凭证的函数
func initializeCredentials() error {
	mutex.Lock()
	defer mutex.Unlock()

	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("missing AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY in environment variables")
	}

	// 设置默认过期时间为 1 小时后（如果需要，可以从配置文件加载具体的过期时间）
	expiration := time.Now().Add(1 * time.Hour)

	gCredentialsData = aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
		Expires:         expiration,
	}

	log.Infof("Initialized credentials: %v", gCredentialsData)
	return nil
}

func assumeRole(ctx context.Context, roleArn, sessionName string, duration int32) (*aws.Credentials, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("ap-northeast-1"))
	if err != nil {
		return nil, fmt.Errorf("unable to load aws config(~/.aws/config), %v", err)
	}
	stsClient := sts.NewFromConfig(cfg)

	// 调用AssumeRole获取临时凭证
	params := &sts.AssumeRoleInput{
		RoleArn:         &roleArn,
		RoleSessionName: &sessionName,
		DurationSeconds: &duration,
	}

	resp, err := stsClient.AssumeRole(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	// 提取临时凭证
	tempCreds := aws.Credentials{
		AccessKeyID:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
		Expires:         *resp.Credentials.Expiration,
	}

	setAWSEnvironmentVariables(tempCreds)

	// 输出临时凭证
	log.Debugf("Access Key ID: %s", *resp.Credentials.AccessKeyId)
	log.Debugf("Secret Access Key: %s", *resp.Credentials.SecretAccessKey)
	log.Debugf("Session Token: %s", *resp.Credentials.SessionToken)
	log.Debugf("Expiration: %s", *resp.Credentials.Expiration)

	return &tempCreds, nil
}

// WriteCredentialsToFile 将临时凭证写入 ~/.aws/credentials 文件
func WriteCredentialsToFile(creds *aws.Credentials) error {
	// 获取当前用户主目录
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %v", err)
	}

	// 构造 ~/.aws/credentials 文件路径
	credentialsPath := filepath.Join(usr.HomeDir, ".aws", "credentials")

	// 读取现有内容
	_, err = os.ReadFile(credentialsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read credentials file: %v", err)
	}

	// 构造新的凭证内容
	newTempCreds := fmt.Sprintf(`
[default]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s
`, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)

	// 将新凭证写入文件
	err = os.WriteFile(credentialsPath, []byte(newTempCreds), 0600)
	if err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}

// 定期刷新 AWS 临时凭据，并在 context 关闭信号到达时优雅退出
func startAssumeRoleProcess(ctx context.Context, wg *sync.WaitGroup, roleARN, roleSession string, duration int32) {
	defer func() {
		GreenInfof("Assume-role process for role %s has exited gracefully.", roleARN)
		wg.Done() // 确保协程退出时调用 wg.Done()
	}()

	GreenInfof("Assume-role process started for role: %s", roleARN)

	refreshCredentials := func() {
		// 尝试获取新凭据，最多重试 3 次
		for attempt := 0; attempt < 3; attempt++ {
			creds, err := assumeRole(ctx, roleARN, roleSession, duration)
			if err == nil {
				// 尝试将凭据写入文件
				if err := WriteCredentialsToFile(creds); err == nil {
					GreenInfof("Credentials renewed successfully. New expiration: %s", creds.Expires)
					return
				} else {
					log.Errorf("Failed to write credentials to file (attempt %d/3): %v", attempt+1, err)
				}
			} else {
				log.Errorf("Failed to renew credentials (attempt %d/3): %v", attempt+1, err)
			}
			time.Sleep(5 * time.Second)
		}
		log.Errorf("Failed to refresh credentials after 3 attempts.")
	}

	// 首次刷新凭据
	GreenInfof("Attempting to refresh credentials at startup.")
	refreshCredentials()

	// 每 10 分钟刷新一次凭据
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Infof("Attempting to refresh credentials.")
			refreshCredentials()

		case <-ctx.Done():
			log.Infof("Assume-role process stopped due to context cancellation, received signal: ctx.Done")
			return
		}
	}
}

// 从环境变量格式文件读取 AWS 凭证
func loadAWSCredentialsFromEnvFile(filePath string) (aws.Credentials, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	creds := aws.Credentials{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // 跳过空行和注释
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "AWS_ACCESS_KEY_ID":
			creds.AccessKeyID = value
		case "AWS_SECRET_ACCESS_KEY":
			creds.SecretAccessKey = value
		case "AWS_SESSION_TOKEN":
			creds.SessionToken = value
		}
	}

	if err := scanner.Err(); err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to read file: %w", err)
	}

	return creds, nil
}

func setAWSEnvironmentVariables(creds aws.Credentials) {
	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	if creds.SessionToken != "" {
		os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	}
}

func generateExportCommands(creds aws.Credentials) {
	fmt.Printf("Run the following to export AWS credentials globally:\n")
	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", creds.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey)
	if creds.SessionToken != "" {
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", creds.SessionToken)
	}
}

// 获取和更新凭证的子函数
func refreshCredential(ctx context.Context, stsClient *sts.Client, roleARN, sessionName string) (*aws.Credentials, error) {
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		o.Duration = time.Hour // 设置凭证有效期为 1 小时
	})

	// 获取新的临时凭证
	creds, err := assumeRoleProvider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %v", err)
	}

	// 更新全局凭证提供程序
	mutex.Lock()
	gCredsProvider = aws.NewCredentialsCache(assumeRoleProvider)
	err = WriteCredentialsToFile(&creds)
	mutex.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to write credentials to ~/.aws/credentials: %v", err)
	}

	return &creds, nil
}

// refreshCredentials 定期刷新临时凭证并更新全局缓存
func refreshCredentials(ctx context.Context, wg *sync.WaitGroup, roleARN, sessionName string, interval time.Duration, initDone chan<- bool) {
	defer func() {
		GreenInfof("RefreshCredentials for role %s has exited gracefully.", roleARN)
		wg.Done() // 确保协程退出时调用 wg.Done()
	}()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("unable to load aws SDK config: %v", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	// 初始化凭证并更新全局提供程序
	creds, err := refreshCredential(ctx, stsClient, roleARN, sessionName)
	if err != nil {
		log.Fatalf("failed to initialize credentials: %v", err)
	}

	// 通知主程序第一次凭证已获取
	if initDone != nil {
		initDone <- true
	}
	GreenInfof("Initial credentials fetched successfully. Expiration: %s", creds.Expires)

	// 定时刷新凭证
	for {
		select {
		case <-ctx.Done():
			log.Infof("Context canceled, stopping refreshCredentials loop")
			return
		case <-time.After(interval):
			// 刷新凭证
			_, err := refreshCredential(ctx, stsClient, roleARN, sessionName)
			if err != nil {
				log.Warnf("failed to refresh credentials: %v", err)
			} else {
				GreenInfof("Credentials renewed successfully. New expiration: %s", creds.Expires)
			}
		}
	}
}

// 返回使用动态凭证的 AWS 配置
func getAWSConfigWithDynamicCredentials(ctx context.Context) (aws.Config, error) {
	mutex.Lock()
	credsProvider := gCredsProvider
	mutex.Unlock()

	if credsProvider == nil {
		return aws.Config{}, fmt.Errorf("credentials provider is not initialized")
	}

	// 返回 AWS 配置，绑定动态凭证提供程序
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithCredentialsProvider(credsProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %v", err)
	}

	return cfg, nil
}

// attachPolicyToRole 将指定的IAM策略附加到指定的IAM角色。
func attachPolicyToRole(ctx context.Context, roleName, policyArn string) error {
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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
	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
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
