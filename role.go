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

// 全局共享的凭证变量
var (
	gCredsProvider   *aws.CredentialsCache
	gCredentialsData aws.Credentials
	mutex            = sync.RWMutex{} // 用于保护凭证的线程安全
)

// 初始化全局凭证的函数
func initializeCredentials(ctx context.Context, roleARN, sessionName string) error {
	mutex.Lock()
	defer mutex.Unlock()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %v", err)
	}
	stsClient := sts.NewFromConfig(cfg)

	identity, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Failed to get caller identity: %v", err)
	}
	GreenInfof("Account: %s, Role-ARN: %s", *identity.Account, *identity.Arn)

	// 使用 default config 配置的临时provider
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		o.Duration = time.Hour
	})
	gCredsProvider = aws.NewCredentialsCache(assumeRoleProvider, func(options *aws.CredentialsCacheOptions) {
		options.ExpiryWindow = 20 * time.Minute // 20分钟就要过期了，就会标记为刷新窗口期
		options.ExpiryWindowJitterFrac = 0.2    // 防止多线程竞争，设置一个窗口，波动在 20 *0.5 = 10分钟内，提前10-20分就开始刷新
	})

	return nil
}

// 获取和更新凭证的子函数，第二个返回值确定是否有更新，y代表更新了 creditals
func refreshCredential(ctx context.Context, roleARN, sessionName string) (*aws.Credentials, bool, error) {
	mutex.Lock()
	//defer mutex.Unlock()
	if gCredsProvider == nil {
		return nil, false, fmt.Errorf("global credentials provider is not initialized")
	}

	cfg, err := getAWSConfigWithDynamicCredentials(ctx)
	if err != nil {
		log.Errorf("failed to load config from dynamic creditals provider: %v", err)
	}
	dynamicStsClient := sts.NewFromConfig(cfg)
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(dynamicStsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		o.Duration = time.Hour // 设置最长有效期
	})

	// 更新全局凭证提供者
	gCredsProvider = aws.NewCredentialsCache(assumeRoleProvider, func(options *aws.CredentialsCacheOptions) {
		options.ExpiryWindow = 20 * time.Minute // 提前 5 分钟刷新
		options.ExpiryWindowJitterFrac = 0.2    // 加入 10% 的随机抖动
	})

	lastExpiredTime := gCredentialsData.Expires
	// 判断是否过期，用来获取新的临时凭证
	creds, err := gCredsProvider.Retrieve(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to assume role: %v", err)
	}
	newExpiredTime := gCredentialsData.Expires
	// 更新全局凭证提供程序
	gCredentialsData = creds
	log.Debugf("For debug, current creditials: %v", gCredentialsData)
	//setAWSEnvironmentVariables(creds)
	err = WriteCredentialsToFile(&creds)
	mutex.Unlock()
	if err != nil {
		return nil, false, fmt.Errorf("failed to write credentials to ~/.aws/credentials: %v", err)
	}
	if AreTimesEqual(lastExpiredTime, newExpiredTime) {
		return &creds, false, nil
	}
	return &creds, true, nil
}

// refreshCredentials 定期刷新临时凭证并更新全局缓存
func RefreshCredentials(ctx context.Context, wg *sync.WaitGroup, roleARN, sessionName string, interval time.Duration, initDone chan<- bool) {
	defer func() {
		GreenInfof("Refresh credentials process has exited gracefully.")
		wg.Done() // 确保协程退出时调用 wg.Done()
	}()

	// 先刷新一次凭证防止第一次等待的10分钟内超时
	creds, _, err := refreshCredential(ctx, roleARN, sessionName)
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
			creds, _, err := refreshCredential(ctx, roleARN, sessionName)
			if err != nil {
				log.Warnf("failed to refresh credentials: %v", err)
			} else {
				GreenInfof("Credentials refreshed successfully. New expiration: %s", creds.Expires)
				//log.Infof("Credentials retrieved, no need to refresh. Current expiration: %s", creds.Expires)
			}
		}
	}
}

// 返回使用动态凭证的 AWS 配置
func getAWSConfigWithDynamicCredentials(ctx context.Context) (aws.Config, error) {

	if gCredsProvider == nil {
		return aws.Config{}, fmt.Errorf("credentials provider is not initialized")
	}

	// 返回 AWS 配置，绑定动态凭证提供程序
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		config.WithCredentialsProvider(gCredsProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %v", err)
	}

	return cfg, nil
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
