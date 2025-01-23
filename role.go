package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type TempCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func assumeRole(roleArn, sessionName string, duration int32) (*TempCredentials, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("ap-northeast-1"))
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

	resp, err := stsClient.AssumeRole(context.TODO(), params)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	// 提取临时凭证
	tempCreds := TempCredentials{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
		Expiration:      *resp.Credentials.Expiration,
	}

	os.Setenv("AWS_ACCESS_KEY_ID", tempCreds.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", tempCreds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", tempCreds.SessionToken)

	// 输出临时凭证
	log.Debugf("Access Key ID: %s", *resp.Credentials.AccessKeyId)
	log.Debugf("Secret Access Key: %s", *resp.Credentials.SecretAccessKey)
	log.Debugf("Session Token: %s", *resp.Credentials.SessionToken)
	log.Debugf("Expiration: %s", *resp.Credentials.Expiration)

	return &tempCreds, nil
}

// WriteCredentialsToFile 将临时凭证写入 ~/.aws/credentials 文件
func WriteCredentialsToFile(creds *TempCredentials) error {
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
`, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken)

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
		GreenInfof("Assume-role process for role %s has exited Gracefully.", roleARN)
		wg.Done() // 确保协程退出时调用 wg.Done()
	}()

	// 每 10 分钟刷新一次凭据
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	GreenInfof("Assume-role process started for role: %s", roleARN)

	for {
		select {
		case <-ticker.C:
			// 尝试获取新凭据
			creds, err := assumeRole(roleARN, roleSession, duration)
			if err != nil {
				log.Errorf("Failed to renew credentials: %v", err)
				continue
			}

			// 尝试将凭据写入文件
			if err := WriteCredentialsToFile(creds); err != nil {
				log.Errorf("Failed to write credentials to file: %v", err)
				continue
			}

			GreenInfof("Credentials renewed successfully. New expiration: %s", creds.Expiration)
		case <-ctx.Done():
			log.Infof("Assume-role process stopped due to context cancellation, received signal: ctx.Done")
			return
		}
	}
}
