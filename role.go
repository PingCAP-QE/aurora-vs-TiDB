package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func assumeRole(roleArn, sessionName string, duration int32) (*Credentials, error) {
	// 加载默认配置
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
		return nil, fmt.Errorf("failed to assume role: %v", err)
	}

	// 提取临时凭证
	creds := Credentials{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
		Expiration:      *resp.Credentials.Expiration,
	}
	// 输出临时凭证
	fmt.Printf("Access Key ID: %s\n", *resp.Credentials.AccessKeyId)
	fmt.Printf("Secret Access Key: %s\n", *resp.Credentials.SecretAccessKey)
	fmt.Printf("Session Token: %s\n", *resp.Credentials.SessionToken)
	fmt.Printf("Expiration: %s\n", *resp.Credentials.Expiration)

	return &creds, nil
}

// WriteCredentialsToFile 将临时凭证写入 ~/.aws/credentials 文件
func WriteCredentialsToFile(creds *Credentials) error {
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
	newCreds := fmt.Sprintf(`
[default]
aws_access_key_id = %s
aws_secret_access_key = %s
aws_session_token = %s
`, creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken)

	// 将新凭证写入文件
	err = os.WriteFile(credentialsPath, []byte(newCreds), 0600)
	if err != nil {
		return fmt.Errorf("failed to write credentials file: %v", err)
	}

	return nil
}
