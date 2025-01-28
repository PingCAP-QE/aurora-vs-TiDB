#!/bin/bash

# AWS AssumeRole配置
ROLE_ARN="arn:aws:iam::986330900858:role/full-manager-service-role"
SESSION_NAME="default"
DURATION=3600 # 凭证有效期（秒）

# 调用AWS CLI的AssumeRole命令获取临时凭证
CREDENTIALS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name $SESSION_NAME --duration-seconds $DURATION --query 'Credentials' --output json)

# 提取AccessKeyId、SecretAccessKey和SessionToken
ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r '.AccessKeyId')
SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r '.SecretAccessKey')
SESSION_TOKEN=$(echo $CREDENTIALS | jq -r '.SessionToken')

# 设置环境变量
export AWS_ACCESS_KEY_ID=$ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY
export AWS_SESSION_TOKEN=$SESSION_TOKEN

# 输出临时凭证信息（可选）
echo "Assumed role with the following credentials:"
echo "\tAWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID"
echo "\tAWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY"
echo "\tAWS_SESSION_TOKEN: $AWS_SESSION_TOKEN"