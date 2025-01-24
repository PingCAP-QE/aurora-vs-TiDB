module aurora-vs-TiDB

go 1.21

toolchain go1.23.4

require (
	github.com/aws/aws-sdk-go-v2 v1.33.0
	github.com/aws/aws-sdk-go-v2/config v1.28.10
	github.com/aws/aws-sdk-go-v2/credentials v1.17.51
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.199.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.6
	github.com/aws/aws-sdk-go-v2/service/rds v1.93.4
	github.com/aws/aws-sdk-go-v2/service/ssm v1.56.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.6
	github.com/aws/smithy-go v1.22.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/pflag v1.0.5
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.8 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
)
