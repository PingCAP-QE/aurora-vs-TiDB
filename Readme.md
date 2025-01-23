# AWS Aurora VS TiDB Performance Test Tool

This tool provides an automated way to do aurora automatic performance testing, including RDS Aurora clusters and EC2 instances. It supports various actions like creating, deleting, and modifying resources, as well as initializing environments for performance testing.

## Features

- **RDS Management**:
  - Create, delete, and modify Aurora clusters and instances.
  - Manage custom parameter groups.
- **EC2 Management**:
  - Create and delete EC2 instances for performance testing.
  - Initialize performance testing environments.
- **Performance Testing**:
  - Prepare data and run Sysbench OLTP tests.

## Prerequisites

1. **AWS CLI Configuration**:
   - Set up your AWS credentials and default region using the AWS CLI:
     ```bash
     aws configure
     ```
   - How to configure the aws config, refer to: https://pingcap.awsapps.com/start/#
2. **Environment Variables**:
   - Set the `MASTER_PASSWORD` environment variable for the RDS master user password:
     ```bash
     export MASTER_PASSWORD="your_master_password"
     ```

3. **IAM Permissions**:
   - Ensure the IAM user or role has sufficient permissions to manage RDS and EC2 resources.

4. **Dependencies**:
   - Install the required Go modules:
     ```bash
     go mod tidy
     ```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. Build the project:
   ```bash
   make
   ```

## Usage

### Command-Line Arguments

| Argument                      | Short | Description                                                                                      |
|-------------------------------|-------|--------------------------------------------------------------------------------------------------|
| `--action`                    | `-a`  | Action to perform: `create-rds`, `delete-rds`, `modify-params`, `create-client`, `delete-client`, `init-perftest-env`, `prepare-data`, `perftest-run` |
| `--cluster-id`                | `-c`  | Aurora cluster identifier (required for most actions).                                           |
| `--instance-id`               | `-i`  | Aurora instance identifier (required for creating/deleting instances).                          |
| `--param-group-name`          | `-p`  | Parameter group name (default: `my-custom-aurora-mysql80`).                                      |
| `--instance-class`            | `-d`  | Aurora instance class (default: `db.r6g.4xlarge`).                                              |
| `--ec2-instance-type`         | `-t`  | EC2 instance type (default: `m5.2xlarge`).                                                      |
| `--ec2-image-id`              | `-m`  | EC2 image ID (default: `ami-0afb6e8e0625142bc`).                                                |
| `--ec2-instance-id`           | `-e`  | EC2 instance ID (required for deleting instances or initializing performance environments).      |
| `--ec2-subnet-id`             | `-s`  | EC2 subnet ID.                                                                                  |
| `--ec2-security-group-id`     | `-g`  | EC2 security group ID.                                                                          |
| `--ec2-key-name`              | `-k`  | EC2 key pair name (default: `pub-st-rsa`).                                                      |
| `--perf-type`                 | `-o`  | Sysbench performance test type: `oltp_read_only`, `oltp_read_write`, or `oltp_write_only`.       |
| `--restore`                   | `-s`  | Restore data from S3 instead of preparing data with Sysbench, create a new cluster and restore data from mysql-snapshot      |
| `--role-arn`                  | `-r`  | aws login account roleARN (default: `arn:aws:iam::986330900858:role/full-manager-service-role`)  |
| `--role-session`              | `-n`  | aws login role session name (default: `full-manager-service-role`)                               |


### Example Commands

#### Create an RDS Aurora Cluster
```bash
bin/aurora-vs-TiDB --action=create-rds --cluster-id=Aurora-v3060-perftest --instance-id=Aurora-v3060-perftest-instance --param-group-name=my-custom-aurora-mysql80
```

#### Restore an RDS Aurora Cluster from mysql snapshot
```bash
bin/aurora-vs-TiDB --action=create-rds --cluster-id=Aurora-v3060-perftest --instance-id=Aurora-v3060-perftest-instance --param-group-name=my-custom-aurora-mysql80
```

#### Modify Aurora Cluster Parameters
```bash
bin/aurora-vs-TiDB --action=modify-params --cluster-id=Aurora-v3060-perftest --param-group-name=my-custom-aurora-mysql80
```

#### Delete an existing Aurora cluster, instance, and parameter group
```bash
bin/aurora-vs-TiDB --action=delete-rds --cluster-id=Aurora-v3060-perftest --instance-id=Aurora-v3060-perftest-instance --param-group-name=my-custom-aurora-mysql80
```

#### Create an EC2 Client Instance
```bash
bin/aurora-vs-TiDB --action=create-client-ec2 --ec2-instance-type=m5.2xlarge 
```

#### Initialize Performance Test Environment
```bash
bin/aurora-vs-TiDB--action init-perftest-env --ec2-instance-id i-1234567890abcdef0
```

#### Prepare Data for Sysbench
```bash
bin/aurora-vs-TiDB --action prepare-data --ec2-instance-id i-1234567890abcdef0 --cluster-id Aurora-v3060-perftest
```

#### Run Sysbench Performance Test
```bash
bin/aurora-vs-TiDB --action perftest-run --ec2-instance-id i-1234567890abcdef0 --cluster-id Aurora-v3060-perftest --perf-type oltp_read_write
```

## Code Structure

- **Main Functionality**:
  - `createResources`: Creates Aurora clusters and instances.
  - `deleteResources`: Deletes Aurora clusters and instances.
  - `modifyClusterParameters`: Modifies Aurora parameter groups.
  - `createClientEC2`: Creates EC2 instances for performance testing.
- **Utility Functions**:
  - `getAuroraClusterVPC`: Retrieves the VPC ID of an Aurora cluster.
  - `createSecurityGroup`: Creates a security group for an EC2 instance.

## Notify
1. ** assume role arn privilege and configuration ** 
   - The role that executes assume-role needs permissions to perform assume-role, RDS, EC2, and other resource operations. For instructions on how to add role permissions, please refer to the AWS Official Documentation.
2. ** restore rds snapshot role arn privilege and configuration **
   - The role that executes restore can be separate from the assume-role role or the same role. Ensure that the role has permissions for S3 and RDS operations.
3. ** aws env preparation **
   - Configure the trust policies for the above two roles. For instructions on how to configure trust policies, please refer to the AWS Official Documentation.When running for the first time, please configure the AWS Access Key ID, Secret Access Key, and Token (these can be set through environment variables, AWS configuration files, etc.). T
4. ** automaticlly refresh temporary credential token **
   - The assume-role operation will run automatically when the program starts and will refresh the temporary token every 10 minutes. he program will automatically refresh the token periodically, so you don't need to worry about token expiration.
5. ** performance test one-click script **
   - You can run the one-click test script aurora_perfrun.sh in the project, or you can run individual steps such as resource creation, deletion, assume-role, running tests, and data preparation. If you choose to run the one-click script, ensure that the permissions and policies described in steps 1-4 are correctly configured.
If you encounter any issues during execution, please contact the author for assistance.
## Notes:
I included hyperlinks to the relevant sections of the AWS official documentation to make it easier for users to find more information.
If you need further adjustments or additional details, please let me know and I will help refine the content!

## License
This project is licensed under the MIT License.
