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

### Example Commands

#### Create an RDS Aurora Cluster
```bash
bin/aurora-vs-TiDB --action=create-rds --cluster-id=Aurora-v3060-r6g4xl --instance-id=Aurora-v3060-r6g4xl-instance --param-group-name=my-custom-aurora-mysql80
```

#### Modify Aurora Cluster Parameters
```bash
bin/aurora-vs-TiDB --action=modify-params --cluster-id=Aurora-v3060-r6g4xl --param-group-name=my-custom-aurora-mysql80
```

#### Delete an existing Aurora cluster, instance, and parameter group
```bash
bin/aurora-vs-TiDB --action=delete-rds --cluster-id=Aurora-v3060-r6g4xl --instance-id=Aurora-v3060-r6g4xl-instance --param-group-name=my-custom-aurora-mysql80
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
bin/aurora-vs-TiDB --action prepare-data --ec2-instance-id i-1234567890abcdef0 --cluster-id Aurora-v3060-r6g4xl
```

#### Run Sysbench Performance Test
```bash
bin/aurora-vs-TiDB --action perftest-run --ec2-instance-id i-1234567890abcdef0 --cluster-id Aurora-v3060-r6g4xl --perf-type oltp_read_write
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

## License

This project is licensed under the MIT License.
