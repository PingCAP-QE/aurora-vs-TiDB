# Aurora VS TiDB Perftest Tool

## Overview

This tool allows you to create, delete, and modify Aurora MySQL database clusters and their parameter groups using the AWS SDK for Go v2. It provides a command-line interface to perform these operations, making it easy to manage your Aurora resources.

## Prerequisites

- **AWS CLI**: Ensure you have the AWS CLI installed and configured with the necessary credentials.
- **Go**: Ensure you have Go installed on your system.
- **AWS SDK for Go v2**: This tool uses the AWS SDK for Go v2 to interact with AWS services.

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/aurora-vs-TiDB.git
   cd aurora-vs-TiDB
   ```

2. Install the required Go packages:
   ```sh
   go mod download
   ```

3. Build the tool:
   ```sh
   go build -o aurora-vs-TiDB
   ```

## Usage

### Environment Variables

- `MASTER_PASSWORD`: The master user password for the Aurora cluster. This is a required environment variable.

### Command-Line Parameters

- `--action` or `-a`: The action to perform. Valid values are `create`, `delete`, and `modify-params`.
- `--cluster-id` or `-c`: The identifier for the Aurora cluster.
- `--instance-id` or `-i`: The identifier for the Aurora instance.
- `--param-group-name` or `-p`: The name of the parameter group.
- `--instance-class` or `-d`: The instance class for the Aurora instance (default: `db.r6g.4xlarge`).

### Examples

#### Create a new Aurora cluster, instance, and parameter group

```sh
export MASTER_PASSWORD=yourpassword123
./aurora-vs-TiDB --action=create --cluster-id=Aurora-v3060-r6g4xl --instance-id=Aurora-v3060-r6g4xl-instance --param-group-name=my-custom-aurora-mysql80
```

#### Modify the parameters of an existing Aurora cluster

```sh
./aurora-vs-TiDB --action=modify-params --cluster-id=Aurora-v3060-r6g4xl --param-group-name=my-custom-aurora-mysql80
```

#### Delete an existing Aurora cluster, instance, and parameter group

```sh
./aurora-vs-TiDB --action=delete --cluster-id=Aurora-v3060-r6g4xl --instance-id=Aurora-v3060-r6g4xl-instance --param-group-name=my-custom-aurora-mysql80
```

## Error Handling

The tool logs errors and provides descriptive messages to help you diagnose issues. Common errors include:

- **Invalid Parameter Group Name**: Ensure the parameter group name starts with a letter, contains only ASCII letters, digits, and hyphens, and does not end with a hyphen or contain two consecutive hyphens or a period.
- **Cluster Not Available for Modification**: Ensure the cluster is in the `available` state before attempting to modify it.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request to suggest improvements or new features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

### 说明

1. **Overview**: 简要介绍工具的功能和用途。
2. **Prerequisites**: 列出使用工具前需要满足的条件，如安装AWS CLI和Go。
3. **Installation**: 说明如何克隆仓库、安装依赖和构建工具。
4. **Usage**: 详细说明如何使用工具，包括环境变量和命令行参数的设置。
5. **Examples**: 提供具体的命令行示例，展示如何创建、修改和删除Aurora资源。
6. **Error Handling**: 说明工具如何处理常见错误，并提供解决方法。
7. **Contributing**: 鼓励用户贡献代码，说明如何提交问题或拉取请求。
8. **License**: 说明项目的许可信息。

希望这个 `README.md` 文件能帮助用户更好地理解和使用你的工具！
