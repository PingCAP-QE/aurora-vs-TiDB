#bin/bash
# install
#1. create aurora RDS cluster and instance
bin/aurora-vs-TiDB --action=create-rds --cluster-id=Aurora-v3060-r6g4xl --instance-id=Aurora-v3060-r6g4xl-instance --param-group-name=my-custom-aurora-mysql80

#2. modify aurora RDS parameter
bin/aurora-vs-TiDB --action=modify-params --cluster-id=Aurora-v3060-r6g4xl --param-group-name=my-custom-aurora-mysql80

#3. create ec2-client-for-rds
bin/aurora-vs-TiDB --action=create-client --cluster-id=Aurora-v3060-r6g4xl 

#4. get rds instance login endpoint
bin/aurora-vs-TiDB --action get-rds-endpoint --cluster-id Aurora-v3060-r6g4xl 
 #uninstall
#1. get ec2-client instance id
# from create ret

#2. delete ec2-client-for-rds
bin/aurora-vs-TiDB --action=delete-client --ec2-instance-id=i-04037f830dc813d31

#3. delete rds cluster and instance
bin/aurora-vs-TiDB --action=delete-rds --cluster-id=Aurora-v3060-r6g4xl --instance-id=Aurora-v3060-r6g4xl-instance --param-group-name=my-custom-aurora-mysql80