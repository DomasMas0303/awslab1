# Solution approach <a name="solution"></a>

- Use EFS for sharing data between compute instances 
- Use ASG and Fargate for application reliability across compute engines 
- Host application instances in 3 Availability Zones 
- Use RDS capabilities for HA DB solution (MySQL)
- Enable ALB as a single application entrypoint 
- Use Public/Private networks for secured access 
- Use strict Security Rules for enabling communication between all components of the entire stack 
- Use AWS Service(s) for managing secrets 
- Use EC2 userdata configuration for application provisioning 
- Use IAM roles and instance profiles for controlled access to AWS resources
- Use AWS CloudWatch to collect metrics and logs
- Use Tags to mark all resources, e.g. 'Project'='CloudX'

As the core application we will use [Ghost](https://ghost.org/) - a leading platform for bloggers.

## Reference Infrastructure Diagram: 

<img width="741" alt="image" src="https://github.com/user-attachments/assets/bce17cf0-8ce8-48eb-b014-acaf12e5e7a9">


## Observability: 

- Avg CPU utilization for EC2 instances in ASG
- ECS Service CPU Utilization 
- ECS Running tasks count 
- EFS ClientConnections 
- EFS StorageBytes in Mb
- RDS DB connections
- RDS CPU utilization
- RDS storage read\write IOPS
- Logs should be aggregated from all sources to CloudWatch Group/Logs 
- All metrics should be arranged into CloudWatch Dashboard 

<img width="1251" alt="image" src="https://github.com/user-attachments/assets/79f46465-5e8a-45b0-9d7d-54c4f189d9e3">

