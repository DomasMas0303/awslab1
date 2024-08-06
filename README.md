# Solutioning approach <a name="solution"></a>

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

As the core application in this task we will use [Ghost](https://ghost.org/) - a leading platform for bloggers.
You have to create complete infrastructure and deploy this application to it according to the statements above.

You can do this task following the step-by-step instructions or you can provision infrastructure on your own using this solution explanation as the requirements and then refer to instructions for self check.


## Reference Infrastructure Diagram: 



## Minimum observability requirements: 

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


# Pre-requirements <a name="prereq"></a>

- Activated AWS account
- All modules from CloudX AWS DevOps course completed
