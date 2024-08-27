# Configure the AWS provider
provider "aws" {
  region = var.region
}

# Create the VPC
resource "aws_vpc" "cloudx" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "cloudx"
  }
}

# Create the public subnets
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.cloudx.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "public_${data.aws_availability_zones.available.names[count.index]}"
  }
}

# Create the private subnets for DB
resource "aws_subnet" "private_db" {
  count             = 3
  vpc_id            = aws_vpc.cloudx.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "private_db_${substr(data.aws_availability_zones.available.names[count.index], -1, 1)}"
  }
}

# Create the Internet gateway
resource "aws_internet_gateway" "cloudx_igw" {
  vpc_id = aws_vpc.cloudx.id

  tags = {
    Name = "cloudx-igw"
  }
}

# Create an Elastic IP for the NAT Gateway
resource "aws_eip" "nat_eip" {
  tags = {
    Name = "cloudx-nat-eip"
  }
}

# Create the NAT Gateway
resource "aws_nat_gateway" "cloudx_nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "cloudx-nat"
  }
}

# Create the public routing table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cloudx.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cloudx_igw.id
  }

  tags = {
    Name = "public_rt"
  }
}

# Associate the public subnets with the public routing table
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Create the private routing table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.cloudx.id

  tags = {
    Name = "private_rt"
  }
}

# Add a route to the private routing table
resource "aws_route" "private_route" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.cloudx_nat.id
}

# Associate the private subnets with the private routing table
resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private_db[count.index].id
  route_table_id = aws_route_table.private.id
}

# Create the security groups
resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "allows access to bastion"
  vpc_id      = aws_vpc.cloudx.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ec2_pool" {
  name        = "ec2_pool"
  description = "allows access to ec2 instances"
  vpc_id      = aws_vpc.cloudx.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "alb" {
  name        = "alb"
  description = "allows access to alb"
  vpc_id      = aws_vpc.cloudx.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
  }
}

resource "aws_security_group" "efs" {
  name        = "efs"
  description = "defines access to efs mount points"
  vpc_id      = aws_vpc.cloudx.id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_pool.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_security_group" "mysql" {
  name        = "mysql"
  description = "defines access to ghost db"
  vpc_id      = aws_vpc.cloudx.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2_pool.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "ec2_pool_from_alb" {
  type                     = "ingress"
  from_port                = 2368
  to_port                  = 2368
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.ec2_pool.id
}

# Egress rule to allow all traffic from alb to fargate_pool
resource "aws_security_group_rule" "alb_to_fargate_pool" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.fargate_pool.id
}

resource "aws_security_group_rule" "alb_to_ec2_pool" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.ec2_pool.id
  security_group_id        = aws_security_group.alb.id
}

resource "aws_security_group_rule" "bastion_to_fargate" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"  # All protocols
  security_group_id        = aws_security_group.bastion.id
  source_security_group_id = aws_security_group.fargate_pool.id
}

resource "aws_security_group_rule" "fargate_from_bastion" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"  # All protocols
  security_group_id        = aws_security_group.fargate_pool.id
  source_security_group_id = aws_security_group.bastion.id
}

# Create new SSH key
resource "tls_private_key" "ghost_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ghost_key_pair" {
  key_name   = "ghost-ec2-pool"
  public_key = tls_private_key.ghost_key.public_key_openssh
}

resource "local_file" "ghost_private_key" {
  content  = tls_private_key.ghost_key.private_key_pem
  filename = "${path.module}/ghost-ec2-pool.pem"
}

# Create the IAM role
resource "aws_iam_role" "ghost_app" {
  name = "ghost_app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ghost_app_permissions" {
  name = "ghost_app_permissions"
  role = aws_iam_role.ghost_app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientRootAccess",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:DescribeMountTargets",
          "elasticfilesystem:DescribeFileSystems",
          "ssm:GetParameter*",
          "secretsmanager:GetSecretValue",
          "kms:Decrypt",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "rds-db:connect",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeLoadBalancers",
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ghost_app_efs_access" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonElasticFileSystemClientFullAccess"
  role       = aws_iam_role.ghost_app.name
}

# Create the EFS file system
resource "aws_efs_file_system" "ghost_content" {
  creation_token = "ghost_content"

  tags = {
    Name = "ghost_content"
  }
}

# Create the EFS mount targets
resource "aws_efs_mount_target" "efs" {
  count           = 3
  file_system_id  = aws_efs_file_system.ghost_content.id
  subnet_id       = aws_subnet.public[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# Create the Application Load Balancer
resource "aws_lb" "ghost" {
  name               = "ghost"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "ghost_ec2" {
  name        = "ghost-ec2"
  port        = 2368
  protocol    = "HTTP"
  vpc_id      = aws_vpc.cloudx.id
  target_type = "instance"
}

# Create the Launch Template
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_launch_template" "ghost" {
  name          = "ghost"
  instance_type = var.instance_type
  image_id      = data.aws_ami.amazon_linux_2.id
  key_name      = aws_key_pair.ghost_key_pair.key_name

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ec2_pool.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ghost_app.name
  }

  user_data = base64encode(templatefile("user_data.sh", {
    LB_DNS_NAME     = aws_lb.ghost.dns_name
    EFS_ID          = aws_efs_file_system.ghost_content.id
    REGION          = var.region
    DB_HOST         = aws_db_instance.ghost.endpoint
    DB_NAME         = aws_db_instance.ghost.db_name
    DB_USER         = aws_db_instance.ghost.username
    SSM_DB_PASSWORD = aws_ssm_parameter.db_password.name
  }))
}

# Create the Auto Scaling Group
resource "aws_autoscaling_group" "ghost_ec2_pool" {
  name                = "ghost_ec2_pool"
  desired_capacity    = var.asg_desired_capacity
  max_size            = var.asg_max_size
  min_size            = var.asg_min_size
  target_group_arns   = [aws_lb_target_group.ghost_ec2.arn]
  vpc_zone_identifier = aws_subnet.public[*].id

  launch_template {
    id      = aws_launch_template.ghost.id
    version = "$Latest"
  }
}

resource "aws_iam_role" "bastion" {
  name = "bastion_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "bastion_ecs_exec" {
  name = "bastion_ecs_exec"
  role = aws_iam_role.bastion.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:ExecuteCommand",
          "ecs:DescribeTasks",
          "ecs:CreateService",
          "ecs:UpdateService"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bastion_ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.bastion.name
}

resource "aws_iam_instance_profile" "bastion" {
  name = "bastion_profile"
  role = aws_iam_role.bastion.name
}


# Create the Bastion host
resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.instance_type
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  availability_zone           = "eu-central-1a"
  iam_instance_profile        = aws_iam_instance_profile.bastion.name

  tags = {
    Name = "bastion"
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "http" "myip" {
  url = "http://ipv4.icanhazip.com"
}

# IAM instance profile
resource "aws_iam_instance_profile" "ghost_app" {
  name = "ghost_app"
  role = aws_iam_role.ghost_app.name
}

# Database subnet group
resource "aws_db_subnet_group" "ghost" {
  name       = "ghost"
  subnet_ids = aws_subnet.private_db[*].id

  tags = {
    Name = "ghost database subnet group"
  }
}

# RDS instance
resource "aws_db_instance" "ghost" {
  identifier           = "ghost"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_type         = "gp2"
  db_name              = "ghost"
  username             = "ghost"
  password             = aws_ssm_parameter.db_password.value
  parameter_group_name = "default.mysql8.0"
  skip_final_snapshot  = true

  vpc_security_group_ids = [aws_security_group.mysql.id]
  db_subnet_group_name   = aws_db_subnet_group.ghost.name
}

# Generate and store DB password
resource "random_password" "db_password" {
  length  = 16
  special = false
}

resource "aws_ssm_parameter" "db_password" {
  name  = "/ghost/dbpassw"
  type  = "SecureString"
  value = random_password.db_password.result
}

# New private subnets for ECS
resource "aws_subnet" "private_ecs" {
  count             = 3
  vpc_id            = aws_vpc.cloudx.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "private_ecs_${substr(data.aws_availability_zones.available.names[count.index], -1, 1)}"
  }
}

# Associate the private ECS subnets with the private routing table
resource "aws_route_table_association" "private_ecs" {
  count          = 3
  subnet_id      = aws_subnet.private_ecs[count.index].id
  route_table_id = aws_route_table.private.id
}

# New security group for Fargate
resource "aws_security_group" "fargate_pool" {
  name        = "fargate_pool"
  description = "Allows access for Fargate instances"
  vpc_id      = aws_vpc.cloudx.id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.efs.id]
  }

  ingress {
    from_port       = 2368
    to_port         = 2368
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Update EFS security group
resource "aws_security_group_rule" "efs_from_fargate" {
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.fargate_pool.id
  security_group_id        = aws_security_group.efs.id
}

# Update MySQL security group
resource "aws_security_group_rule" "mysql_from_fargate" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.fargate_pool.id
  security_group_id        = aws_security_group.mysql.id
}

# Create a new EFS file system for ECS
resource "aws_efs_file_system" "ghost_content_ecs" {
  creation_token = "ghost_content_ecs"

  tags = {
    Name = "ghost_content_ecs"
  }
}

# Create the EFS mount targets for ECS
resource "aws_efs_mount_target" "efs_ecs" {
  count           = 3
  file_system_id  = aws_efs_file_system.ghost_content_ecs.id
  subnet_id       = aws_subnet.private_ecs[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# ECR repository
resource "aws_ecr_repository" "ghost" {
  name                 = "ghost"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

# IAM role for ECS
resource "aws_iam_role" "ghost_ecs" {
  name = "ghost_ecs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role" "cloudwatch_role" {
  name = "cloudwatch_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_permissions" {
  name = "cloudwatch_permissions"
  role = aws_iam_role.cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DeleteAlarms",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ghost_ecs_permissions" {
  name = "ghost_ecs_permissions"
  role = aws_iam_role.ghost_ecs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientRootAccess",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:DescribeMountTargets",
          "elasticfilesystem:DescribeFileSystems",
          "ssm:GetParameter*",
          "secretsmanager:GetSecretValue",
          "kms:Decrypt",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "rds-db:connect",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeLoadBalancers",
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "ecs:DescribeClusters",
          "ecs:ListServices",
          "ecs:DescribeServices"
        ]
        Resource = "*"
      }
    ]
  })
}

# VPC Endpoints
resource "aws_security_group" "vpc_endpoint" {
  name        = "vpc_endpoint"
  description = "Allow traffic for VPC endpoints"
  vpc_id      = aws_vpc.cloudx.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.cloudx.id
  service_name = "com.amazonaws.${var.region}.s3"
  route_table_ids = [aws_route_table.private.id]
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "efs" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.elasticfilesystem"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "cloudwatch" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.monitoring"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

resource "aws_vpc_endpoint" "cloudwatch_logs" {
  vpc_id              = aws_vpc.cloudx.id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_ecs[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
}

# ECS Cluster
resource "aws_ecs_cluster" "ghost" {
  name = "ghost"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "ghost" {
  family                   = "task_def_ghost"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ghost_ecs.arn
  task_role_arn            = aws_iam_role.ghost_ecs.arn

  container_definitions = jsonencode([
    {
      name  = "ghost_container"
      image = "${aws_ecr_repository.ghost.repository_url}:4.12.1"
      essential = true
      environment = [
        { name = "database__client", value = "mysql" },
        { name = "database__connection__host", value = split(":", aws_db_instance.ghost.endpoint)[0] },
        { name = "database__connection__port", value = split(":", aws_db_instance.ghost.endpoint)[1] },
        { name = "database__connection__user", value = aws_db_instance.ghost.username },
        { name = "database__connection__database", value = aws_db_instance.ghost.db_name },
        { name = "logging__level", value = "debug" },
        { name = "url", value = "http://${aws_lb.ghost.dns_name}" },
        { name = "server__host", value = "0.0.0.0" }
      ]
      secrets = [
        { name = "database__connection__password", valueFrom = aws_ssm_parameter.db_password.arn }
      ]
      mountPoints = [
        {
          containerPath = "/var/lib/ghost/content"
          sourceVolume  = "ghost_volume_ecs"
        }
      ]
      portMappings = [
        {
          containerPort = 2368
          hostPort = 2368
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/ghost"
          awslogs-region        = var.region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  volume {
    name = "ghost_volume_ecs"

    efs_volume_configuration {
      file_system_id = aws_efs_file_system.ghost_content_ecs.id
    }
  }
}

# ECS Service
resource "aws_ecs_service" "ghost" {
  name            = "ghost"
  cluster         = aws_ecs_cluster.ghost.id
  task_definition = aws_ecs_task_definition.ghost.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  enable_execute_command = true

  health_check_grace_period_seconds = 120

  network_configuration {
    subnets         = [aws_subnet.private_ecs[0].id]
    security_groups = [aws_security_group.fargate_pool.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.ghost_fargate.arn
    container_name   = "ghost_container"
    container_port   = 2368
  }
}

resource "aws_lb_target_group" "ghost_fargate" {
  name        = "ghost-fargate"
  port        = 2368
  protocol    = "HTTP"
  vpc_id      = aws_vpc.cloudx.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/"
    port                = 2368
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 5
    interval            = 40
    matcher             = "200-399"
  }
}

# Modify ALB listener to support both EC2 and Fargate
resource "aws_lb_listener" "ghost" {
  load_balancer_arn = aws_lb.ghost.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "forward"
    forward {
      target_group {
        arn    = aws_lb_target_group.ghost_ec2.arn
        weight = 50
      }
      target_group {
        arn    = aws_lb_target_group.ghost_fargate.arn
        weight = 50
      }
    }
  }
}

# CloudWatch log group for ECS
resource "aws_cloudwatch_log_group" "ghost" {
  name = "/ecs/ghost"
  retention_in_days = 30
}

# EC2 instances in ASG - Average CPU Utilization
resource "aws_cloudwatch_metric_alarm" "asg_cpu_alarm" {
  alarm_name          = "ASG-CPU-Utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EC2 CPU utilization in ASG"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.ghost_ec2_pool.name
  }
}

# ECS - Service CPU Utilization
resource "aws_cloudwatch_metric_alarm" "ecs_cpu_alarm" {
  alarm_name          = "ECS-Service-CPU-Utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ECS service CPU utilization"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    ClusterName = aws_ecs_cluster.ghost.name
    ServiceName = aws_ecs_service.ghost.name
  }
}

# ECS - Running Tasks Count
resource "aws_cloudwatch_metric_alarm" "ecs_tasks_alarm" {
  alarm_name          = "ECS-Running-Tasks-Count"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = "300"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors the number of running ECS tasks"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    ClusterName = aws_ecs_cluster.ghost.name
  }
}

# EFS - Client Connections
resource "aws_cloudwatch_metric_alarm" "efs_connections_alarm" {
  alarm_name          = "EFS-Client-Connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ClientConnections"
  namespace           = "AWS/EFS"
  period              = "300"
  statistic           = "Average"
  threshold           = "100"
  alarm_description   = "This metric monitors the number of EFS client connections"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    FileSystemId = aws_efs_file_system.ghost_content.id
  }
}

# EFS - Storage Bytes in MB
resource "aws_cloudwatch_metric_alarm" "efs_storage_alarm" {
  alarm_name          = "EFS-Storage-Bytes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "StorageBytes"
  namespace           = "AWS/EFS"
  period              = "300"
  statistic           = "Average"
  threshold           = "5000000000"  # 5 GB in bytes
  alarm_description   = "This metric monitors EFS storage usage"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    FileSystemId = aws_efs_file_system.ghost_content.id
  }
}

# RDS - Database Connections
resource "aws_cloudwatch_metric_alarm" "rds_connections_alarm" {
  alarm_name          = "RDS-Database-Connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "100"
  alarm_description   = "This metric monitors the number of database connections"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.ghost.id
  }
}

# RDS - CPU Utilization
resource "aws_cloudwatch_metric_alarm" "rds_cpu_alarm" {
  alarm_name          = "RDS-CPU-Utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.ghost.id
  }
}

# RDS - Storage Read IOPS
resource "aws_cloudwatch_metric_alarm" "rds_read_iops_alarm" {
  alarm_name          = "RDS-Read-IOPS"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ReadIOPS"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "500"
  alarm_description   = "This metric monitors RDS read IOPS"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.ghost.id
  }
}

# RDS - Storage Write IOPS
resource "aws_cloudwatch_metric_alarm" "rds_write_iops_alarm" {
  alarm_name          = "RDS-Write-IOPS"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "WriteIOPS"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "500"
  alarm_description   = "This metric monitors RDS write IOPS"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.ghost.id
  }
}

# SNS Topic for alarms
resource "aws_sns_topic" "alarms" {
  name = "cloudwatch-alarms"
}

resource "aws_cloudwatch_dashboard" "ghost" {
  dashboard_name = "Ghost-Dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.ghost_ec2_pool.name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "EC2 ASG - CPU Utilization"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.ghost.name, "ServiceName", aws_ecs_service.ghost.name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "ECS - Service CPU Utilization"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["ECS/ContainerInsights", "RunningTaskCount", "ClusterName", aws_ecs_cluster.ghost.name]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "ECS - Running Tasks Count"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EFS", "ClientConnections", "FileSystemId", aws_efs_file_system.ghost_content.id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "EFS - Client Connections"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EFS", "StorageBytes", "FileSystemId", aws_efs_file_system.ghost_content.id, "StorageClass", "Total"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "EFS - Storage Bytes"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.ghost.id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "RDS - Database Connections"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 18
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.ghost.id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "RDS - CPU Utilization"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 18
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "ReadIOPS", "DBInstanceIdentifier", aws_db_instance.ghost.id],
            [".", "WriteIOPS", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.region
          title   = "RDS - Read/Write IOPS"
        }
      }
    ]
  })
}
