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

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
  }

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

resource "aws_security_group_rule" "alb_to_ec2_pool" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.ec2_pool.id
  security_group_id        = aws_security_group.alb.id
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
          "ec2:Describe*",
          "elasticfilesystem:DescribeFileSystems",
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "ssm:GetParameter*",
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
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

resource "aws_lb_listener" "ghost" {
  load_balancer_arn = aws_lb.ghost.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ghost_ec2.arn
  }
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

# Create the Bastion host
resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.ghost_key_pair.key_name
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true

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
