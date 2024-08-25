variable "region" {
  description = "AWS region to create resources in"
  default     = "eu-central-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  default     = "10.10.0.0/16"
}

variable "ssh_key_name" {
  description = "Name of the SSH key pair in AWS"
  default     = "ghost-ec2-pool"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "t2.micro"
}

variable "asg_desired_capacity" {
  description = "Desired capacity for Auto Scaling Group"
  default     = 1
}

variable "asg_min_size" {
  description = "Minimum size for Auto Scaling Group"
  default     = 1
}

variable "asg_max_size" {
  description = "Maximum size for Auto Scaling Group"
  default     = 1
}
