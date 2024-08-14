output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.ghost.dns_name
}

output "bastion_public_ip" {
  description = "Public IP address of the bastion host"
  value       = aws_instance.bastion.public_ip
}
