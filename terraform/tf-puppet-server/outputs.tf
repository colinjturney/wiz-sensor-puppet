output "puppet_internal_private_dns_name" {
    value = aws_instance.puppet_ec2.private_dns
}