output "puppet_internal_private_dns_name" {
    value = aws_network_interface.puppet_internal.private_dns_name
}