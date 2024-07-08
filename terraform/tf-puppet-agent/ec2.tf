data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server*"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "puppet_agent_ec2" {

    ami                     = data.aws_ami.ubuntu.id
    instance_type           = "t3.small"
    subnet_id               = var.puppet_public_subnet_id
    vpc_security_group_ids  = [aws_security_group.puppet_agent_sg.id]
    key_name                = var.aws_ec2_ssh_key_name
    associate_public_ip_address = true

    user_data            = templatefile("${path.module}/provisioning/templates/cloud-config.tpl",{
      apt_puppet_release_url = var.apt_puppet_release_url
      puppet_server_hostname = var.puppet_server_hostname
    })

    tags = {
        Name = "PuppetAgent"
    }
}

resource "aws_network_interface" "puppet_internal" {
  subnet_id       = var.puppet_private_subnet_id
  security_groups = [aws_security_group.puppet_agent_sg.id]

  attachment {
    instance     = aws_instance.puppet_agent_ec2.id
    device_index = 1
  }
}