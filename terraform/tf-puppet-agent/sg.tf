resource "aws_security_group" "puppet_agent_sg" {
  name        = "puppet_agent_sg"
  description = "Allow Puppet and SSH ingress. Allow all egress"
  vpc_id      = var.vpc_id

  ingress {
    description      = "Allow SSH Ingress"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["212.132.219.162/32"]
  }

  ingress {
    description      = "Allow Puppet Ingress"
    from_port        = 8140
    to_port          = 8140
    protocol         = "tcp"
    cidr_blocks      = ["10.0.0.0/8"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "Puppet_Server_SG"
  }
}