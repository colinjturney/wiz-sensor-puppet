module "vpc" {
  source    = "terraform-aws-modules/vpc/aws"
  version   = "5.2.0"

  name = "puppet-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-2a", "eu-west-2b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Terraform = "true"
    Environment = "dev"
  }
}

module "zones" {
  source  = "terraform-aws-modules/route53/aws//modules/zones"
  version = "~> 2.0"

  zones = {
    "colinturney.me" = {
      comment = "puppet example"
      private_zone = true
      vpc = [
        {
          vpc_id = module.vpc.vpc_id
        }
      ]

    }
  }

  tags = {
    ManagedBy = "Terraform"
  }

  depends_on = [ module.vpc ]
}

module "records" {
  source  = "terraform-aws-modules/route53/aws//modules/records"
  version = "~> 2.0"

  zone_id = values(module.zones.route53_zone_zone_id)[0]

  records = [
    {
      name    = "puppet"
      type    = "CNAME"
      ttl     = 60
      records = [
        module.puppet_server.puppet_internal_private_dns_name
      ]
    },
  ]

  depends_on = [module.zones, module.puppet_server]
}

module "puppet_server" {
    source =    "../tf-puppet-server"

    puppet_public_subnet_id = module.vpc.public_subnets[0]
    puppet_private_subnet_id = module.vpc.private_subnets[0]
    aws_ec2_ssh_key_name = "colin-puppet-demo-ssh"
    vpc_id                = module.vpc.vpc_id
    apt_puppet_release_url = "https://apt.puppet.com/puppet8-release-jammy.deb"
}

module "puppet_agent" {
    source =    "../tf-puppet-agent"

    puppet_public_subnet_id = module.vpc.public_subnets[0]
    puppet_private_subnet_id = module.vpc.private_subnets[0]
    aws_ec2_ssh_key_name = "colin-puppet-demo-ssh"
    vpc_id                = module.vpc.vpc_id
    apt_puppet_release_url = "https://apt.puppet.com/puppet8-release-jammy.deb"
    puppet_server_hostname = module.puppet_server.puppet_internal_private_dns_name
}