#cloud-config
write_files:
  - path: /home/ubuntu/install-puppet-agent.sh
    permissions: '0744'
    owner: root:root
    content: |
        #!/bin/bash

      export APT_PUPPET_RELEASE_URL=${apt_puppet_release_url}
      
      wget https://apt.puppet.com/puppet8-release-jammy.deb -O /home/ubuntu/puppet8-release-jammy.deb
      sudo dpkg -i /home/ubuntu/puppet8-release-jammy.deb

      sudo apt-get -y update

      sudo apt-get -y install puppet-agent

      sleep 30

      sudo /opt/puppetlabs/bin/puppet resource service puppet ensure=running enable=true

      source /etc/profile.d/puppet-agent.sh

      export PATH=/opt/puppetlabs/bin:$PATH

      puppet config set server ip-10-0-101-154.eu-west-2.compute.internal --section main

      puppet ssl bootstrap

runcmd:
  - /home/ec2-user/install-puppet-agent.sh