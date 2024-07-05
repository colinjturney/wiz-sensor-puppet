#cloud-config
write_files:
  - path: /home/ubuntu/install-puppet-server.sh
    permissions: '0744'
    owner: root:root
    content: |
      #!/bin/bash

      export APT_PUPPET_RELEASE_URL=${apt_puppet_release_url}
      
      wget https://apt.puppet.com/puppet8-release-jammy.deb -O /home/ubuntu/puppet8-release-jammy.deb
      sudo dpkg -i /home/ubuntu/puppet8-release-jammy.deb

      sudo apt-get -y update

      sudo apt-get -y install puppetserver

      sleep 30

      sudo systemctl start puppetserver
runcmd:
  - /home/ubuntu/install-puppet-server.sh