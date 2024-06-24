#!/bin/bash
# (C) Wiz, Inc. 2023-present
# All rights reserved
# Licensed for Wiz customers only under the Wiz Master Subscription Agreement or such other agreement in place between Wiz and customer
# Wiz Sensor installation script: install and set up the Sensor on supported Linux distributions
# using the package manager and Wiz repositories.

# script config
IS_GCOS=$(grep -q "Container-Optimized OS from Google" /etc/os-release && echo 1 || echo 0)
if [ $IS_GCOS -eq 1 ]; then
  WIZ_DIR=/var/lib/wiz
else
  WIZ_DIR=/opt/wiz
fi
SENSOR_DIR=${WIZ_DIR}/sensor/host-store
LOGFILE=${SENSOR_DIR}/install.log
YUM_KEY_URL="https://downloads.wiz.io/sensor/sensor_public_key.asc"
YUM_URL="https://rpm.wiz.io/projects/sensor-repos"
YUM_CHANNEL="${YUM_CHANNEL:-sensor-yum}"
APT_URL="https://dpkg.wiz.io/projects/sensor-repos"
APT_KEY_URL="https://dpkg.wiz.io/doc/repo-signing-key.gpg"
APT_CHANNEL="${APT_CHANNEL:-sensor-apt}"
CONTAINER_REGISTRY_LOGIN="${CONTAINER_REGISTRY_LOGIN:-1}"
CONTAINER_REGISTRY="${CONTAINER_REGISTRY:-wizio.azurecr.io}"
DOCKER_ONLY_OS_LIST="GCOS Flatcar"

export WIZ_BACKEND_ENV="${WIZ_BACKEND_ENV:-prod}"
export WIZ_AUTOUPDATE="${WIZ_AUTOUPDATE:-1}"

SCRIPT_VERSION=1.0.3045
if [ -z "1.0.3045" ]; then
  SCRIPT_VERSION=1.0.0
fi

if [ "$SENSOR_VERSION_SAME_AS_SCRIPT_VERSION" = "1" ]; then
  export WIZ_SENSOR_VERSION="1.0.3045"
fi

YUM_GPGCHECK=1
if [[ -z "$WIZ_ENABLE_YUM_GPGCHECK" || "$WIZ_ENABLE_YUM_GPGCHECK" == "0" || "${WIZ_ENABLE_YUM_GPGCHECK,,}" == "false" ]]; then
    YUM_GPGCHECK=0
fi

print_banner() {
  cat << 'BANNER'
  __        ___       ____                            
  \ \      / (_)____ / ___|  ___ _ __  ___  ___  _ __ 
   \ \ /\ / /| |_  / \___ \ / _ \ '_ \/ __|/ _ \| '__|
    \ V  V / | |/ /   ___) |  __/ | | \__ \ (_) | |   
     \_/\_/  |_/___| |____/ \___|_| |_|___/\___/|_|   

BANNER
}

BOLD="$(tput bold 2>/dev/null || printf '')"
RED="$(tput setaf 1 2>/dev/null || printf '')"
GREEN="$(tput setaf 2 2>/dev/null || printf '')"
BLUE="$(tput setaf 4 2>/dev/null || printf '')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
NO_COLOR="$(tput sgr0 2>/dev/null || printf '')"

info() {
  printf '%s\n' "${BOLD}${BLUE}$*${NO_COLOR}"
}

warn() {
  printf '%s\n' "${YELLOW}$*${NO_COLOR}"
}

error() {
  printf '%s\n' "${RED}$*${NO_COLOR}" >&2
}

completed() {
  printf '%s\n' "${GREEN}$*${NO_COLOR}"
}

setup_logger() {
  npipe=/tmp/$$.tmp
  mknod $npipe p
  tee <$npipe $LOGFILE &
  exec 1>&-
  exec 1>$npipe 2>&1
  trap 'rm -f $npipe' EXIT
}

create_sensor_dir() {
  mkdir -m 700 -p "$WIZ_DIR"
  mkdir -p "$SENSOR_DIR"
  chmod -R 700 "$WIZ_DIR"
}

generate_persistent_id() {
  if [ ! -f "$SENSOR_DIR/persistent_id.yml" ]; then
    if command -v uuidgen &>/dev/null; then
      uuid=$(uuidgen)
    elif [ -f /proc/sys/kernel/random/uuid ]; then
      uuid=$(cat /proc/sys/kernel/random/uuid)
    elif command -v tr &> /dev/null && command -v fold &> /dev/null && command -v head &> /dev/null; then
      hex_string=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1)
      uuid="${hex_string:0:8}-${hex_string:8:4}-${hex_string:12:4}-${hex_string:16:4}-${hex_string:20:12}"
    fi

    if [ -n "$uuid" ]; then
      echo "persistent_id: $uuid" > "$SENSOR_DIR/persistent_id.yml"
    fi
  fi
}

select_install_method() {
  if [ -z "$DOCKER_INSTALL" ]; then
    if [[ "$DOCKER_ONLY_OS_LIST" =~ "$OS" ]]; then
      DOCKER_INSTALL=1
    else
      DOCKER_INSTALL=0
    fi
  fi

  if [ "$DOCKER_INSTALL" = "1" ]; then
    info "Installing Wiz Sensor using Docker"
  else
    info "Installing Wiz Sensor using package manager"
  fi
}

get_auth_url() {
  if [ "$WIZ_BACKEND_ENV" = "prod" ]; then
    base_domain="app.wiz.io"
  else
    base_domain="$WIZ_BACKEND_ENV.wiz.io"
  fi

  echo "https://auth.$base_domain/oauth/token"
}

check_api_key() {
  if [[ -z $WIZ_API_CLIENT_ID ]] || [[ -z $WIZ_API_CLIENT_SECRET ]]; then
    error "Missing API key. Please set WIZ_API_CLIENT_ID and WIZ_API_CLIENT_SECRET environment variables and try again.";
    exit 1;
  fi

  if [[ -n "$WIZ_EXTRA_SSL_CERT_DIR" ]]; then
    warn "Skipping API key check since WIZ_EXTRA_SSL_CERT_DIR is set."
    return 0
  fi

  if [[ -z $WIZ_SKIP_COMM_CHECK ]]; then
    local auth_url=$(get_auth_url)
    local curl_cmd="curl -s --write-out "%{http_code}" --output /dev/null -X POST $auth_url \
      -A \"wiz-sensor-install-script/1.0.3045\" \
      -H \"Content-Type: application/x-www-form-urlencoded\" \
      -H \"encoding: UTF-8\" \
      --data-urlencode \"grant_type=client_credentials\" \
      --data-urlencode \"client_id=$WIZ_API_CLIENT_ID\" \
      --data-urlencode \"client_secret=$WIZ_API_CLIENT_SECRET\" \
      --data-urlencode \"audience=wiz-agent-api\"";

    if [ -n "$WIZ_HTTP_PROXY_URL" ]; then
      curl_cmd+=" --proxy $WIZ_HTTP_PROXY_URL"
    fi

    if [ -n "$WIZ_HTTP_PROXY_USERNAME" ] && [ -n "$WIZ_HTTP_PROXY_PASSWORD" ]; then
      curl_cmd+=" --proxy-user $WIZ_HTTP_PROXY_USERNAME:$WIZ_HTTP_PROXY_PASSWORD"
    fi

    if [ -n "$WIZ_HTTP_PROXY_CERT" ]; then
      local tmp_cert_file=$(mktemp)
      echo "$WIZ_HTTP_PROXY_CERT" | base64 -d > $tmp_cert_file
      curl_cmd+=" --cacert $tmp_cert_file"
    fi

    local http_status_code=$(eval $curl_cmd)
    if [ "$http_status_code" -ne "200" ]; then
      error "Invalid API key."
      exit 1;
    fi
  fi
}

check_arch() {
  arch=$(uname -m)
  if [ "$arch" != "x86_64" ] && [ "$arch" != "aarch64" ]; then
    error "Unsupported architecture: $arch"
    exit 1;
  fi
}

check_kernel_version() {
  kernel_ver=$(uname -r | cut -d '-' -f 1)
  major_ver=$(echo $kernel_ver | cut -d '.' -f 1)
  minor_ver=$(echo $kernel_ver | cut -d '.' -f 2)
  if [ "$major_ver" -lt 4 ] || ([ "$major_ver" -eq 4 ] && [ "$minor_ver" -lt 18 ]); then
    error "Unsupported kernel version: $kernel_ver"
    exit 1;
  fi
}

check_os_and_distro() {
KNOWN_DISTRIBUTION="(Debian|Ubuntu|RedHat|CentOS|openSUSE|Amazon|Arista|SUSE|Rocky|AlmaLinux|Container-Optimized OS|Flatcar Container Linux)"
DISTRIBUTION=$(lsb_release -d 2>/dev/null | grep -Eo "$KNOWN_DISTRIBUTION"  || grep -Eo "$KNOWN_DISTRIBUTION" /etc/issue 2>/dev/null || grep -Eo "$KNOWN_DISTRIBUTION" /etc/Eos-release 2>/dev/null || grep -m1 -Eo "$KNOWN_DISTRIBUTION" /etc/os-release 2>/dev/null || uname -s)

  if [ -f /etc/debian_version ] || [ "$DISTRIBUTION" == "Debian" ] || [ "$DISTRIBUTION" == "Ubuntu" ]; then
    OS="Debian"
  elif [ -f /etc/redhat-release ] || [ "$DISTRIBUTION" == "RedHat" ] || [ "$DISTRIBUTION" == "CentOS" ] || [ "$DISTRIBUTION" == "Amazon" ] || [ "$DISTRIBUTION" == "Rocky" ] || [ "$DISTRIBUTION" == "AlmaLinux" ]; then
    OS="RedHat"
  # Some newer distros like Amazon may not have a redhat-release file
  elif [ -f /etc/system-release ] || [ "$DISTRIBUTION" == "Amazon" ]; then
    OS="RedHat"
  # Arista is based off of Fedora14/18 but do not have /etc/redhat-release
  elif [ -f /etc/Eos-release ] || [ "$DISTRIBUTION" == "Arista" ]; then
    OS="RedHat"
  # openSUSE and SUSE use /etc/SuSE-release or /etc/os-release
  elif [ -f /etc/SuSE-release ] || [ "$DISTRIBUTION" == "SUSE" ] || [ "$DISTRIBUTION" == "openSUSE" ]; then
    OS="SUSE"
  elif [ "$DISTRIBUTION" == "Container-Optimized OS" ]; then
    OS="GCOS"
  elif [ "$DISTRIBUTION" == "Flatcar Container Linux" ]; then
    OS="Flatcar"
  else
    error "Unsupported distribution"
    exit 1;
  fi

  info "Detected OS is $OS"
  DISTRIBUTION="${DISTRIBUTION:-$OS}"
  export WIZ_LINUX_DISTRO="$DISTRIBUTION"
}

check_root() {
  if [ "$UID" != "0" ]; then
    error "Please run this script as root"
    exit 1;
  fi
}

check_update_policy() {
  if [ "$DOCKER_INSTALL" = "1" ]; then
    if [ -z "$WIZ_SENSOR_VERSION" ]; then
      export WIZ_SENSOR_VERSION="v1"
    fi
  else
    if [ -n "$WIZ_SENSOR_VERSION" ] && [ "$WIZ_AUTOUPDATE" != "false" ] && [ "$WIZ_AUTOUPDATE" != "0" ]; then
      error "WIZ_AUTOUPDATE is not supported when WIZ_SENSOR_VERSION is set."
      exit 1;
    fi

    # explicitly disable auto-update in case the version is fixed
    if [ -n "$WIZ_SENSOR_VERSION" ]; then
      export WIZ_AUTOUPDATE="false"
    fi
  fi
}

create_config_file() {
  CONFIG_FILE=${SENSOR_DIR}/config.yaml
  WIZ_ENV_VARS=$(env | grep '^WIZ_' | sed -e 's/^WIZ_//' -e 's/^\([^=]*\)=\(.*\)$/\1: \2/')

  echo "${WIZ_ENV_VARS}" > "$CONFIG_FILE"
  echo "SCRIPT_VERSION: 1.0.3045" >> "$CONFIG_FILE"
  chown "root:root" "$CONFIG_FILE"
  chmod 400 "$CONFIG_FILE"
}

install_repository_package_redhat() {
  info "Installing YUM sources for Wiz"
  ARCHI=$(uname -m)

  cat << EOF > /etc/yum.repos.d/wiz.repo
[wiz]
name=Wiz, Inc.
baseurl=${YUM_URL}/${YUM_CHANNEL}
enabled=1
gpgcheck=${YUM_GPGCHECK}
repo_gpgcheck=0
priority=1
gpgkey=${YUM_KEY_URL}
EOF

  package="wiz-sensor"
  if [ -n "$WIZ_SENSOR_VERSION" ]; then
    package+="-$WIZ_SENSOR_VERSION"
  fi

  if [ -f "/usr/bin/dnf" ]; then
    dnf -y clean metadata
    dnf -y --disablerepo='*' --enablerepo='wiz' install --best "$package" || dnf -y install --best "$package"
  else
    yum -y clean metadata
    yum -y --disablerepo='*' --enablerepo='wiz' install "$package" || yum -y install "$package"
  fi
}

install_repository_package_suse() {
  # Install yum repo for Wiz
  cat << EOF > /etc/zypp/repos.d/wiz.repo
[wiz]
name=Wiz, Inc.
baseurl=${YUM_URL}/${YUM_CHANNEL}
enabled=1
gpgcheck=${YUM_GPGCHECK}
repo_gpgcheck=0
priority=1
gpgkey=${YUM_KEY_URL}
EOF

  zypper --non-interactive --gpg-auto-import-keys refresh wiz

  package="wiz-sensor"
  if [ -n "$WIZ_SENSOR_VERSION" ]; then
    package+="-$WIZ_SENSOR_VERSION"
  fi

  zypper --non-interactive --gpg-auto-import-keys install -r wiz "$package"
}

install_repository_package_debian() {
  apt_trusted_d_keyring="/etc/apt/trusted.gpg.d/wiz-archive-keyring.gpg"
  apt_usr_share_keyring="/usr/share/keyrings/wiz-archive-keyring.gpg"

  info "Installing apt-transport-https and gnupg"
  apt-get update || warn "'apt-get update' failed, the script will not install the latest version of apt-transport-https\n"
  apt-get install -y apt-transport-https gnupg

  info "Installing APT sources for Wiz"
  sh -c "echo 'deb [signed-by=${apt_usr_share_keyring}] ${APT_URL}/ ${APT_CHANNEL} main' > /etc/apt/sources.list.d/wiz.list"

  if [ ! -f $apt_usr_share_keyring ]; then
      touch $apt_usr_share_keyring
  fi
  # ensure that the _apt user used on Ubuntu/Debian systems to read GPG keyrings
  # can read our keyring
  chmod a+r $apt_usr_share_keyring

  curl --retry 5 -o "/tmp/wiz_repo_public_key.gpg" "${APT_KEY_URL}"
  cat "/tmp/wiz_repo_public_key.gpg" | gpg --import --batch --no-default-keyring --keyring "$apt_usr_share_keyring"

  release_version="$(grep VERSION_ID /etc/os-release | cut -d = -f 2 | xargs echo | cut -d "." -f 1)"
  if { [ "$DISTRIBUTION" == "Debian" ] && [ "$release_version" -lt 9 ]; } || \
  { [ "$DISTRIBUTION" == "Ubuntu" ] && [ "$release_version" -lt 16 ]; }; then
      # copy with -a to preserve file permissions
      cp -a $apt_usr_share_keyring $apt_trusted_d_keyring
  fi

  apt-get update -o Dir::Etc::sourcelist="sources.list.d/wiz.list" -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"

  package="wiz-sensor"
  if [ -n "$WIZ_SENSOR_VERSION" ]; then
    package+="=$WIZ_SENSOR_VERSION"
  fi

  apt-get install -y --force-yes "$package"
}

install_package() {
  if [ "$OS" = "RedHat" ]; then
    install_repository_package_redhat
  elif [ "$OS" = "SUSE" ]; then
    install_repository_package_suse
  elif [ "$OS" = "Debian" ]; then
    install_repository_package_debian
  elif [[ "$DOCKER_ONLY_OS_LIST" =~ "$OS" ]]; then
    error "$OS only supports Docker installation. Please set DOCKER_INSTALL=1 and try again."
    exit 1
  fi
}

create_env_file() {
  ENV_FILE=${SENSOR_DIR}/sensor_config.env
  WIZ_ENV_VARS=$(env | grep '^WIZ_' | sed -e 's/^WIZ_//' -e 's/^\([^=]*\)=\(.*\)$/\1=\2/')

  cat << EOF > "$ENV_FILE"
RUST_BACKTRACE=full
WIZ_HOST_STORE=/wiz-host-cache/
WIZ_TMP_STORE=/wiz-host-cache/tmp_store/
WIZ_RAMFS_STORE=/tmp/ramfs/
SENSOR_TYPE=$( [ "${IS_GCOS}" -eq 1 ] && echo "gcos" || echo "container" )
LOG_FILE=/wiz-host-cache/sensor_logs/sensor.log
SCRIPT_VERSION=1.0.3045
${WIZ_ENV_VARS}
EOF

  chown "root:root" "${ENV_FILE}"
  chmod 400 "${ENV_FILE}"
}

install_docker_container() {
  if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Please install Docker and try again."
    exit 1
  fi

  if ! docker info &>/dev/null; then
    error "Docker is not running. Please start Docker and try again."
    exit 1
  fi

  if ! has_systemd; then
    error "Systemd is not installed. Please install Systemd and try again."
    exit 1
  fi

  export DOCKER_CONFIG=${WIZ_DIR}/sensor/docker-config

  if [ "$CONTAINER_REGISTRY_LOGIN" -eq 1 ]; then
    if [[ -z "$PULL_USERNAME" ||  -z "$PULL_PASSWORD" ]]; then
      error "Missing PULL_USERNAME or PULL_PASSWORD environment variables."
      exit 1
    fi

    login_successful=$(timeout 5 docker login "$CONTAINER_REGISTRY" -u "$PULL_USERNAME" -p "$PULL_PASSWORD" > /dev/null 2>&1 && echo 1 || echo 0)
    if [ $login_successful -eq 0 ]; then
      error "Failed to login to Wiz container registry."
      exit 1
    fi
  fi

  docker_path=$(which docker 2>/dev/null || echo "/usr/bin/docker")
  cat << EOF > /etc/systemd/system/wiz-sensor.service
[Unit]
Description=Wiz Sensor
After=docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=15
TimeoutStartSec=0

Environment=DOCKER_CONFIG=${DOCKER_CONFIG}
ExecStartPre=-${docker_path} pull ${CONTAINER_REGISTRY}/sensor:${WIZ_SENSOR_VERSION}
ExecStartPre=-${docker_path} kill wiz-sensor
ExecStartPre=-${docker_path} rm wiz-sensor
ExecStart=${docker_path} run --name wiz-sensor \\
    --restart unless-stopped \\
    --mount type=bind,source=/sys/kernel/debug,target=/sys/kernel/debug,readonly \\
    --mount type=tmpfs,destination=/tmp,tmpfs-size=100m \\
    --env-file ${ENV_FILE} \\
    -v ${SENSOR_DIR}:/wiz-host-cache \\
    -u 2202:2202 \\
    --cgroupns host \\
    --pid host \\
    --ipc host \\
    --network host \\
    --read-only \\
    --security-opt apparmor=unconfined \\
    --security-opt seccomp=unconfined \\
    --security-opt label:disable \\
    --cap-add=SYS_ADMIN \\
    --cap-add=SYS_CHROOT \\
    --cap-add=SYS_RESOURCE \\
    --cap-add=SYS_RAWIO \\
    --cap-add=DAC_OVERRIDE \\
    --cap-add=DAC_READ_SEARCH \\
    --cap-add=NET_ADMIN \\
    --cap-add=NET_RAW \\
    --cap-add=IPC_LOCK \\
    --cap-add=FOWNER \\
    --cap-add=SYS_PTRACE \\
    --cap-add=KILL \\
    ${CONTAINER_REGISTRY}/sensor:${WIZ_SENSOR_VERSION}
ExecStop=${docker_path} kill wiz-sensor

[Install]
WantedBy=multi-user.target
EOF

}

silent() {
  "$@" > /dev/null 2>&1
}

has_systemd() {
  [ -d "/lib/systemd/system/" -o -d "/usr/lib/systemd/system" ] && silent which systemctl
}

has_upstart() {
  [ -d "/etc/init" ] && silent which initctl
}

has_launchd() {
  [ -d "/Library/LaunchDaemons" ] && silent which launchtl
}

has_sysv() {
  [ -d "/etc/init.d" ]
}

enable_service() {
  case $platform in
    systemd) systemctl enable wiz-sensor.service ;;
  esac
}

enable_sensor_service() {
  platforms="systemd upstart launchd sysv"
  for platform in $platforms ; do
    if has_$platform ; then
      enable_service $platform
      break
    fi
  done
}

start_service() {
  case $platform in
    systemd) systemctl start wiz-sensor.service ;;
    upstart) initctl start wiz-sensor ;;
    launchd) launchctl start wiz-sensor ;;
    sysv) /etc/init.d/wiz-sensor start ;;
  esac
}

start_sensor_service() {
  if [ "$WIZ_INSTALL_ONLY" = "1" ]; then
    return
  fi

  platforms="systemd upstart launchd sysv"
  for platform in $platforms ; do
    if has_$platform ; then
      start_service $platform
      break
    fi
  done
}

function do_install() {
  print_banner
  check_root
  create_sensor_dir
  setup_logger
  check_update_policy
  check_api_key
  check_arch
  check_kernel_version
  check_os_and_distro
  generate_persistent_id
  select_install_method
  if [ "$DOCKER_INSTALL" = "1" ]; then
    create_env_file
    install_docker_container
  else
    create_config_file
    install_package
  fi
  enable_sensor_service
  start_sensor_service
  completed "Wiz sensor was successfully installed!"
}

set -e
do_install
