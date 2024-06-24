# Install and configure a Wiz Sensor
# You should feel free to expand on this and document any parameters etc

# Create Sensor Directory

file { 'sensor_directory':
  ensure => directory,
  path   => '/opt/wiz/',
}
