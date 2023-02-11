#!/usr/bin/env bash

# Installer script toto turn ubuntu host into docker based server for this project
# To run extract this repository onto a blank ubuntu server and run as root

if [ "$EUID" -ne 0 ]
  then echo "Must be run as root"
  exit
fi

sudo apt-get update
sudo apt-get -y install docker.io docker-compose awscli
docker-compose up -d
echo "complete" > /opt/status
chmod 666 /opt/status
echo "Services started"

# Required for SSH connectivity from guacd
echo "HostKeyAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config
echo "PubkeyAcceptedAlgorithms +ssh-rsa" >> /etc/ssh/sshd_config
