#!/bin/bash

sudo apt-get install libusb-dev libpcsclite-dev libpam0g-dev libusb-0.1-4 libpcsclite1 libccid pcscd libssl-dev kdelibs5-dev autoconf libtool libc6-dbg g++

sudo su -c 'mkdir -p /usr/local/lib'
sudo su -c 'mkdir -p /usr/local/lib/security'
sudo su -c 'mkdir -p /usr/local/lib/nfc-eventd/modules'

sudo su -c 'echo /usr/local/lib >> /etc/ld.so.conf'
sudo su -c 'echo /usr/local/lib/security >> /etc/ld.so.conf'
sudo su -c 'echo /usr/local/lib/nfc-eventd/modules >> /etc/ld.so.conf'
sudo ldconfig -v


#sudo fink install libpcsclite-dev libpam0g-dev libusb-0.1-4 libpcsclite1 libccid pcscd libssl-dev kdelibs5-dev autoconf libtool
