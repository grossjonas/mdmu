#!/bin/bash

sudo apt-get install libusb-dev libpcsclite-dev libpam0g-dev libusb-0.1-4 libpcsclite1 libccid pcscd libssl-dev kdelibs5-dev autoconf libtool libc6-dbg g++

sudo su -c 'echo /usr/local/lib >> /etc/ld.so.conf'
sudo ldconfig -v


#sudo fink install libpcsclite-dev libpam0g-dev libusb-0.1-4 libpcsclite1 libccid pcscd libssl-dev kdelibs5-dev autoconf libtool
