#!/bin/bash

echo "### libnfc ####################"
cd libnfc/

## Normale Installation
#autoreconf -vis && ./configure --prefix=/usr/local && make && sudo make install
## Mit Documentation
#autoreconf -vis && ./configure --prefix=/usr/local --enable-doc && make && sudo make install
## Für die Benutzung mit gdb
#autoreconf -vis && CFLAGS="-g -Wall -pedantic -O0 -ggdb" ./configure --prefix=/usr/local && make clean all && sudo make install
## Um traces zu beobachten
autoreconf -vis && ./configure --prefix=/usr/local --enable-debug && make clean all && sudo make install
#autoreconf -vis && ./configure --prefix=/usr/local --disable-debug && make && sudo make install

cd ..

echo "### libndef ####################"

cd libndef

qmake && make && sudo make install

cd ..

echo "#### nfc-tools ####################"

cd nfc-tools

echo "### libfreefare --------------------"
cd libfreefare

autoreconf -vis && ./configure --prefix=/usr/local && make && sudo make install
#autoreconf -vis && ./configure --prefix=/usr/local --enable-debug && make && sudo make install

cd ..

echo "### nfcutils --------------------"

cd nfcutils

autoreconf -vis && ./configure --prefix=/usr/local  && make && sudo make install
#autoreconf -vis && ./configure --prefix=/usr/local --enable-debug && make && sudo make install

cd ..


echo "### pam_nfc --------------------"
cd pam_nfc

autoreconf -vis && ./configure --prefix=/usr/local --sysconfdir=/etc --with-pam-dir=/usr/local/lib/security && make && sudo make install

cd ..

echo "### nfc-eventd --------------------"

cd nfc-eventd

autoreconf -vis && ./configure --prefix=/usr/local  && make && sudo make install
#autoreconf -vis && ./configure --prefix=/usr/local --enable-debug && make && sudo make install

cd ..

echo "### nfcd --------------------"
cd nfcd

mkdir -p build 
cd build/ 
#cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && make && sudo make install && sudo cp ../nfcd.conf /etc/dbus-1/system.d/ 
#cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Debug && make && sudo make install && sudo cp ../nfcd.conf /etc/dbus-1/system.d/ 
cd ..
cd ..

echo "### desknfc --------------------"
cd desknfc

mkdir -p build 
cd build
#cmake .. -DCMAKE_INSTALL_PREFIX=`kde4-config --prefix` && make && sudo make install 
cd ..
cd ..

echo "### mfoc --------------------"
cd mfoc

autoreconf -vis && ./configure --prefix=/usr/local && make && sudo make install

cd ..

echo "## mfcuk --------------------"
cd ..
cd mfcuk

autoreconf -vis && ./configure --prefix=/usr/local && make && sudo make install

cd ..

