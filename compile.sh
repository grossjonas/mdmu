#!/bin/bash

myPrefix="/usr/local"
myWorkingDir=$(pwd)
myNfcLibDir="nfc-tools"
myDir="${myWorkingDir}/${myNfcLibDir}/"
echo ${myDir}

echo "### libnfc ####################"
cd "${myDir}/libnfc/"

## normal installation
autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install
## with documentation
#autoreconf -vis && ./configure --prefix=${myPrefix} --enable-doc && make && sudo make install
## with gdb
#autoreconf -vis && CFLAGS="-g -Wall -pedantic -O0 -ggdb" ./configure --prefix=${myPrefix} && make clean all && sudo make install
## with traces
#autoreconf -vis && ./configure --prefix=${myPrefix} --enable-debug --with-drivers='all' && make clean all && sudo make install
#autoreconf -vis && ./configure --prefix=${myPrefix} --disable-debug && make && sudo make install

cd ${myDir}

echo "### libfreefare ####################"
cd "${myDir}/libfreefare"

autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install
#autoreconf -vis && ./configure --prefix=${myPrefix} --enable-debug && make && sudo make install

cd ${myDir}

echo "### libndef ####################"

cd "${myDir}/libndef"

#qmake PREFIX=${myPrefix} && make && sudo make install

cd ${myDir}

echo "### ifdnfc ####################"

cd "${myDir}/ifdnfc"

#autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install

cd ${myDir}

echo "## mfcuk ####################"
cd "${myDir}/mfcuk"

#autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install

cd ${myDir}

echo "### mfoc ####################"
cd "${myDir}/mfoc"

#autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install

cd ${myDir}

#TODO:
#echo "### mtools ####################"
#cd "${myDir}/mtools/mtools"

#autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install

#cd ${myDir}

echo "### qnfcd ####################"
cd "${myDir}/qnfcd"

#autoreconf -vis && ./configure --prefix=${myPrefix} && make && sudo make install

cd ${myDir}

echo "### nfcutils --------------------"

cd "${myDir}/nfcutils"

#autoreconf -vis && ./configure --prefix=${myPrefix}  && make && sudo make install
#autoreconf -vis && ./configure --prefix=${myPrefix} --enable-debug && make && sudo make install

cd ${myDir}

echo "### pam_nfc --------------------"
cd "${myDir}/pam_nfc"

#autoreconf -vis && ./configure --prefix=${myPrefix} --sysconfdir=/etc --with-pam-dir=/usr/local/lib/security && make && sudo make install

cd ${myDir}

echo "### nfc-eventd --------------------"

cd "${myDir}/nfc-eventd"

#autoreconf -vis && ./configure --prefix=${myPrefix}  && make && sudo make install
#autoreconf -vis && ./configure --prefix=${myPrefix} --enable-debug && make && sudo make install

#echo "### nfcd --------------------"
#cd "${myDir}/nfcd"

#mkdir -p build 
#cd build/ 
#cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && make && sudo make install && sudo cp ../nfcd.conf /etc/dbus-1/system.d/ 
#cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Debug && make && sudo make install && sudo cp ../nfcd.conf /etc/dbus-1/system.d/ 

#echo "### desknfc --------------------"
#cd "${myDir}/nfc-tools/desknfc"

#mkdir -p build 
#cd build
#cmake .. -DCMAKE_INSTALL_PREFIX=`kde4-config --prefix` && make && sudo make install 
#cd ..
#cd ..

