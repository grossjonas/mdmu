#!/bin/bash

workingDir=`pwd`

baseDir="nfclibs"

mkdir ${baseDir}

for lib in libnfc nfc-tools libndef mfcuk mtools
do
	tmpDir=${baseDir}"/"${lib}
	if [[ ! -d ${tmpDir} ]]
	then
		svn co http://${lib}.googlecode.com/svn/trunk/ ${tmpDir}
	else
		echo "${lib} already exists"
	fi
done

cd ${workingDir}"/"${baseDir}
for lib in libfreefare qnfcd mfoc ifdnfc 
do
	git clone https://code.google.com/p/${lib}/
done

cd ${workingDir}
