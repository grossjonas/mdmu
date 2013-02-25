#!/bin/bash

workingDir=`pwd`

baseDir="nfclibs"

mkdir -p ${baseDir}
cd "${workingDir}/${baseDir}"

for lib in nfc-tools libndef mfcuk mtools
do
	tmpDir="${workingDir}/${baseDir}/${lib}"
	if [[ ! -d ${tmpDir} ]]
	then
		svn co http://${lib}.googlecode.com/svn/trunk/ ${tmpDir}
	else
		echo "${lib} already exists in ${tmpDir} - trying to update" >&2
		svn up ${tmpDir}
	fi
done

for lib in libnfc libfreefare qnfcd mfoc ifdnfc 
do
	tmpDir="${workingDir}/${baseDir}/${lib}"
	if [[ ! -d ${tmpDir} ]]
	then
		git clone https://code.google.com/p/${lib}/ ${tmpDir}
	else
		echo ${lib} already exists in ${tmpDir} - trying to pull >&2
		cd ${tmpDir}
		git pull	
	fi
done

cd ${workingDir}

