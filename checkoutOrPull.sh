#!/bin/bash

workingDir=$(pwd)

baseDir="nfc-tools"

mkdir -p ${baseDir}
cd "${workingDir}/${baseDir}"

# TODO: mtools
for lib in libnfc libfreefare qnfcd mfoc ifdnfc nfcutils libndef mfcuk pam_nfc
do
	tmpDir="${workingDir}/${baseDir}/${lib}"
	if [[ ! -d ${tmpDir} ]]
	then
		git clone https://github.com/nfc-tools/${lib}/ ${tmpDir}
	else
		echo ${lib} already exists in ${tmpDir} - trying to pull >&2
		cd ${tmpDir}
		git pull
	fi
done

cd ${workingDir}

