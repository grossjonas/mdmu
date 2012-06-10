#!/bin/bash

for lib in libnfc nfc-tools libndef mfcuk
do
	if [ ! -d ${lib} ]; then
		svn co http://${lib}.googlecode.com/svn/trunk/ ${lib}
	else
		echo $lib hab ich scho
	fi
done
