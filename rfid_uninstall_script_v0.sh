#!/bin/bash

echo "### libnfc ####################"
cd libnfc/

sudo make uninstall

cd ..

echo "### libndef ####################"

cd libndef

sudo make uninstall

cd ..

echo "#### nfc-tools ####################"

cd nfc-tools

echo "### libfreefare --------------------"
cd libfreefare

sudo make uninstall

cd ..

echo "### pam_nfc --------------------"
cd pam_nfc

sudo make uninstall

cd ..

echo "### nfcutils --------------------"

cd nfcutils

sudo make uninstall

cd ..


echo "### nfc-eventd --------------------"

cd nfc-eventd

sudo make uninstall

cd ..

echo "## nfcd --------------------"
cd nfcd
cd build
sudo xargs rm < install_manifest.txt
cd ..
cd ..

echo "### desknfc --------------------"
cd desknfc
cd build
sudo xargs rm < install_manifest.txt
cd ..
cd ..

echo "### mfoc --------------------"
cd mfoc

sudo make uninstall

cd ..

