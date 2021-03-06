#! /bin/sh

#exit on error
set -e

for test in 1 2 3 4; do
cd coap-test-server
sudo make TARGET=zoul BOARD=firefly-reva clean
sudo make TARGET=zoul BOARD=firefly-reva TEST=$test
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 clean
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 TEST=$test
cd ..

cd group-coap-test-server
sudo make TARGET=zoul BOARD=firefly-reva clean
sudo make TARGET=zoul BOARD=firefly-reva TEST=$test
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 clean
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 TEST=$test
cd ..

cd oscore-test-server
sudo make TARGET=zoul BOARD=firefly-reva clean
sudo make TARGET=zoul BOARD=firefly-reva MAKE_WITH_HW_CRYPTO=1 TEST=$test
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 clean
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 MAKE_WITH_HW_CRYPTO=1 TEST=$test

sudo make TARGET=zoul BOARD=firefly-reva clean
sudo make TARGET=zoul BOARD=firefly-reva MAKE_WITH_HW_CRYPTO=0 TEST=$test
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 clean
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 MAKE_WITH_HW_CRYPTO=0 TEST=$test
cd ..

cd group-oscore-test-server
sudo make TARGET=zoul BOARD=firefly-reva clean
sudo make TARGET=zoul BOARD=firefly-reva MAKE_WITH_HW_CRYPTO=1 TEST=$test
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 clean
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 MAKE_WITH_HW_CRYPTO=1 TEST=$test

sudo make TARGET=zoul BOARD=firefly-reva clean
sudo make TARGET=zoul BOARD=firefly-reva MAKE_WITH_HW_CRYPTO=0 TEST=$test 
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 clean
sudo make TARGET=simplelink BOARD=launchpad/cc1352r1 MAKE_WITH_HW_CRYPTO=0 TEST=$test
cd ..
done
