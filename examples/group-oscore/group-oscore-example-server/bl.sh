#!/bin/bash
#strip .c from file
FILE=$1
TARGET="${FILE%%.*}"
echo "Target: $TARGET"
echo "Device: $2"
make TARGET=zoul BOARD=firefly-reva $TARGET.upload PORT=/dev/$2
make TARGET=zoul BOARD=firefly-reva login PORT=/dev/$2
