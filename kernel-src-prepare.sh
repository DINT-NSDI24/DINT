#!/bin/bash
# --------------------
# Run this script to extract and generate kernel sources files required to compile BMC
# --------------------
source ./env.sh

echo "Extracting kernel sources to ${LS_PATH}/linux"
if tar xf ${LS_KERNEL_TARXZ} -C ${LS_PATH} && mv ${LS_PATH}/linux-${LS_KERNEL_VERSION} ${LS_PATH}/linux; then
	echo "Successfully extracted kernel sources to ${LS_PATH}/linux"
else
	echo "Failed to extract kernel sources"
	exit 1
fi

echo "Preparing kernel sources"
if make -C ${LS_PATH}/linux defconfig && make -C ${LS_PATH}/linux prepare; then
	echo "Done preparing kernel sources"
else
	echo "Failed to prepare kernel sources"
	exit 1
fi
