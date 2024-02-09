#!/bin/bash
# --------------------
# Run this script to delete downloaded kernel sources
# --------------------
source ./env.sh

if [[ -f ${LS_KERNEL_TARXZ} ]]; then
    echo "Deleting ${LS_KERNEL_TARXZ}"
    rm -rf ${LS_KERNEL_TARXZ}
fi

if [[ -d "${LS_PATH}/linux" ]]; then
    echo "Deleting ${LS_PATH}/linux"
    rm -rf "${LS_PATH}/linux"
fi

echo "Finished cleaning up."
