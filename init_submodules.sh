#!/bin/bash

sudo apt install make gcc cmake pkg-config libnl-3-dev libnl-route-3-dev libnuma-dev uuid-dev libssl-dev libaio-dev libcunit1-dev libclang-dev libncurses-dev meson python3-pyelftools -y

pushd caladan
make submodules -j
make clean && make -j
pushd ksched
make clean && make -j
popd
sudo ./scripts/setup_machine.sh
make -C bindings/cc -j
popd
