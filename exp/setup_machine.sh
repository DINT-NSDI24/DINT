#!/bin/bash

# git clone https://github.com/xyxiang7/dotfiles.git && cd dotfiles/sys && ./linux-version.sh 6.1.0
# Wait for machine reboot

sudo add-apt-repository ppa:git-core/ppa -y
sudo apt update

sudo apt install git byobu htop clang-format -y
sudo apt install gpg curl tar xz-utils flex bison libssl-dev libelf-dev libnuma-dev -y
sudo apt install make gcc cmake meson llvm-9 clang-9 python3-pyelftools -y

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 16
rm llvm.sh
