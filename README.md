# DINT

This is an implementation of accelerating distributed database transactions using eBPF, as described in the paper [DINT: Fast In-Kernel Distributed Transactions with eBPF](https://www.usenix.org/conference/nsdi24/presentation/zhou-yang) from NSDI 2024.

## Content

- **caladan/** contains the source code of Caladan [OSDI '20].
- **exp/** contains experiment scripts.

### Microbenchmarks

- **lock_2pl/** contains the code for the lock server and client (only with Caladan) running the two-phase locking protocol.
- **lock_fasst/** contains the code for the lock server and client running the FaSST protocol.
- **log_server/** contains the code for the log server and client.
- **store/** contains the code for the key-value store server and client.

In these microbenchmarks, servers are implemented with UDP, Caladan, eBPF for evaluation, while clients are only implemented with Caladan. We also have a write-through eBPF key-value store server and a write-back one without bloom filters, for ablation testing.

### Transaction workloads

+ **smallbank/** contains the code for the server and client of Smallbank (see section III of [this](https://www.comp.nus.edu.sg/~cs5226/papers/si-cost-icde08.pdf) paper).
+ **tatp/** contains the code for the server and client of [TATP](https://en.wikipedia.org/wiki/TATP_Benchmark).

We have in addition a DPDK server for TATP to compare its performance with eBPF.

## Preparing

We did our experiment in [Cloudlab](https://cloudlab.us/) by using the `r650` machines from Clemson. The initial Disk Image is `UBUNTU20-64-STD`.

### Kernel version

We use kernel version `5.8.0` for Caladan and DPDK code, and `6.1.0` for eBPF and UDP code. Please update the kernel for each machine:

```
  wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
  sudo bash ubuntu-mainline-kernel.sh -i [5.8.0|6.1.0]
  sudo reboot
```

You can check your kernel version by `uname -r`. After rebooting, the result should be `5.8.0-050800-generic` or `6.1.0-060100-generic`.

In one experiment, all machines don't necessarily have the same kernel version. For instance, we have 3 servers and 10 clients when testing the TATP eBPF server. The servers are in eBPF, therefore should run kernel `6.1.0`, while the clients are written with Caladan and should run kernel `5.8.0`. Please refer to the paper for experimental settings.

### Setting up machines

Run the following to setup the machine and install the required packages.

```
  sudo add-apt-repository ppa:git-core/ppa -y
  sudo apt update

  sudo apt install gpg curl tar xz-utils flex bison libssl-dev libelf-dev libnuma-dev -y
  sudo apt install make gcc cmake meson llvm-9 clang-9 python3-pyelftools -y

  wget https://apt.llvm.org/llvm.sh
  chmod +x llvm.sh
  sudo ./llvm.sh 16
  rm llvm.sh
```

We recommend cloning this repo into `~/dev/` to use our scripts for experiments. To avoid running out of storage, run the following to mount the device `/dev/sda4` onto `~/dev/` .

```
  sudo mkfs -t ext4 /dev/sda4
  sudo mount /dev/sda4 ~/dev
  sudo chown [username] ~/dev
```

Remember to remount each time the machine reboots.

We provided a script, `cpu_setup.sh` (as follows), to configure the NIC (disable adaptive batching and irqbalance, and setup IR queue mapping). It is integrated in our experiment scripts so you don't need to run it.

```
  ncpu=$1

  sudo ifconfig ens2f0np0 mtu 3000 up
  sudo ethtool -C ens2f0np0 adaptive-rx off adaptive-tx off rx-usecs 0 rx-frames 1 tx-usecs 0 tx-frames 1
  sudo ethtool -C ens2f0np0 adaptive-rx off adaptive-tx off rx-usecs 0 rx-frames 1 tx-usecs 0 tx-frames 1
  sudo service irqbalance stop

  sudo ethtool -N ens2f0np0 rx-flow-hash udp4 sdfn
  sudo ethtool -L ens2f0np0 combined $ncpu

  (let cnt=0; cd /sys/class/net/ens2f0np0/device/msi_irqs/;
    for IRQ in *; do
      let CPU=$((cnt*2+3))
      let cnt=$(((cnt+1)%ncpu))
      echo $IRQ '->' $CPU
      echo $CPU | sudo tee /proc/irq/$IRQ/smp_affinity_list > /dev/null
  done)
```

Before running the TATP DPDK experiment, you should setup `r650`'s Mellanox NIC for DPDK by installing the DPDK driver, as follows.

```
  wget https://content.mellanox.com/ofed/MLNX_OFED-4.9-5.1.0.0/MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu20.04-x86_64.tgz
  tar -xvzf MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu20.04-x86_64.tgz
  cd MLNX_OFED_LINUX-4.9-5.1.0.0-ubuntu20.04-x86_64
  sudo ./mlnxofedinstall --upstream-libs --dpdk
  sudo /etc/init.d/openibd restart
  sudo reboot
```

### Building

#### eBPF

To build eBPF code within directory `foo/ebpf/`, run the following from root of this repo.

```
  ./kernel-src-download.sh foo 6.1
  ./kernel-src-prepare.sh foo 6.1
  make -C foo/ebpf -j
```

For example, to build the eBPF code for SmallBank, run the following.

```
  ./kernel-src-download.sh smallbank 6.1
  ./kernel-src-prepare.sh smallbank 6.1
  make -C smallbank/ebpf -j
```

#### UDP

To build UDP code within `foo/udp/`, run the following.

```
  make -C foo/udp -j
```

#### Caladan and DPDK

First build Caladan and its submodules (and set up huge pages) by running the `init_submodules.sh` script in the root of this repo.

After that, run the following to build Caladan or DPDK code within `foo/caladan` or `foo/dpdk`.

```
  make -C foo/[caladan|dpdk] -j
```

### Generating traces

Microbenchmark clients depend on traces generated before running. To generate traces, run the following on each client machine.

```
  pushd lock_2pl/caladan && ./trace_init.sh 24000000 0.8 4800 && popd
  pushd lock_fasst/caladan && ./trace_init.sh 24000000 0.8 4800 && popd
  pushd log_server/caladan && ./trace_init.sh 4800 && popd
```

### Caladan config files

Caladan clients need config files to run correctly, and we provided templates in each caladan code subdirectory (e.g. `lock_2pl/caladan/client.config`). Refer to [Caladan](https://github.com/shenango/caladan) for more information.

Please add necessary static ARP entries. For microbenchmarks we have only 1 server, so a single entry for `10.10.1.1` should be added to all clients. For transaction workloads we have 3 servers, so ARP entries for `10.10.1.1`, `10.10.1.2`, and `10.10.1.3` are needed.

Remember to set proper number of cores for the `runtime_kthreads`, `runtime_spinning_kthreads` and `runtime_guaranteed_kthreads` fields. Typically, we use 8 cores for servers and 64 for clients. Please refer to the paper for details.

## Running microbenchmarks

After setting up all machines, building binaries, generating traces and writing config files, edit the hostnames in `exp/run_all.sh`, `exp/run_lock_2pl.sh`, `exp/run_lock_fasst.sh`, `exp/run_log_server.sh` and `exp/run_store.sh`. We provided a `exp/kill_all.sh` utility to conveniently terminate all running experiments. The hostnames in it also need editing.

Then, simply run the following from `exp/` and wait for the results in `exp/results/`. A single run takes around 1 hour.

```
  nohup ./run_all.sh &
```

## Running Smallbank and TATP

Similar to microbenchmarks, you should edit the hostnames in `exp/run_smallbank.sh`, `exp/run_smallbank_wrapper.sh`, `exp/run_tatp.sh`, `exp/run_tatp_colocate.sh`, `exp/run_tatp_cpu.sh`, `exp/run_tatp_wrapper.sh`. Run the following after that and wait for the results in `exp/results/`.

```
  nohup ./run_[smallbank|tatp]_wrapper.sh &
```

### Warning

eBPF and caladan tests use different kernel versions, so you should run them separately by commenting out parts of `exp/run_all.sh`, `exp/run_smallbank_wrapper.sh` or `exp/run_tatp_wrapper.sh`.