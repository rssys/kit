# Kernel Isolation Tester

KIT is a dynamic testing framework that discovers functional interference bugs in Linux containers.

## Getting started

### Prerequisite

**Hardware**: x86-64 CPU (more cores are better); >=128GB memory; >=256GB storage (bare-metal machine recommended);

**Software**: Linux systems with QEMU and KVM support (Ubuntu 22.04 recommended);

KIT only needs root privilege for installing some dependencies and create VM images.

### Download

You can download the code via:

```bash
git clone --recurse-submodules git@github.com:rssys/kit.git
```

### Build

Run following commands to install dependencies:

```shell
# Build KIT
sudo apt-get install make build-essential automake autoconf gcc-multilib g++-multilib libselinux1-dev libselinux1 libsepol-dev libsepol2
# Build customized gcc
sudo apt-get install flex bison
# Build kernel
sudo apt-get install libelf-dev libssl-dev bc
# Build Debian images
sudo apt-get install debootstrap
sudo apt-get install qemu-utils
```

KIT relies on QEMU-KVM to efficiently execute test cases. Please refer to this [link](https://help.ubuntu.com/community/KVM/Installation) for KVM installation and how to run QEMU-KVM as a non-root user. If everything is successfully configured, you should expect the output to be similar to the following when running:

```bash
user@hostname:~$ qemu-system-x86_64 -nographic -enable-kvm
SeaBIOS (version 1.15.0-1)


iPXE (https://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+07F8B470+07ECB470 CA00
                                                                               


Booting from Hard Disk...
Boot failed: could not read the boot disk

Booting from Floppy...
Boot failed: could not read the boot disk


```

Run `prerequisite/setup.sh` to finalize the setup, which includes installing the go compiler, patching the syzkaller code, and building KIT and the customized gcc.

### Kernel

Make sure the following configurations are within the kernel build configuration file:

```shell
# For Debian images
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y

# For host-guest communication
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_CONSOLE=y
```

You might also need to disable SELinux by setting `CONFIG_SECURITY_SELINUX =n`, in case it stops the booting process.

## Publications

* Congyu Liu, Sishuai Gong, Pedro Fonseca. Kit: Testing OS-level Virtualization for Functional Interference Bugs. In *Proceedings of the 28th ACM International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS)*, Vancouver, Canada, 2023