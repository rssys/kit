#!/bin/bash
qemu-system-x86_64 \
	-m 2G \
	-smp 1 \
	-kernel $1/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 nokaslr" \
	-drive file=$2,format=qcow2 \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-nographic \
	-enable-kvm \
	-pidfile vm.pid \
	-snapshot \
	2>&1 | tee vm.log2
	# -s -S \