#!/bin/bash
# To-do: consider add a stricter check; maybe at a
# certain point we want to create several images
if [ -f "$MAIN_HOME/testsuite/image/vm.qcow2" ]; then
	echo "VM image already created"
	exit 0
fi
IMAGE_DIR=$MAIN_HOME/testsuite/image/
pushd $IMAGE_DIR > /dev/null
./create-image.sh
qemu-img convert -f raw -O qcow2 stretch.img vm.qcow2

popd
