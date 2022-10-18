#!/bin/bash

CUR_DIR="$(readlink -f $(dirname "$0"))"
source $CUR_DIR/../script/common.sh

# Install Go.
$MAIN_HOME/prerequisite/go/install.sh
RES=$?
if [ $RES -ne 0 ]; then
	echo "Failed to install Go!"
fi

# Patch Syzkaller.
$MAIN_HOME/prerequisite/syzkaller/patch.sh

# Build
pushd $MAIN_HOME/executor/libsclog > /dev/null
./build.sh
popd
pushd $MAIN_HOME > /dev/null
make
pushd $MAIN_HOME/testsuite/kernel-memory-acccess-tracing/gcc > /dev/null
./contrib/download_prerequisites
mkdir build
cd build
$PWD/../configure --prefix=$CC_MT --enable-languages=c,c++
make -j`nproc`
make install