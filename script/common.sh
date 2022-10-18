export MAIN_HOME=$(readlink -f  $(dirname $BASH_SOURCE)/../)
export GOPATH=$MAIN_HOME/prerequisite/go/gopath/
export GOROOT=$MAIN_HOME/prerequisite/go/goroot/
export PATH=$GOPATH/bin:$PATH
export PATH=$GOROOT/bin:$PATH
export CC_MT=$MAIN_HOME/testsuite/kernel-memory-acccess-tracing/gcc-memtrace