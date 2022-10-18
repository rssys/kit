BUILDOS := $(shell go env GOOS)
BUILDARCH := $(shell go env GOARCH)
HOSTOS ?= $(BUILDOS)
HOSTARCH ?= $(BUILDARCH)
TARGETOS ?= $(HOSTOS)
TARGETARCH ?= $(HOSTARCH)
TARGETVMARCH ?= $(TARGETARCH)

GO := go
GOFLAGS := "-ldflags=-s -w"
GOHOSTFLAGS := $(GOFLAGS)
GOTARGETFLAGS := $(GOFLAGS)

LIBSCLOGFLAGS :=  -lrt -lselinux -lsepol

.PHONY: all clean syzkaller executord executor manager

all: syzkaller executord executor executorcd manager resanalyze pmcpc memtracedump pmcrand predstat

syzkaller:
	$(MAKE) -C ./syzkaller executor

executord: syzkaller
	mkdir -p ./bin
	GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) $(GO) build $(GOTARGETFLAGS) -o ./bin/executord github.com/rss/kit/executord

# compile flags are copied from syzkaller Makefile
executor: syzkaller
	cp ./syzkaller/executor/syscalls.h ./executor
	cp ./syzkaller/executor/defs.h ./executor
	cp ./syzkaller/executor/common_usb_linux.h ./executor
	cp ./syzkaller/executor/common_usb.h ./executor
	cp ./syzkaller/executor/kvm.h ./executor
	cp ./syzkaller/executor/common_kvm_amd64.h ./executor
	cp ./syzkaller/executor/kvm_amd64.S.h ./executor
	cp -r ./syzkaller/executor/android ./executor
	cp ./syzkaller/executor/cov_filter.h ./executor
	cp ./syzkaller/executor/test.h ./executor
	cp ./syzkaller/executor/test_linux.h ./executor
	$(CC) -o ./bin/executor ./executor/executor.cc executor/libsclog/libsclog.a \
		-m64 -O2 -pthread -Wall -Werror -Wparentheses -Wunused-const-variable -Wframe-larger-than=16384 -static-pie \
		-DGOOS_$(TARGETOS)=1 -DGOARCH_$(TARGETARCH)=1 \
		-DHOSTGOOS_$(HOSTOS)=1 \
		$(LIBSCLOGFLAGS)

manager: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/manager github.com/rss/kit/manager

pmcpc: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/pmcpc github.com/rss/kit/tools/pmcpc

pmcrand: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/pmcrand github.com/rss/kit/tools/pmcrand
	
resanalyze: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/resanalyze github.com/rss/kit/tools/resanalyze

memtracedump: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/memtracedump github.com/rss/kit/tools/memtracedump

predstat: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/predstat github.com/rss/kit/tools/predstat

executorcd: syzkaller
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOHOSTFLAGS) -o ./bin/executorcd github.com/rss/kit/executorcd

clean:
	$(MAKE) -C ./syzkaller clean 
	rm -rf ./bin
	rm ./executor/syscalls.h
	rm ./executor/defs.h
	rm ./executor/common_usb.h
	rm ./executor/common_usb_linux.h
	rm ./executor/common_kvm_amd64.h
	rm ./executor/kvm.h
	rm ./executor/kvm_amd64.S.h
	rm -r ./executor/android
	rm ./executor/cov_filter.h
	rm ./executor/test.h
	rm ./executor/test_linux.h
