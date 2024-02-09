# Makefile for bench
ROOT_PATH=../..

# toolchain definitions
INC = -I.
FLAGS   = -g -Wall -D_GNU_SOURCE $(INC)
LD      = gcc
CC      = gcc
LDXX	  = g++
CXX	    = g++
AR      = ar
SPARSE  = sparse

# dpdk
DPDK_PATH = $(ROOT_PATH)/caladan/dpdk
RDMA_PATH = $(ROOT_PATH)/caladan/rdma-core
PKG_CONFIG_PATH := $(RDMA_PATH)/build/lib/pkgconfig:$(DPDK_PATH)/build/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
CHECKFLAGS = -D__CHECKER__ -Waddress-space

# dpdk libs
DPDK_LIBS=$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs --static libdpdk)

# optimize
FLAGS += -march=native -flto -ffast-math

# debug
# FLAGS += -DDEBUG -rdynamic -O0 -ggdb -mssse3
# LDFLAGS += -rdynamic

# release
FLAGS += -DNDEBUG -O3

# compiler flags
CFLAGS = -std=gnu11 $(FLAGS)
CXXFLAGS = -std=gnu++17 $(FLAGS)

# pthread
CFLAGS += -pthread
CXXFLAGS += -pthread
LDFLAGS += -pthread

server_shard_src = server_shard.cc
server_shard_obj = $(server_shard_src:.cc=.o)
$(server_shard_obj): INC += -I$(DPDK_PATH)/build/include

# must be first
all: server_shard

server_shard: $(server_shard_obj)
	$(LDXX) -o $@ $(server_shard_obj) $(LDFLAGS) $(DPDK_LIBS)

# general build rules for all targets
src = $(server_shard_src)
obj = $(src:.cc=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# prints sparse checker tool output
sparse: $(src)
	$(foreach f,$^,$(SPARSE) $(filter-out -std=gnu11, $(CFLAGS)) $(CHECKFLAGS) $(f);)

.PHONY: clean
clean:
	rm -f $(obj) $(dep) server_shard