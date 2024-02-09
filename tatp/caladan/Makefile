# Makefile for benchmarks
ROOT_PATH=../../caladan
include $(ROOT_PATH)/build/shared.mk

client_udp_shard_src = client_udp_shard.cc
client_udp_shard_obj = $(client_udp_shard_src:.cc=.o)

client_ebpf_shard_src = client_ebpf_shard.cc
client_ebpf_shard_obj = $(client_ebpf_shard_src:.cc=.o)

client_caladan_shard_src = client_caladan_shard.cc
client_caladan_shard_obj = $(client_caladan_shard_src:.cc=.o)

client_dpdk_shard_src = client_dpdk_shard.cc
client_dpdk_shard_obj = $(client_dpdk_shard_src:.cc=.o)

client_lock_src = client_lock.cc
client_lock_obj = $(client_lock_src:.cc=.o)

server_shard_src = server_shard.cc
server_shard_obj = $(server_shard_src:.cc=.o)

mem_src = mem.c
mem_obj = $(mem_src:.c=.o)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

librt_libs = $(ROOT_PATH)/bindings/cc/librt++.a
INC += -I$(ROOT_PATH)/bindings/cc

# must be first
all: client server

client: client_udp_shard client_ebpf_shard client_caladan_shard client_dpdk_shard client_lock

client_udp_shard: $(client_udp_shard_obj) $(librt_libs) $(RUNTIME_DEPS) $(mem_obj)
	$(LDXX) -o $@ $(LDFLAGS) $(client_udp_shard_obj) \
	$(librt_libs) $(RUNTIME_LIBS) $(mem_obj) -ldl

client_ebpf_shard: $(client_ebpf_shard_obj) $(librt_libs) $(RUNTIME_DEPS) $(mem_obj)
	$(LDXX) -o $@ $(LDFLAGS) $(client_ebpf_shard_obj) \
	$(librt_libs) $(RUNTIME_LIBS) $(mem_obj) -ldl

client_caladan_shard: $(client_caladan_shard_obj) $(librt_libs) $(RUNTIME_DEPS) $(mem_obj)
	$(LDXX) -o $@ $(LDFLAGS) $(client_caladan_shard_obj) \
	$(librt_libs) $(RUNTIME_LIBS) $(mem_obj) -ldl

client_dpdk_shard: $(client_dpdk_shard_obj) $(librt_libs) $(RUNTIME_DEPS) $(mem_obj)
	$(LDXX) -o $@ $(LDFLAGS) $(client_dpdk_shard_obj) \
	$(librt_libs) $(RUNTIME_LIBS) $(mem_obj) -ldl

client_lock: $(client_lock_obj) $(librt_libs) $(RUNTIME_DEPS) $(mem_obj)
	$(LDXX) -o $@ $(LDFLAGS) $(client_lock_obj) \
	$(librt_libs) $(RUNTIME_LIBS) $(mem_obj) -ldl

server: server_shard

server_shard: $(server_shard_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(server_shard_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

# general build rules for all targets
src = $(client_udp_shard_src) $(client_ebpf_shard_src) $(client_caladan_shard_src) $(client_dpdk_shard_src) $(client_lock_src)
src += $(server_shard_src)
obj = $(src:.cc=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.cc
	@$(CXX) $(CXXFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(obj) $(dep) client_udp_shard client_ebpf_shard client_caladan_shard client_dpdk_shard client_lock \
	server_shard mem.o
