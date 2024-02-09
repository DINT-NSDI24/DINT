# Makefile for benchmarks
ROOT_PATH=../../caladan
include $(ROOT_PATH)/build/shared.mk

client_src = client.cc
client_obj = $(client_src:.cc=.o)

client_caladan_src = client_caladan.cc
client_caladan_obj = $(client_caladan_src:.cc=.o)

server_src = server.cc
server_obj = $(server_src:.cc=.o)

librt_libs = $(ROOT_PATH)/bindings/cc/librt++.a
INC += -I$(ROOT_PATH)/bindings/cc

# must be first
all: client client_caladan server

client: $(client_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(client_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

client_caladan: $(client_caladan_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(client_caladan_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

server: $(server_obj) $(librt_libs) $(RUNTIME_DEPS)
	$(LDXX) -o $@ $(LDFLAGS) $(server_obj) \
	$(librt_libs) $(RUNTIME_LIBS)

# general build rules for all targets
src = $(client_src) $(client_caladan_src) $(server_src)
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
	rm -f $(obj) $(dep) client client_caladan server