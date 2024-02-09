# Makefile for lock_fasst/udp

# toolchain definitions
INC = -I.
FLAGS   = -g -Wall -D_GNU_SOURCE $(INC)
LDFLAGS = -T $(ROOT_PATH)/base/base.ld
LD      = gcc
CC      = gcc
LDXX	  = g++
CXX	    = g++
AR      = ar
SPARSE  = sparse

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

# mmodel
CXXFLAGS += -mcmodel=large

# main
server_src = server.cc
server_obj = $(server_src:.cc=.o)

# must be first
all: server

server: $(server_obj)
	$(CXX) -o $@ $(CXXFLAGS) $(server_obj)

# general build rules for all targets
src = $(server_src)
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
	rm -f $(obj) $(dep) server