.PHONY: all check bluedroid btt32 btt64 btt bttplugin

all: btt

CONFIG=-DWITHOUT_STACK -DDEVELOPMENT_VERSION=1
DEBUG_FLAGS=-Wall -Wextra -Werror -Wno-unused -O0 -g

BTT_OBJ= \
btt_daemon_adapter.c \
btt_daemon_misc.c \
btt_daemon_main.c \
btt_main.c \
btt_adapter.c \
btt_utils.c

ALL_OBJ= $(BTT_OBJ) \
btt_sdp_external.c

INCLUDES=-I../../../../hardware/libhardware/include/ -I../../../../system/core/include/

### Tested C/C++ compilers ###

# one pass compilation
GCC=gcc
#GCC=gcc -std=c99
#GCC=gcc-4.8
#GCC=gcc-4.7
#GCC=gcc-4.6
#GCC=gcc-4.5
#GCC=gcc-4.4
#GCC=llvm-gcc
#GCC=llvm-g++
#GCC=arm-linux-gnueabi-gcc
#GCC=arm-linux-gnueabi-g++

# multiple object *.o compilation
#GXX=g++
#GXX=g++ -std=c++98
#GXX=clang
#GXX=clang++
#GXX=tcc
#GXX=$(GCC)


out:
	mkdir out
	mkdir out/tmp

btt32: out out/btt32

out/btt32: $(BTT_OBJ) version_build.h
	$(GCC) -m32 -o $@ $^ $(CONFIG) $(DEBUG_FLAGS) -ldl -lpthread $(INCLUDES)
btt64: out out/btt64

out/btt64: $(BTT_OBJ) version_build.h
	$(GCC) -m64 -o $@ $^ $(CONFIG) $(DEBUG_FLAGS) -ldl -lpthread $(INCLUDES)

btt: out out/btt

out/btt: $(BTT_OBJ) version_build.h
	$(GCC) -o $@ $^ $(CONFIG) $(DEBUG_FLAGS) -ldl -lpthread $(INCLUDES)

# optional, please build manually
bttplugin: out/btt_sdp_external.so

out/btt_sdp_external.so: btt_sdp_external.c
	$(GCC) -shared -o $@ $^ -fPIC $(CONFIG) $(DEBUG_FLAGS) $(INCLUDES)

check:
	@ cppcheck  -DDEVELOPMENT_VERSION=1 --enable=all -v -q $(ALL_OBJ)
