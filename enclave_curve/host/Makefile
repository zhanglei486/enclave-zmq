# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
	CXX_COMPILER=$(notdir $(CXX))
	USE_GCC = true
endif

ifeq ($(USE_GCC),)
	CC = clang-7
	CXX = clang++-7
	C_COMPILER=clang
	CXX_COMPILER=clang
endif

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --libs)


all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../enclave_curve.edl --untrusted
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. host.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. enclave_curve_u.c
	$(CXX) -o enclave_curve_host host.o enclave_curve_u.o $(LDFLAGS)

clean:
	rm -f enclave_curve_host *.o enclave_curve_u.* enclave_curve_args.h
