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
	CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) sign

# $(MAKE) keys

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../enclave_curve.edl --trusted  --trusted-dir .
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. -DOE_API_VERSION=2 -std=c++11 ecalls.cpp dispatcher.cpp keys.cpp  
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. -DOE_API_VERSION=2 -std=c++11 curve_server.cpp curve_client.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 enclave_curve_t.c  tweetnacl.c
	$(CXX) -o enclave_curve ecalls.o dispatcher.o keys.o enclave_curve_t.o  tweetnacl.o curve_server.o curve_client.o $(LDFLAGS)
	cp enclave_curve enclave_curve_client
	cp enclave_curve enclave_curve_server

sign:
	oesign sign -e enclave_curve -c enclave_curve.conf -k private.pem
	oesign sign -e enclave_curve_client -c enclave_curve.conf -k private.pem
	oesign sign -e enclave_curve_server -c enclave_curve_server.conf -k private.pem



clean:
	rm -f enclave_curve enclave_curve.signed *.o *.pem 
	rm -f enclave_curve_server enclave_curve_client enclave_curve_client.signed enclave_curve_server.signed 

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
