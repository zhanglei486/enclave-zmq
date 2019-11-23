# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean
	rm *.bin

#run_genkey:
#	host/enclave_curve_host ./enclave/enclave_curve_server.signed ./enclave/enclave_curve_client.signed key
#
#run:
#	host/enclave_curve_host ./enclave/enclave_curve_server.signed ./enclave/enclave_curve_client.signed 

run_genkey:
	host/enclave_curve_host ./enclave/enclave_curve.signed ./enclave/enclave_curve.signed key

run:
	host/enclave_curve_host ./enclave/enclave_curve.signed ./enclave/enclave_curve.signed 
