all:zmq_server zmq_client zmq_curve_server zmq_curve_client

CC=g++
CFLAGS=-fPIC
#CFLAGS+=-I../libzmq/src
#CFLAGS+=-I../libzmq/include
CFLAGS+=-I../enclave-libzmq-4.3.2/src
CFLAGS+=-I../enclave-libzmq-4.3.2/include
CFLAGS+=-DZMQ_USE_TWEETNACL

LD_FLAGS+=-L. -lzmq -lpthread -L/opt/openenclave/share/pkgconfig/../../lib/openenclave/host -rdynamic -Wl,-z,noexecstack -loehost -ldl -lpthread -lsgx_enclave_common -lsgx_dcap_ql -lsgx_urts -lssl -lcrypto

zmq_server:zmq_server.o
	$(CC) -o zmq_server zmq_server.o $(LD_FLAGS)

zmq_client:zmq_client.o
	$(CC) -o zmq_client zmq_client.o $(LD_FLAGS)

zmq_curve_server:zmq_curve_server.o
	$(CC) -o zmq_curve_server zmq_curve_server.o $(LD_FLAGS)

zmq_curve_client:zmq_curve_client.o
	$(CC) -o zmq_curve_client zmq_curve_client.o $(LD_FLAGS)

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)

.cpp.o:
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -fr *.o zmq_server zmq_client zmq_curve_server zmq_curve_client

