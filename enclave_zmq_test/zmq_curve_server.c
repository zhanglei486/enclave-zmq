#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "tweetnacl.h"

#include "zmq_curve_util.h"

int main (void)
{
    // public and secret key
    unsigned char curve_secret[1024];
    unsigned char curve_public[crypto_box_PUBLICKEYBYTES];
    int secret_key_len, key_len, role;

    readFromFile("server_sealed_secret.bin", curve_secret, &secret_key_len);
    readFromFile("server_public.bin", curve_public, &key_len);
    printf("key_len:%d\n", key_len);

    //  Socket to talk to clients
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);

    role = 1;
    zmq_setsockopt(responder, ZMQ_CURVE_SERVER, &role, sizeof(int));
    zmq_setsockopt(responder, ZMQ_CURVE_PUBLICKEY, curve_public, crypto_box_PUBLICKEYBYTES);
    zmq_setsockopt(responder, ZMQ_CURVE_SECRETKEY, curve_secret, secret_key_len);

    int rc = zmq_bind (responder, "tcp://*:5555");
    assert (rc == 0);

    while (1) {
        char buffer [10];
        zmq_recv (responder, buffer, 10, 0);
        printf ("Received Hello\n");
        sleep (1);          //  Do some 'work'
        zmq_send (responder, "World", 5, 0);
    }
    return 0;
}


