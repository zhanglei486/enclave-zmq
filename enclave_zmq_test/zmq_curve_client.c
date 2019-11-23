#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "tweetnacl.h"
#include "zmq_curve_util.h"

int main (void)
{
    // public and secret key
    unsigned char curve_secret[1024];
    unsigned char curve_public[crypto_box_PUBLICKEYBYTES];
    unsigned char server_public[crypto_box_PUBLICKEYBYTES];
    int secret_key_len, key_len;
   
    readFromFile("client_sealed_secret.bin", curve_secret, &secret_key_len);
    readFromFile("client_public.bin", curve_public, &key_len);
    readFromFile("server_public.bin", server_public, &key_len);
    printf("key_len:%d\n", key_len);

    printf ("Connecting to hello world server…\n");
    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);

    zmq_setsockopt(requester, ZMQ_CURVE_PUBLICKEY, curve_public, crypto_box_PUBLICKEYBYTES);
    zmq_setsockopt(requester, ZMQ_CURVE_SECRETKEY, curve_secret, secret_key_len);
    zmq_setsockopt(requester, ZMQ_CURVE_SERVERKEY, server_public, crypto_box_PUBLICKEYBYTES);

    zmq_connect (requester, "tcp://localhost:5555");

    int request_nbr;
    for (request_nbr = 0; request_nbr != 10; request_nbr++) {
        char buffer [10];
        printf ("Sending Hello %d…\n", request_nbr);
        zmq_send (requester, "Hello", 5, 0);
        zmq_recv (requester, buffer, 10, 0);
        printf ("Received World %d\n", request_nbr);
    }
    zmq_close (requester);
    zmq_ctx_destroy (context);
    return 0;
}
