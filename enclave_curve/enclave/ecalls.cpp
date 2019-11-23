//
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openenclave/enclave.h>

#include "dispatcher.h"
#include "enclave_curve_t.h"
#include "tweetnacl.h"
#include "common.h"
#include "common/shared.h"

#include "curve_client.h"
#include "curve_server.h"

#include "time.h"

void hex_dump_data(
    const char* name,
    const unsigned char* data,
    size_t data_size);


// Declare a static dispatcher object for better organization of enclave-wise
// global variables
static ecall_dispatcher dispatcher;
const char* enclave_name = "EnclaveZMQ";

static curve_zmq::curve_client_t zmq_client;
static curve_zmq::curve_server_t zmq_server;

static int m_isClient=0;

oe_result_t enclave_SetCurveZMQ(int clientOrServer)
{
    oe_result_t result = OE_OK;

    m_isClient = clientOrServer;

    return result;
}

oe_result_t enclave_ExportSealedPrivateKey(
    sealed_data_t** sealed_prikey,
    size_t* sealed_prikey_len,
    uint8_t** pubkey,
    size_t* pubkey_len)
{
    oe_result_t result = OE_OK;
    u8 u8_pubkey[crypto_box_PUBLICKEYBYTES], u8_prikey[crypto_box_SECRETKEYBYTES];

if(0)
{
    int i;
    Time_F(TM_START);
    for(i=0;i<1000;i++){
        crypto_box_keypair(u8_pubkey, u8_prikey);
    }
    double tttt = Time_F(TM_STOP);
    printf("*** time: %.5lf, %.5lf, %.1lf\n", tttt, tttt/1000, 1000/tttt);
}
    crypto_box_keypair(u8_pubkey, u8_prikey);

    dispatcher.seal_data( POLICY_UNIQUE, u8_prikey, crypto_box_SECRETKEYBYTES,
        sealed_prikey, sealed_prikey_len);

    *pubkey = (uint8_t*)oe_host_malloc(crypto_box_PUBLICKEYBYTES);
    memcpy(*pubkey, u8_pubkey, crypto_box_PUBLICKEYBYTES);
    *pubkey_len = crypto_box_PUBLICKEYBYTES;

    //hex_dump_data("privkey", u8_prikey, crypto_box_SECRETKEYBYTES);
    //hex_dump_data("pubkey", u8_pubkey, crypto_box_PUBLICKEYBYTES);

    memset( u8_prikey, 0, crypto_box_SECRETKEYBYTES);
    memset( u8_pubkey, 0, crypto_box_PUBLICKEYBYTES);    

    return result;
}

oe_result_t enclave_ImportSealedPrivateKey(
    sealed_data_t* sealed_prikey,
    size_t sealed_prikey_len,
    uint8_t* pubkey,
    size_t pubkey_len)
{
    oe_result_t result = OE_OK;
    int rc = 0;
    unsigned char *data = NULL;
    size_t data_size;

    rc = dispatcher.unseal_data(sealed_prikey, sealed_prikey_len, &data, &data_size);
    if(rc!=0){
        return OE_FAILURE;
    }

    //hex_dump_data("privkey", data, data_size);

    if(m_isClient==CURVE_SERVER){
        zmq_server.set_srv_public_key(pubkey);
        zmq_server.set_srv_secret_key(data);
    }else if(m_isClient==CURVE_CLIENT){
        zmq_client.set_cli_public_key(pubkey);
        zmq_client.set_cli_secret_key(data);
    }
    //printf("unseal data:%ld\n",data_size);
    //hex_dump_data("unseal data",data, data_size);

    if(data)
        free(data);
    return result;
}

oe_result_t enclave_ImportServerPublicKey(
    uint8_t* pubkey,
    size_t pubkey_len)
{
    oe_result_t result = OE_OK;

    //TRACE_ENCLAVE("return m_isClient:%d", m_isClient);
    //hex_dump_data("server_pubkey", pubkey, pubkey_len);
    zmq_client.set_srv_public_key(pubkey);
    return result;
}

oe_result_t enclave_ProduceHello(
    uint8_t** hello_msg,
    size_t* hello_msg_len)
{
    oe_result_t result = OE_OK;

    u8 u8_pubkey[crypto_box_PUBLICKEYBYTES], u8_prikey[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(u8_pubkey, u8_prikey);
    zmq_client.set_cli_tmp_public(u8_pubkey);
    zmq_client.set_cli_tmp_secret(u8_prikey);

    *hello_msg = (uint8_t*)oe_host_malloc(200);
    zmq_client.produce_hello(*hello_msg);
    *hello_msg_len = 200;

    return result;
}

oe_result_t enclave_ProcessHello(
    uint8_t* hello_msg,
    size_t hello_msg_len)
{
    oe_result_t result = OE_OK;

    result = zmq_server.process_hello(hello_msg, hello_msg_len);

    return result;
}

oe_result_t enclave_ProduceWelcome(
    uint8_t** welcome_msg,
    size_t* welcome_msg_len)
{
    oe_result_t result = OE_OK;

    result = zmq_server.produce_welcome(welcome_msg, welcome_msg_len);

    return result;
}

oe_result_t enclave_ProcessWelcome(
    uint8_t* welcome_msg,
    size_t welcome_msg_len)
{
    oe_result_t result = OE_OK;

    result = zmq_client.process_welcome(welcome_msg, welcome_msg_len);

    return result;
}

oe_result_t enclave_ProduceInitiate(
    uint8_t* metadata_plaintext_,
    size_t metadata_length,
    uint8_t** initiate_msg,
    size_t* initiate_msg_len)
{
    oe_result_t result = OE_OK;

    result = zmq_client.produce_initiate(
        metadata_plaintext_, metadata_length,
        initiate_msg, initiate_msg_len
        );

    return result;
}

oe_result_t enclave_ProcessInitiate(
    uint8_t* initiate_msg,
    size_t initiate_msg_len,
    uint8_t** metadata_plaintext,
    size_t *metadata_length)
{
    oe_result_t result = OE_OK;

    result = zmq_server.process_initiate(
        initiate_msg, initiate_msg_len,
        metadata_plaintext, metadata_length
        );
    return result;
}

oe_result_t enclave_ProduceReady(
    uint8_t *metadata_,
    size_t metadata_length,
    uint8_t** ready_msg,
    size_t* ready_msg_len)
{
    oe_result_t result = OE_OK;

    result = zmq_server.produce_ready(
        metadata_, metadata_length,
        ready_msg, ready_msg_len
        );

    return result;
}

oe_result_t enclave_ProcessReady(
    uint8_t* ready_msg,
    size_t ready_msg_len,
    uint8_t **metadata_,
    size_t *metadata_length)
{
    oe_result_t result = OE_OK;

    result = zmq_client.process_ready(
        ready_msg, ready_msg_len,
        metadata_, metadata_length
        );

    return result;
}

oe_result_t enclave_ProduceMessage(
    uint8_t* msg,
    size_t msg_len,
    uint8_t** enc_msg,
    size_t* enc_msg_len)
{
    oe_result_t result = OE_OK;
    if(m_isClient==CURVE_SERVER){
        result = zmq_server.produceMessage(msg, msg_len, enc_msg, enc_msg_len);
    }else if(m_isClient==CURVE_CLIENT){
        result = zmq_client.produceMessage(msg, msg_len, enc_msg, enc_msg_len);
    }

    return result;
}

oe_result_t enclave_ProcessMessage(
    uint8_t* enc_msg,
    size_t enc_msg_len,
    uint8_t** msg,
    size_t* msg_len)
{
    oe_result_t result = OE_OK;
    if(m_isClient==CURVE_SERVER){
        result = zmq_server.processMessage(enc_msg, enc_msg_len, msg, msg_len);
    }else if(m_isClient==CURVE_CLIENT){
        result = zmq_client.processMessage(enc_msg, enc_msg_len, msg, msg_len);
    }

    return result;
}

void hex_dump_data(
    const char* name,
    const unsigned char* data,
    size_t data_size)
{
    TRACE_ENCLAVE("Data name: %s:", name);
    //for (size_t i = 0; i < data_size; i++)
    //{
    //    TRACE_ENCLAVE("[%ld]-0x%02X", i, data[i]);
    //}
    //TRACE_ENCLAVE("\n");
    size_t i;
    for(i=0;i<data_size;i++){
        printf("%02x", data[i]&0xff);
        if((i+1)%4==0){
            if((i+1)%32==0)
                printf("\n");
            else
                printf(" ");
        }
    }
    if(i%32!=0) printf("\n");
}
