// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <common/shared.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include "enclave_curve_u.h"

using namespace std;

static void writeToFile(const char *fname,  const unsigned char *buf, size_t len);
static void readFromFile(const char *fname, unsigned char *buf, size_t *len);   

const char* g_plain_text = "test plaintext";
const char* g_opt_msg = "optional sealing message";

oe_enclave_t* create_enclave(const char* enclavePath)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Loading enclave library %s\n", enclavePath);
    oe_result_t result = oe_create_enclave_curve_enclave(
        enclavePath,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_datasealing_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: enclave terminated.\n");
}

void  hexdump(unsigned char *buf, int len)
{
    int i;
    for(i=0;i<len;i++){
        printf("%02x", buf[i]&0xff);
        if((i+1)%4==0){
            if((i+1)%32==0)
                printf("\n");
            else
                printf(" ");
        }
    }
    if(i%32!=0) printf("\n");
}

oe_result_t generate_enclave_key(
    oe_enclave_t* enclave_server,
    oe_enclave_t* enclave_client)
{
    oe_result_t result = OE_OK;

    sealed_data_t *srv_sealed_prikey=NULL;
    sealed_data_t *cli_sealed_prikey=NULL;
    uint8_t *srv_pubkey=NULL, *cli_pubkey=NULL;
    size_t srv_sealed_prikey_len, srv_pubkey_len;
    size_t cli_sealed_prikey_len, cli_pubkey_len;

    enclave_SetCurveZMQ(enclave_server, &result, CURVE_SERVER);
    enclave_SetCurveZMQ(enclave_client, &result, CURVE_CLIENT);


    // server
    enclave_ExportSealedPrivateKey(enclave_server, &result,
           &srv_sealed_prikey, &srv_sealed_prikey_len,
          &srv_pubkey, &srv_pubkey_len);
    printf("enclave_ExportSealedPrivateKey return:%d, prikey_len:%ld, pubkey_len:%ld, total_size:%ld\n", 
            result, srv_sealed_prikey_len, srv_pubkey_len,
            srv_sealed_prikey->total_size);
    printf("key_info_size:%ld, original_data_size:%ld, encrypted_data_len:%ld\n",
        srv_sealed_prikey->key_info_size,
        srv_sealed_prikey->original_data_size,
        srv_sealed_prikey->encrypted_data_len);

    printf("%s:%d encrypted_data:%p\n", __func__, __LINE__, srv_sealed_prikey->encrypted_data);
    //hexdump((unsigned char *)sealed_prikey->encrypted_data, sealed_prikey->encrypted_data_len);
    //hexdump((unsigned char *)sealed_prikey->encrypted_data+sealed_prikey->encrypted_data_len,
    //    sealed_prikey->key_info_size);
    hexdump(srv_pubkey, srv_pubkey_len);   

    // client 
    enclave_ExportSealedPrivateKey(enclave_client, &result,
           &cli_sealed_prikey, &cli_sealed_prikey_len,
          &cli_pubkey, &cli_pubkey_len);
    hexdump(cli_pubkey, cli_pubkey_len);

    writeToFile("server_sealed_secret.bin", (unsigned char *)srv_sealed_prikey, srv_sealed_prikey_len);
    writeToFile("server_public.bin", srv_pubkey, srv_pubkey_len);
    writeToFile("client_sealed_secret.bin", (unsigned char *)cli_sealed_prikey, cli_sealed_prikey_len);
    writeToFile("client_public.bin", cli_pubkey, cli_pubkey_len);

    // Free host memory allocated by the enclave.
    if (srv_sealed_prikey != NULL)
        free(srv_sealed_prikey);
    if (cli_sealed_prikey != NULL)
        free(cli_sealed_prikey);
    if (srv_pubkey != NULL)
        free(srv_pubkey);
    if (cli_pubkey != NULL)
        free(cli_pubkey);

    return OE_OK;
}

oe_result_t enclave_curve_api_test(
    oe_enclave_t* enclave_server,
    oe_enclave_t* enclave_client)
{
    oe_result_t result = OE_OK;

    sealed_data_t *srv_sealed_prikey=NULL;
    sealed_data_t *cli_sealed_prikey=NULL;
    uint8_t *srv_pubkey=NULL, *cli_pubkey=NULL;
    size_t srv_sealed_prikey_len=0, srv_pubkey_len=0;
    size_t cli_sealed_prikey_len=0, cli_pubkey_len=0;

    enclave_SetCurveZMQ(enclave_server, &result, CURVE_SERVER);
    enclave_SetCurveZMQ(enclave_client, &result, CURVE_CLIENT);


    readFromFile("server_sealed_secret.bin", NULL, &srv_sealed_prikey_len);
    readFromFile("server_public.bin", NULL, &srv_pubkey_len);
    readFromFile("client_sealed_secret.bin", NULL, &cli_sealed_prikey_len);
    readFromFile("client_public.bin", NULL, &cli_pubkey_len);

    if( (srv_sealed_prikey_len==0) || (cli_sealed_prikey_len==0) )
        return OE_FAILURE;

    srv_sealed_prikey = (sealed_data_t *)malloc(srv_sealed_prikey_len);
    srv_pubkey = (uint8_t *)malloc(srv_pubkey_len);
    cli_sealed_prikey = (sealed_data_t *)malloc(cli_sealed_prikey_len);
    cli_pubkey = (uint8_t *)malloc(cli_pubkey_len);

    if( (srv_sealed_prikey==NULL) || (cli_sealed_prikey==NULL) )
        return OE_FAILURE;

    readFromFile("server_sealed_secret.bin", (unsigned char *)srv_sealed_prikey, &srv_sealed_prikey_len);
    readFromFile("server_public.bin", srv_pubkey, &srv_pubkey_len);
    readFromFile("client_sealed_secret.bin", (unsigned char *)cli_sealed_prikey, &cli_sealed_prikey_len);
    readFromFile("client_public.bin", cli_pubkey, &cli_pubkey_len);
 
 /*
    // test whether key sealed using unique policy, can import to another enclave
    {
        cout<<"***** *****"<<endl;
        // import server secret key
        enclave_ImportSealedPrivateKey(enclave_server, &result, 
            cli_sealed_prikey, cli_sealed_prikey_len, cli_pubkey, cli_pubkey_len);
        cout<<"enclave_ImportSealedPrivateKey,return:"<<result<<endl;
        if(result!=OE_OK)
            return result;
    }
*/    

    // import server secret key
    enclave_ImportSealedPrivateKey(enclave_server, &result, 
        srv_sealed_prikey, srv_sealed_prikey_len, srv_pubkey, srv_pubkey_len);
    cout<<"enclave_ImportSealedPrivateKey("<<__LINE__<<"),return:"<<result<<endl;
    if(result!=OE_OK)
        return result;
    // import client secret key
    enclave_ImportSealedPrivateKey(enclave_client, &result, 
        cli_sealed_prikey, cli_sealed_prikey_len, cli_pubkey, cli_pubkey_len);
    cout<<"enclave_ImportSealedPrivateKey("<<__LINE__<<"),return:"<<result<<endl;
    if(result!=OE_OK)
        return result;

    result = OE_OK;

    enclave_ImportServerPublicKey(enclave_client, &result,
        srv_pubkey, srv_pubkey_len);

    // protocol test

    // cli->srv HelloMsg
    uint8_t *helloMsg=NULL;
    size_t helloMsgLen;

    printf("=======helloMsg(cli->srv)=======\n");
    printf("=======call enclave_ProduceHello=======\n");
    enclave_ProduceHello(enclave_client, &result, &helloMsg, &helloMsgLen);
    printf("%s:%d result:%d, helloMsgLen:%ld\n", __func__, __LINE__, result, helloMsgLen);
    hexdump(helloMsg, helloMsgLen);
    

    // srv process HelloMsg
    printf("=======call enclave_ProcessHello=======\n");
    enclave_ProcessHello(enclave_server, &result, helloMsg, helloMsgLen);
    printf("%s:%d result:%d, helloMsgLen:%ld\n", __func__, __LINE__, result, helloMsgLen);
    free(helloMsg);

    // srv>cli WelcomeMsg
    uint8_t *welcomeMsg=NULL;
    size_t welcomeMsgLen;

    printf("=======welcomeMsg(srv->cli)=======\n");
    printf("=======call enclave_ProduceWelcome=======\n");
    enclave_ProduceWelcome(enclave_server, &result, &welcomeMsg, &welcomeMsgLen);
    printf("%s:%d result:%d, welcomeMsgLen:%ld\n", __func__, __LINE__, result, welcomeMsgLen);
    hexdump(welcomeMsg, welcomeMsgLen);

    //client process welcomeMsg
    printf("=======call enclave_ProcessWelcome=======\n");
    enclave_ProcessWelcome(enclave_client, &result, welcomeMsg, welcomeMsgLen);
    printf("%s:%d result:%d, welcomeMsgLen:%ld\n", __func__, __LINE__, result, welcomeMsgLen);

    free(welcomeMsg);

    // cli->srv InitiateMsg
    uint8_t *initiateMsg=NULL;
    size_t initiateMsgLen;

    uint8_t metaMsg[64], *metaMsgOut;
    size_t metaMsgLen;

    printf("=======initiateMsg(cli->srv)=======\n");
    metaMsgLen = sizeof(metaMsg);
    memset(metaMsg, '1', metaMsgLen);

    printf("=======call enclave_ProduceInitiate=======\n");
    enclave_ProduceInitiate(enclave_client, &result, metaMsg, metaMsgLen, 
        &initiateMsg, &initiateMsgLen);
    printf("%s:%d result:%d, initiateMsgLen:%ld\n", __func__, __LINE__, result, initiateMsgLen);
    hexdump(initiateMsg, initiateMsgLen);
    
    printf("=======call enclave_ProcessInitiate=======\n");
    // srv process InitiateMsg
    enclave_ProcessInitiate(enclave_server, &result, initiateMsg, initiateMsgLen, &metaMsgOut, &metaMsgLen);
    printf("%s:%d result:%d, initiateMsgLen:%ld, metaMsgLen:%ld\n", __func__, __LINE__, result, initiateMsgLen, metaMsgLen);
    if(metaMsgLen){
        hexdump(metaMsgOut, metaMsgLen);
        free(metaMsgOut);
    }

    free(initiateMsg);

    // srv->cli readyMsg
    uint8_t *readyMsg=NULL;
    size_t readyMsgLen;

    printf("=======readyMsg(srv->cli)=======\n");
    metaMsgLen = sizeof(metaMsg);
    memset(metaMsg, '1', metaMsgLen);

    printf("=======call enclave_ProduceReady=======\n");
    enclave_ProduceReady(enclave_server, &result, metaMsg, metaMsgLen, 
        &readyMsg, &readyMsgLen);
    printf("%s:%d result:%d, readyMsgLen:%ld\n", __func__, __LINE__, result, readyMsgLen);
    hexdump(readyMsg, readyMsgLen);
    
    printf("=======call enclave_ProcessReady=======\n");
    // srv process readyMsg
    enclave_ProcessReady(enclave_client, &result, readyMsg, readyMsgLen, &metaMsgOut, &metaMsgLen);
    printf("%s:%d result:%d, initiateMsgLen:%ld, metaMsgLen:%ld\n", __func__, __LINE__, result, readyMsgLen, metaMsgLen);
    if(metaMsgLen){
        hexdump(metaMsgOut, metaMsgLen);
        free(metaMsgOut);
    }
    free(readyMsg);

    // srv->cli Real Message
    uint8_t *encMsg=NULL;
    size_t encMsgLen;
    uint8_t commMsg[32], *commMsg2=NULL;
    size_t commMsgLen=32;

    printf("=======realMsg(srv->cli)=======\n");
    commMsgLen = sizeof(commMsg);
    memset(commMsg, 'a', commMsgLen);


    printf("=======call enclave_ProduceMessage=======\n");
    enclave_ProduceMessage(enclave_server, &result, commMsg, commMsgLen, 
        &encMsg, &encMsgLen);
    printf("%s:%d result:%d, encMsgLen:%ld\n", __func__, __LINE__, result, encMsgLen);
    hexdump(encMsg, encMsgLen);
    printf("=======call enclave_ProcessMessage=======\n");
    enclave_ProcessMessage(enclave_client, &result, encMsg, encMsgLen, 
        &commMsg2, &commMsgLen);
    printf("%s:%d result:%d, commMsgLen:%ld\n", __func__, __LINE__, result, commMsgLen);
    if(commMsgLen){
        hexdump(commMsg2, commMsgLen);
        free(commMsg2);
    }
    free(encMsg);

    printf("=======realMsg(cli->srv)=======\n");
    commMsgLen = sizeof(commMsg);
    memset(commMsg, 'a', commMsgLen);


    printf("=======call enclave_ProduceMessage=======\n");
    enclave_ProduceMessage(enclave_client, &result, commMsg, commMsgLen, 
        &encMsg, &encMsgLen);
    printf("%s:%d result:%d, encMsgLen:%ld\n", __func__, __LINE__, result, encMsgLen);
    hexdump(encMsg, encMsgLen);
    printf("=======call enclave_ProcessMessage=======\n");
    enclave_ProcessMessage(enclave_server, &result, encMsg, encMsgLen, 
        &commMsg2, &commMsgLen);
    printf("%s:%d result:%d, commMsgLen:%ld\n", __func__, __LINE__, result, commMsgLen);
    if(commMsgLen){
        hexdump(commMsg2, commMsgLen);
        free(commMsg2);
    }
    free(encMsg);


exit:

    // Free host memory allocated by the enclave.
    if (srv_sealed_prikey != NULL)
        free(srv_sealed_prikey);
    if (cli_sealed_prikey != NULL)
        free(cli_sealed_prikey);
    if (srv_pubkey != NULL)
        free(srv_pubkey);
    if (cli_pubkey != NULL)
        free(cli_pubkey);

    return result;
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    oe_enclave_t* enclave_server = NULL;
    oe_enclave_t* enclave_client = NULL;
    int ret = 1;

    if(argc<3){
        cout<<"Usage:\n\t"<<argv[0]<<" server_enclave client_enclave [key]"<<endl;
        return 0;
    }
    cout << "Host: enter main" << endl;

    enclave_server = create_enclave(argv[1]);
    //enclave_client = create_enclave("enclave_zmq");
    if (enclave_server == NULL)
    {
        ret = -1;
        goto exit;
    }
    enclave_client = create_enclave(argv[2]);
    //enclave_client = create_enclave("enclave_zmq");
    if (enclave_client == NULL)
    {
        ret = -1;
        goto exit;
    }

    if ( (argc > 3) && (strcmp(argv[3],"key")==0))
    {
        generate_enclave_key(enclave_server, enclave_client);
        ret = 0;
        goto exit;
    }
    

    result = enclave_curve_api_test(enclave_server, enclave_client);
    if (result != OE_OK)
    {
        cout << "Host: EncalveZMQ API test failed!" << ret << endl;
        ret = -1;
        goto exit;
    }

    ret = 0;

exit:
    cout << "Host: Terminating enclaves" << endl;
    if (enclave_client)
        terminate_enclave(enclave_client);
    if (enclave_server)
        terminate_enclave(enclave_server);

    if (ret == 0)
        cout << "Host: Sample completed successfully." << endl;

    return ret;
}


static void writeToFile(const char *fname,  const unsigned char *buf, size_t len)
{
    FILE *fp = fopen(fname, "wb");
    if(!fp) return;

    fwrite(buf, len, 1, fp);
    fclose(fp);
}

static void readFromFile(const char *fname, unsigned char *buf, size_t *len)
{
    struct stat fst;
    int ret;

    ret = stat(fname, &fst);
    if(ret!=0){
        *len = 0;
        return;
    }

    *len = fst.st_size;
    if(buf==NULL){       
        return;
    }
    FILE *fp =fopen(fname, "rb");
    if(fp==NULL) return;
    fread(buf, *len, 1, fp);
    fclose(fp);
}
