/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 */
#ifndef EDGER8R_ENCLAVE_CURVE_U_H
#define EDGER8R_ENCLAVE_CURVE_U_H

#include <openenclave/host.h>

#include "enclave_curve_args.h"

OE_EXTERNC_BEGIN

oe_result_t oe_create_enclave_curve_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    oe_enclave_t** enclave);

/**** ECALL prototypes. ****/
oe_result_t enclave_SetCurveZMQ(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    int clientOrServer);

oe_result_t enclave_ExportSealedPrivateKey(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    sealed_data_t** sealed_prikey,
    size_t* sealed_prikey_len,
    uint8_t** pubkey,
    size_t* pubkey_len);

oe_result_t enclave_ImportSealedPrivateKey(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    sealed_data_t* sealed_prikey,
    size_t sealed_prikey_len,
    uint8_t* pubkey,
    size_t pubkey_len);

oe_result_t enclave_ImportServerPublicKey(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* pubkey,
    size_t pubkey_len);

oe_result_t enclave_ProduceHello(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t** hello_msg,
    size_t* hello_msg_len);

oe_result_t enclave_ProcessHello(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* hello_msg,
    size_t hello_msg_len);

oe_result_t enclave_ProduceWelcome(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t** welcome_msg,
    size_t* welcome_msg_len);

oe_result_t enclave_ProcessWelcome(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* welcome_msg,
    size_t welcome_msg_len);

oe_result_t enclave_ProduceInitiate(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* metadata_plaintext_,
    size_t metadata_length,
    uint8_t** initiate_msg,
    size_t* initiate_msg_len);

oe_result_t enclave_ProcessInitiate(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* initiate_msg,
    size_t initiate_msg_len,
    uint8_t** metadata_plaintext,
    size_t* metadata_length);

oe_result_t enclave_ProduceReady(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* metadata_,
    size_t metadata_length,
    uint8_t** ready_msg,
    size_t* ready_msg_len);

oe_result_t enclave_ProcessReady(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* ready_msg,
    size_t ready_msg_len,
    uint8_t** metadata_,
    size_t* metadata_length);

oe_result_t enclave_ProduceMessage(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* msg,
    size_t msg_len,
    uint8_t** enc_msg,
    size_t* enc_msg_len);

oe_result_t enclave_ProcessMessage(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint8_t* enc_msg,
    size_t enc_msg_len,
    uint8_t** msg,
    size_t* msg_len);

/**** OCALL prototypes. ****/
/* There were no ocalls. */

OE_EXTERNC_END

#endif // EDGER8R_ENCLAVE_CURVE_U_H
