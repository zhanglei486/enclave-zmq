/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 */
#ifndef EDGER8R_ENCLAVE_CURVE_T_H
#define EDGER8R_ENCLAVE_CURVE_T_H

#include <openenclave/enclave.h>

#include "enclave_curve_args.h"

OE_EXTERNC_BEGIN

/**** ECALL prototypes. ****/
oe_result_t enclave_SetCurveZMQ(int clientOrServer);

oe_result_t enclave_ExportSealedPrivateKey(
    sealed_data_t** sealed_prikey,
    size_t* sealed_prikey_len,
    uint8_t** pubkey,
    size_t* pubkey_len);

oe_result_t enclave_ImportSealedPrivateKey(
    sealed_data_t* sealed_prikey,
    size_t sealed_prikey_len,
    uint8_t* pubkey,
    size_t pubkey_len);

oe_result_t enclave_ImportServerPublicKey(
    uint8_t* pubkey,
    size_t pubkey_len);

oe_result_t enclave_ProduceHello(
    uint8_t** hello_msg,
    size_t* hello_msg_len);

oe_result_t enclave_ProcessHello(
    uint8_t* hello_msg,
    size_t hello_msg_len);

oe_result_t enclave_ProduceWelcome(
    uint8_t** welcome_msg,
    size_t* welcome_msg_len);

oe_result_t enclave_ProcessWelcome(
    uint8_t* welcome_msg,
    size_t welcome_msg_len);

oe_result_t enclave_ProduceInitiate(
    uint8_t* metadata_plaintext_,
    size_t metadata_length,
    uint8_t** initiate_msg,
    size_t* initiate_msg_len);

oe_result_t enclave_ProcessInitiate(
    uint8_t* initiate_msg,
    size_t initiate_msg_len,
    uint8_t** metadata_plaintext,
    size_t* metadata_length);

oe_result_t enclave_ProduceReady(
    uint8_t* metadata_,
    size_t metadata_length,
    uint8_t** ready_msg,
    size_t* ready_msg_len);

oe_result_t enclave_ProcessReady(
    uint8_t* ready_msg,
    size_t ready_msg_len,
    uint8_t** metadata_,
    size_t* metadata_length);

oe_result_t enclave_ProduceMessage(
    uint8_t* msg,
    size_t msg_len,
    uint8_t** enc_msg,
    size_t* enc_msg_len);

oe_result_t enclave_ProcessMessage(
    uint8_t* enc_msg,
    size_t enc_msg_len,
    uint8_t** msg,
    size_t* msg_len);

/**** OCALL prototypes. ****/
/* There were no ocalls. */

OE_EXTERNC_END

#endif // EDGER8R_ENCLAVE_CURVE_T_H
