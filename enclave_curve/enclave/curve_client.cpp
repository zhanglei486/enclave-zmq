#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openenclave/enclave.h>

#include "enclave_curve_t.h"
#include "tweetnacl.h"
#include "common.h"
#include "common/shared.h"

#include <errno.h>

#include <vector>

#include "tweetnacl.h"
#include "curve_client.h"

using namespace curve_zmq;

extern void hex_dump_data(
    const char* name,
    const unsigned char* data,
    size_t data_size);

curve_client_t::curve_client_t () : 
                    cn_nonce (1),
                    cn_peer_nonce (1)
{
}

curve_client_t::~curve_client_t ()
{
}

oe_result_t curve_client_t::produce_hello(uint8_t* hello_data_)
{
    uint8_t hello_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> hello_plaintext (
          crypto_box_ZEROBYTES + 64, 0);
    uint8_t hello_box[crypto_box_BOXZEROBYTES + 80];

    //  Prepare the full nonce
    memcpy (hello_nonce, "CurveZMQHELLO---", 16);
    put_uint64 (hello_nonce + 16, cn_nonce);

    crypto_box_keypair(m_cli_tmp_public, m_cli_tmp_secret);
    //hex_dump_data("m_cli_tmp_public", m_cli_tmp_public, 32);
    //hex_dump_data("m_cli_tmp_secret", m_cli_tmp_secret, 32);

    //  Create Box [64 * %x0](C'->S)
    int rc =
      crypto_box (hello_box, &hello_plaintext[0], hello_plaintext.size (),
                hello_nonce, m_srv_public_key, m_cli_tmp_secret);
    if (rc == -1)
        return OE_FAILURE;

    uint8_t *hello = static_cast<uint8_t *> (hello_data_);

    memcpy (hello, "\x05HELLO", 6);
    //  CurveZMQ major and minor version numbers
    memcpy (hello + 6, "\1\0", 2);
    //  Anti-amplification padding
    memset (hello + 8, 0, 72);
    //  Client public connection key
    memcpy (hello + 80, m_cli_tmp_public, crypto_box_PUBLICKEYBYTES);
    //  Short nonce, prefixed by "CurveZMQHELLO---"
    memcpy (hello + 112, hello_nonce + 16, 8);
    //  Signature, Box [64 * %x0](C'->S)
    memcpy (hello + 120, hello_box + crypto_box_BOXZEROBYTES, 80);

    return OE_OK;
}


oe_result_t curve_client_t::process_welcome(uint8_t* welcome_data_, int welcome_data_len)
{
    if (welcome_data_len != 168) {
        errno = EPROTO;
        return OE_INVALID_PARAMETER;
    }

    uint8_t welcome_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> welcome_plaintext (
          crypto_box_ZEROBYTES + 128);
    uint8_t welcome_box[crypto_box_BOXZEROBYTES + 144];

    //  Open Box [S' + cookie](C'->S)
    memset (welcome_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (welcome_box + crypto_box_BOXZEROBYTES, welcome_data_ + 24, 144);

    memcpy (welcome_nonce, "WELCOME-", 8);
    memcpy (welcome_nonce + 8, welcome_data_ + 8, 16);

    //hex_dump_data("welcome_box", welcome_box, sizeof welcome_box);
    //hex_dump_data("m_srv_public_key", m_srv_public_key, 32);
    //hex_dump_data("m_cli_tmp_secret", m_cli_tmp_secret, 32);
    //hex_dump_data("welcome_nonce", welcome_nonce, crypto_box_NONCEBYTES);

    int rc = crypto_box_open (&welcome_plaintext[0], welcome_box,
                              sizeof welcome_box, welcome_nonce,
                              m_srv_public_key, m_cli_tmp_secret);
    if (rc != 0) {
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_FAILURE;
    }

    memcpy (m_srv_tmp_public, &welcome_plaintext[crypto_box_ZEROBYTES], 32);
    memcpy (cn_cookie, &welcome_plaintext[crypto_box_ZEROBYTES + 32],
                16 + 80);
    //hex_dump_data("****client_cn_cookie", cn_cookie, 96);
    //printf("****client_cn_cookie****\n");

    //  Message independent precomputation
    rc = crypto_box_beforenm (cn_precom, m_srv_tmp_public, m_cli_tmp_secret);
    assert (rc == 0);

    return OE_OK;
}

oe_result_t curve_client_t::produce_initiate(const uint8_t *metadata_plaintext_,
                          const size_t metadata_length_,
                          uint8_t** initiate_data_, size_t *initiate_data_len
                        )
{
    uint8_t vouch_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> vouch_plaintext (
          crypto_box_ZEROBYTES + 64);
    uint8_t vouch_box[crypto_box_BOXZEROBYTES + 80];

    //  Create vouch = Box [C',S](C->S')
    std::fill (vouch_plaintext.begin (),
                   vouch_plaintext.begin () + crypto_box_ZEROBYTES, 0);
    memcpy (&vouch_plaintext[crypto_box_ZEROBYTES], m_cli_tmp_public, 32);
    memcpy (&vouch_plaintext[crypto_box_ZEROBYTES + 32], m_srv_public_key, 32);

    memcpy (vouch_nonce, "VOUCH---", 8);
    randombytes (vouch_nonce + 8, 16);

    int rc =
          crypto_box (vouch_box, &vouch_plaintext[0], vouch_plaintext.size (),
                      vouch_nonce, m_srv_tmp_public, m_cli_secret_key);
    if (rc == -1)
        return OE_FAILURE;

    uint8_t initiate_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> initiate_box (crypto_box_BOXZEROBYTES + 144
                                           + metadata_length_);
    std::vector<uint8_t> initiate_plaintext (
          crypto_box_ZEROBYTES + 128 + metadata_length_);

    //  Create Box [C + vouch + metadata](C'->S')
    std::fill (initiate_plaintext.begin (),
                   initiate_plaintext.begin () + crypto_box_ZEROBYTES, 0);
    //memcpy (&initiate_plaintext[crypto_box_ZEROBYTES], m_cli_tmp_public_key, 32);
    //hex_dump_data("****m_cli_public_key", m_cli_public_key, 32);
    memcpy (&initiate_plaintext[crypto_box_ZEROBYTES], m_cli_public_key, 32);
    memcpy (&initiate_plaintext[crypto_box_ZEROBYTES + 32], vouch_nonce + 8,
            16);
    memcpy (&initiate_plaintext[crypto_box_ZEROBYTES + 48],
            vouch_box + crypto_box_BOXZEROBYTES, 80);
    if (metadata_length_) {
        memcpy (&initiate_plaintext[crypto_box_ZEROBYTES + 48 + 80],
                metadata_plaintext_, metadata_length_);
    }

    memcpy (initiate_nonce, "CurveZMQINITIATE", 16);
    put_uint64 (initiate_nonce + 16, cn_nonce);

    rc = crypto_box (&initiate_box[0], &initiate_plaintext[0],
                         crypto_box_ZEROBYTES + 128 + metadata_length_,
                         initiate_nonce, m_srv_tmp_public, m_cli_tmp_secret);

    if (rc == -1)
            return OE_FAILURE;

    //assert (size_
    //                == 113 + 128 + crypto_box_BOXZEROBYTES + metadata_length_);
    *initiate_data_len = 113 + 128 + crypto_box_BOXZEROBYTES + metadata_length_;
    *initiate_data_ = (uint8_t *)oe_host_malloc(*initiate_data_len);

    uint8_t *initiate = static_cast<uint8_t *> (*initiate_data_);

    memcpy (initiate, "\x08INITIATE", 9);
    //  Cookie provided by the server in the WELCOME command
    memcpy (initiate + 9, cn_cookie, 96);
    //  Short nonce, prefixed by "CurveZMQINITIATE"
    memcpy (initiate + 105, initiate_nonce + 16, 8);
    //  Box [C + vouch + metadata](C'->S')
    memcpy (initiate + 113, &initiate_box[crypto_box_BOXZEROBYTES],
                128 + metadata_length_ + crypto_box_BOXZEROBYTES);

    return OE_OK;
}


oe_result_t curve_client_t::process_ready(uint8_t* ready_data_, int ready_data_len, 
    uint8_t **metadata_, size_t *metadata_length)
{
    if (ready_data_len < 30) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (),
        //  ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY);
        errno = EPROTO;
        return OE_BUFFER_TOO_SMALL;
    }

    const size_t clen = (ready_data_len - 14) + crypto_box_BOXZEROBYTES;

    uint8_t ready_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> ready_plaintext (
      crypto_box_ZEROBYTES + clen);
    std::vector<uint8_t> ready_box (crypto_box_BOXZEROBYTES + 16 + clen);

    std::fill (ready_box.begin (), ready_box.begin () + crypto_box_BOXZEROBYTES,
               0);
    memcpy (&ready_box[crypto_box_BOXZEROBYTES], ready_data_ + 14,
            clen - crypto_box_BOXZEROBYTES);

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    memcpy (ready_nonce + 16, ready_data_ + 6, 8);
    cn_peer_nonce = get_uint64 (ready_data_ + 6);

    int rc = crypto_box_open_afternm (&ready_plaintext[0], &ready_box[0], clen,
                                      ready_nonce, cn_precom);

    if (rc != 0) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        return OE_FAILURE;
    }

    //rc = parse_metadata (&ready_plaintext[crypto_box_ZEROBYTES],
    //                     clen - crypto_box_ZEROBYTES);
    *metadata_length = clen - crypto_box_ZEROBYTES;
    *metadata_ = (uint8_t *)oe_host_malloc(*metadata_length);
    memcpy(*metadata_, &ready_plaintext[crypto_box_ZEROBYTES], *metadata_length);

    oe_result_t oe_ret;
    if (rc == 0){
        _state = connected;
        oe_ret = OE_OK;
    }else {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);
        errno = EPROTO;
        oe_ret = OE_FAILURE;
    }

    return oe_ret;
}

oe_result_t curve_client_t::produceMessage( uint8_t* msg,
                        size_t msg_len,
                        uint8_t** enc_msg,
                        size_t* enc_msg_len)
{
    oe_result_t result = OE_OK;

    const size_t mlen = crypto_box_ZEROBYTES + msg_len;

    uint8_t message_nonce[crypto_box_NONCEBYTES];
    //memcpy (message_nonce, encode_nonce_prefix, 16);
    memcpy( message_nonce, "CurveZMQMESSAGEC", 16);
    put_uint64 (message_nonce + 16, cn_nonce);

    std::vector<uint8_t> message_plaintext (mlen);

    std::fill (message_plaintext.begin (),
               message_plaintext.begin () + crypto_box_ZEROBYTES, 0);
    // this is copying the data from insecure memory, so there is no point in
    // using secure_allocator_t for message_plaintext
    memcpy (&message_plaintext[crypto_box_ZEROBYTES], msg,
            msg_len);

    std::vector<uint8_t> message_box (mlen);

    int rc = crypto_box_afternm (&message_box[0], &message_plaintext[0], mlen,
                                 message_nonce, cn_precom);
    assert (rc == 0);
    //rc = msg_->close ();
    //ssert (rc == 0);

    //rc = msg_->init_size (16 + mlen - crypto_box_BOXZEROBYTES);
    //mq_assert (rc == 0);    
    *enc_msg_len = 16 + mlen - crypto_box_BOXZEROBYTES;
    *enc_msg = (uint8_t *)oe_host_malloc(*enc_msg_len);

    uint8_t *message = static_cast<uint8_t *> (*enc_msg);

    memcpy (message, "\x07MESSAGE", 8);
    memcpy (message + 8, message_nonce + 16, 8);
    memcpy (message + 16, &message_box[crypto_box_BOXZEROBYTES],
            mlen - crypto_box_BOXZEROBYTES);

    cn_nonce++;

    return result;
}

oe_result_t curve_client_t::processMessage(
    uint8_t* enc_msg,
    size_t enc_msg_len,
    uint8_t** msg,
    size_t* msg_len)
{
    oe_result_t result = OE_OK;

    int rc;
    //int rc = check_basic_command_structure (msg_);
    //if (rc == -1)
    //    return OE_FAILURE;

    const size_t size = enc_msg_len;
    const uint8_t *message = static_cast<uint8_t *> (enc_msg);

    if (size < 8 || memcmp (message, "\x07MESSAGE", 8)) {
        //session->get_socket ()->event_handshake_failed_protocol (
        // session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return OE_FAILURE;
    }

    if (size < 33) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (),
        //  ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return OE_FAILURE;
    }

    uint8_t message_nonce[crypto_box_NONCEBYTES];
    //memcpy (message_nonce, decode_nonce_prefix, 16);
    memcpy( message_nonce, "CurveZMQMESSAGEC", 16);
    memcpy (message_nonce + 16, message + 8, 8);
    uint64_t nonce = get_uint64 (message + 8);
    if (nonce <= cn_peer_nonce) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE);
        errno = EPROTO;
        return OE_FAILURE;
    }
    cn_peer_nonce = nonce;

    const size_t clen = crypto_box_BOXZEROBYTES + enc_msg_len - 16;

    std::vector<uint8_t> message_plaintext (clen);
    std::vector<uint8_t> message_box (clen);

    std::fill (message_box.begin (),
               message_box.begin () + crypto_box_BOXZEROBYTES, 0);
    memcpy (&message_box[crypto_box_BOXZEROBYTES], message + 16,
            enc_msg_len - 16);

    rc = crypto_box_open_afternm (&message_plaintext[0], &message_box[0], clen,
                                  message_nonce, cn_precom);

    if (rc == 0) {
        //rc = msg_->close ();
        //zmq_assert (rc == 0);

        //rc = msg_->init_size (clen - 1 - crypto_box_ZEROBYTES);
        //zmq_assert (rc == 0);

        *msg_len = clen - crypto_box_ZEROBYTES;        
        *msg = (uint8_t *)oe_host_malloc(*msg_len);

        // this is copying the data to insecure memory, so there is no point in
        // using secure_allocator_t for message_plaintext
         
        memcpy (*msg, &message_plaintext[crypto_box_ZEROBYTES], *msg_len);         
    } else {
        // CURVE I : connection key used for MESSAGE is wrong
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);

        errno = EPROTO;
        return OE_FAILURE;
    } 
    result = OE_OK;
    return result;
}

void curve_client_t::set_cli_public_key(uint8_t *cli_public_key)
{
    memcpy(m_cli_public_key, cli_public_key, crypto_box_PUBLICKEYBYTES);
}

void curve_client_t::set_cli_secret_key(uint8_t *cli_secret_key)
{
    memcpy(m_cli_secret_key, cli_secret_key, crypto_box_SECRETKEYBYTES);
}

void curve_client_t::set_cli_tmp_public(uint8_t *cli_tmp_public)
{
    memcpy(m_cli_tmp_public, cli_tmp_public, crypto_box_PUBLICKEYBYTES);
}

void curve_client_t::set_cli_tmp_secret(uint8_t *cli_tmp_secret)
{
    memcpy(m_cli_tmp_secret, cli_tmp_secret, crypto_box_SECRETKEYBYTES);
}

void curve_client_t::set_srv_public_key(uint8_t *srv_public_key)
{
    memcpy(m_srv_public_key, srv_public_key, crypto_box_PUBLICKEYBYTES);
}

void curve_client_t::set_srv_tmp_public(uint8_t *srv_tmp_public)
{
    memcpy(m_srv_tmp_public, srv_tmp_public, crypto_box_PUBLICKEYBYTES);
}

