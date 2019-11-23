#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openenclave/enclave.h>
#include <errno.h>

#include <vector>

#include "common.h"
#include "tweetnacl.h"
#include "curve_server.h"

using namespace curve_zmq;

extern void hex_dump_data(
    const char* name,
    const unsigned char* data,
    size_t data_size);

curve_server_t::curve_server_t () : 
                    cn_nonce (1),
                    cn_peer_nonce (1)
{
}

curve_server_t::~curve_server_t ()
{
}


oe_result_t curve_server_t::process_hello(uint8_t* hello_data_, int hello_data_len)
{
    int rc;
    const size_t size = hello_data_len;
    const uint8_t *const hello = static_cast<uint8_t *> (hello_data_);

    if (size < 6 || memcmp (hello, "\x05HELLO", 6)) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return OE_INVALID_PARAMETER;
    }

    if (size != 200) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (),
        //  ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_BUFFER_TOO_SMALL;
    }

    const uint8_t major = hello[6];
    const uint8_t minor = hello[7];

    if (major != 1 || minor != 0) {
        // CURVE I: client HELLO has unknown version number
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (),
        //  ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_INVALID_PARAMETER;
    }

    //  Save client's short-term public key (C')
    //memcpy (_cn_client, hello + 80, 32);
    //set_cli_tmp_public(hello + 80);
    memcpy (m_cli_tmp_public, hello + 80, 32);

    uint8_t hello_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> hello_plaintext (
      crypto_box_ZEROBYTES + 64);
    uint8_t hello_box[crypto_box_BOXZEROBYTES + 80];

    memcpy (hello_nonce, "CurveZMQHELLO---", 16);
    memcpy (hello_nonce + 16, hello + 112, 8);
    cn_peer_nonce = get_uint64 (hello + 112);

    memset (hello_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (hello_box + crypto_box_BOXZEROBYTES, hello + 120, 80);

    //  Open Box [64 * %x0](C'->S)
    rc = crypto_box_open (&hello_plaintext[0], hello_box, sizeof hello_box,
                          hello_nonce, m_cli_tmp_public, m_srv_secret_key);
    if (rc != 0) {
        // CURVE I: cannot open client HELLO -- wrong server key?
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_FAILURE;
    }

    state = sending_welcome;

    return OE_OK;
}

#include "time.h"
oe_result_t curve_server_t::produce_welcome(uint8_t** welcome_data_, size_t *welcome_data_len)
{
    uint8_t cookie_nonce[crypto_secretbox_NONCEBYTES];
    std::vector<uint8_t> cookie_plaintext (
      crypto_secretbox_ZEROBYTES + 64);
    uint8_t cookie_ciphertext[crypto_secretbox_BOXZEROBYTES + 80];

    //  Create full nonce for encryption
    //  8-byte prefix plus 16-byte random nonce
    memcpy (cookie_nonce, "COOKIE--", 8);
    randombytes (cookie_nonce + 8, 16);

    crypto_box_keypair(m_srv_tmp_public, m_srv_tmp_secret);

    //  Generate cookie = Box [C' + s'](t)
    std::fill (cookie_plaintext.begin (),
               cookie_plaintext.begin () + crypto_secretbox_ZEROBYTES, 0);
    memcpy (&cookie_plaintext[crypto_secretbox_ZEROBYTES], m_cli_tmp_public, 32);
    memcpy (&cookie_plaintext[crypto_secretbox_ZEROBYTES + 32], m_srv_tmp_secret, 32);

    //  Generate fresh cookie key
    randombytes (_cookie_key, crypto_secretbox_KEYBYTES);

// speed test 
if(0)
{
    Time_F(TM_START);
    int i, total=1000000, rc1;
    for(i=0;i<total;i++)
        rc1 = crypto_secretbox (cookie_ciphertext, &cookie_plaintext[0],
                        cookie_plaintext.size (), cookie_nonce, _cookie_key);
    double tttt = Time_F(TM_STOP);
    printf("%.3lf avg:%.3lf num:%.1lf\n", tttt, tttt/total, total/tttt );
}
    //  Encrypt using symmetric cookie key
    int rc =
      crypto_secretbox (cookie_ciphertext, &cookie_plaintext[0],
                        cookie_plaintext.size (), cookie_nonce, _cookie_key);
    //assert (rc == 0);
    if(rc)
        return OE_FAILURE;

    uint8_t welcome_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> welcome_plaintext (
      crypto_box_ZEROBYTES + 128);
    uint8_t welcome_ciphertext[crypto_box_BOXZEROBYTES + 144];

    //  Create full nonce for encryption
    //  8-byte prefix plus 16-byte random nonce
    memcpy (welcome_nonce, "WELCOME-", 8);
    randombytes (welcome_nonce + 8, crypto_box_NONCEBYTES - 8);

    //  Create 144-byte Box [S' + cookie](S->C')
    std::fill (welcome_plaintext.begin (),
               welcome_plaintext.begin () + crypto_box_ZEROBYTES, 0);
    memcpy (&welcome_plaintext[crypto_box_ZEROBYTES], m_srv_tmp_public, 32);
    memcpy (&welcome_plaintext[crypto_box_ZEROBYTES + 32], cookie_nonce + 8,
            16);
    memcpy (&welcome_plaintext[crypto_box_ZEROBYTES + 48],
            cookie_ciphertext + crypto_secretbox_BOXZEROBYTES, 80);

    //hex_dump_data("welcome_plaintext", &welcome_plaintext[0], welcome_plaintext.size ());

    rc = crypto_box (welcome_ciphertext, &welcome_plaintext[0],
                     welcome_plaintext.size (), welcome_nonce, m_cli_tmp_public,
                     m_srv_secret_key);
    //hex_dump_data("welcome_nonce", welcome_nonce, crypto_box_NONCEBYTES);
    //hex_dump_data("welcome_plaintext", welcome_ciphertext, 144);

    //  TODO I think we should change this back to zmq_assert (rc == 0);
    //  as it was before https://github.com/zeromq/libzmq/pull/1832
    //  The reason given there was that secret_key might be 0ed.
    //  But if it were, we would never get this far, since we could
    //  not have opened the client's hello box with a 0ed key.

    if (rc == -1)
        return OE_FAILURE;

    //rc = msg_->init_size (168);
    //errno_assert (rc == 0);

    *welcome_data_ = (uint8_t *)oe_host_malloc(168);

    uint8_t *const welcome = static_cast<uint8_t *> (*welcome_data_);
    memcpy (welcome, "\x07WELCOME", 8);
    memcpy (welcome + 8, welcome_nonce + 8, 16);
    memcpy (welcome + 24, welcome_ciphertext + crypto_box_BOXZEROBYTES, 144);

    *welcome_data_len = 168;

    return OE_OK;
}


oe_result_t curve_server_t::process_initiate(uint8_t* initiate_data_, int initiate_data_len,
    uint8_t **metadata_plaintext, size_t *metadata_length)
{
    int  rc = 0;
    oe_result_t oe_ret = OE_OK;
    //int rc = check_basic_command_structure (msg_);
    //if (rc == -1)
    //    return -1;

    const size_t size = initiate_data_len;
    const uint8_t *initiate = static_cast<uint8_t *> (initiate_data_);

    if (size < 9 || memcmp (initiate, "\x08INITIATE", 9)) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_INVALID_PARAMETER;
    }

    if (size < 257) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (),
        //  ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return OE_BUFFER_TOO_SMALL;
    }

    uint8_t cookie_nonce[crypto_secretbox_NONCEBYTES];
    uint8_t cookie_plaintext[crypto_secretbox_ZEROBYTES + 64];
    uint8_t cookie_box[crypto_secretbox_BOXZEROBYTES + 80];

    //  Open Box [C' + s'](t)
    memset (cookie_box, 0, crypto_secretbox_BOXZEROBYTES);
    memcpy (cookie_box + crypto_secretbox_BOXZEROBYTES, initiate + 25, 80);

    memcpy (cookie_nonce, "COOKIE--", 8);
    memcpy (cookie_nonce + 8, initiate + 9, 16);

    rc = crypto_secretbox_open (cookie_plaintext, cookie_box, sizeof cookie_box,
                                cookie_nonce, _cookie_key);
    if (rc != 0) {
        // CURVE I: cannot open client INITIATE cookie
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_FAILURE;
    }

    //  Check cookie plain text is as expected [C' + s']
    if (memcmp (cookie_plaintext + crypto_secretbox_ZEROBYTES, m_cli_tmp_public, 32)
        || memcmp (cookie_plaintext + crypto_secretbox_ZEROBYTES + 32,
                   m_srv_tmp_secret, 32)) {
        // TODO this case is very hard to test, as it would require a modified
        //  client that knows the server's secret temporary cookie key

        // CURVE I: client INITIATE cookie is not valid
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_INVALID_PARAMETER;
    }

    const size_t clen = (size - 113) + crypto_box_BOXZEROBYTES;

    uint8_t initiate_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> initiate_plaintext (
      crypto_box_ZEROBYTES + clen);
    std::vector<uint8_t> initiate_box (crypto_box_BOXZEROBYTES + clen);

    //  Open Box [C + vouch + metadata](C'->S')
    std::fill (initiate_box.begin (),
               initiate_box.begin () + crypto_box_BOXZEROBYTES, 0);
    memcpy (&initiate_box[crypto_box_BOXZEROBYTES], initiate + 113,
            clen - crypto_box_BOXZEROBYTES);

    memcpy (initiate_nonce, "CurveZMQINITIATE", 16);
    memcpy (initiate_nonce + 16, initiate + 105, 8);
    cn_peer_nonce = get_uint64 (initiate + 105);

    const uint8_t *client_key = &initiate_plaintext[crypto_box_ZEROBYTES];

    rc = crypto_box_open (&initiate_plaintext[0], &initiate_box[0], clen,
                          initiate_nonce, m_cli_tmp_public, m_srv_tmp_secret);
    if (rc != 0) {
        // CURVE I: cannot open client INITIATE
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        errno = EPROTO;
        return OE_FAILURE;
    }

    uint8_t vouch_nonce[crypto_box_NONCEBYTES];
    std::vector<uint8_t> vouch_plaintext (
      crypto_box_ZEROBYTES + 64);
    uint8_t vouch_box[crypto_box_BOXZEROBYTES + 80];

    //  Open Box Box [C',S](C->S') and check contents
    memset (vouch_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (vouch_box + crypto_box_BOXZEROBYTES,
            &initiate_plaintext[crypto_box_ZEROBYTES + 48], 80);

    memcpy (vouch_nonce, "VOUCH---", 8);
    memcpy (vouch_nonce + 8, &initiate_plaintext[crypto_box_ZEROBYTES + 32],
            16);

    //hex_dump_data("****client_key", client_key, 32);
    rc = crypto_box_open (&vouch_plaintext[0], vouch_box, sizeof vouch_box,
                          vouch_nonce, client_key, m_srv_tmp_secret);
    if (rc != 0) {
        // CURVE I: cannot open client INITIATE vouch
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_FAILURE;
    }

    //  What we decrypted must be the client's short-term public key
    if (memcmp (&vouch_plaintext[crypto_box_ZEROBYTES], m_cli_tmp_public, 32)) {
        // TODO this case is very hard to test, as it would require a modified
        //  client that knows the server's secret short-term key

        // CURVE I: invalid handshake from client (public key)
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE);
        errno = EPROTO;
        TRACE_ENCLAVE("return errno:%d, %s", errno, strerror(errno));
        return OE_INVALID_PARAMETER;
    }

    //  Precompute connection secret from client key
    rc = crypto_box_beforenm (cn_precom, m_cli_tmp_public, m_srv_tmp_secret);
    
    assert (rc == 0);
    if(rc != 0){
         *metadata_length = 0;
        return OE_FAILURE;
    }
    oe_ret = OE_OK;


    *metadata_length = clen - crypto_box_ZEROBYTES - 128;
    *metadata_plaintext = (uint8_t *)oe_host_malloc(*metadata_length);
    memcpy(*metadata_plaintext, &initiate_plaintext[crypto_box_ZEROBYTES + 128], *metadata_length);
    //TRACE_ENCLAVE("return metadata_length:%zu", *metadata_length);

    return oe_ret;
}

oe_result_t curve_server_t::produce_ready(uint8_t *metadata_, size_t metadata_length, 
    uint8_t** ready_data_, size_t *ready_data_len)
{
    //const size_t metadata_length = basic_properties_len ();
    uint8_t ready_nonce[crypto_box_NONCEBYTES];

    std::vector<uint8_t> ready_plaintext (
      crypto_box_ZEROBYTES + metadata_length);

    //  Create Box [metadata](S'->C')
    std::fill (ready_plaintext.begin (),
               ready_plaintext.begin () + crypto_box_ZEROBYTES, 0);
    uint8_t *ptr = &ready_plaintext[crypto_box_ZEROBYTES];

    //ptr += add_basic_properties (ptr, metadata_length);
    memcpy(ptr, metadata_, metadata_length);
    ptr += metadata_length;
    const size_t mlen = ptr - &ready_plaintext[0];

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    put_uint64 (ready_nonce + 16, cn_nonce);

    std::vector<uint8_t> ready_box (crypto_box_BOXZEROBYTES + 16
                                    + metadata_length);

    int rc = crypto_box_afternm (&ready_box[0], &ready_plaintext[0], mlen,
                                 ready_nonce, cn_precom);
    assert (rc == 0);
    //rc = msg_->init_size (14 + mlen - crypto_box_BOXZEROBYTES);
    //assert (rc == 0);
    *ready_data_len = 14 + mlen - crypto_box_BOXZEROBYTES;
    *ready_data_ = (uint8_t *)oe_host_malloc(*ready_data_len);

    uint8_t *ready = static_cast<uint8_t *> (*ready_data_);

    memcpy (ready, "\x05READY", 6);
    //  Short nonce, prefixed by "CurveZMQREADY---"
    memcpy (ready + 6, ready_nonce + 16, 8);
    //  Box [metadata](S'->C')
    memcpy (ready + 14, &ready_box[crypto_box_BOXZEROBYTES],
            mlen - crypto_box_BOXZEROBYTES);

    cn_nonce++;

    return OE_OK;
}

oe_result_t curve_server_t::produceMessage( uint8_t* msg,
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

oe_result_t curve_server_t::processMessage(
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
    // server not compare nonce 
    /*
    if (nonce <= cn_peer_nonce) {
        //session->get_socket ()->event_handshake_failed_protocol (
        //  session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE);
        errno = EPROTO;     
        return OE_FAILURE;
    }
    */
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

    //return rc;

    result = OE_OK;
    return result;
}

void curve_server_t::set_srv_public_key(uint8_t *srv_public_key)
{
    memcpy(m_srv_public_key, srv_public_key, crypto_box_PUBLICKEYBYTES);
}

void curve_server_t::set_srv_secret_key(uint8_t *srv_secret_key)
{
    memcpy(m_srv_secret_key, srv_secret_key, crypto_box_SECRETKEYBYTES);
}

void curve_server_t::set_srv_tmp_public(uint8_t *srv_tmp_public)
{
    memcpy(m_srv_tmp_public, srv_tmp_public, crypto_box_PUBLICKEYBYTES);
}

void curve_server_t::set_srv_tmp_secret(uint8_t *srv_tmp_secret)
{
    memcpy(m_srv_tmp_secret, srv_tmp_secret, crypto_box_SECRETKEYBYTES);
}

void curve_server_t::set_cli_tmp_public(uint8_t *cli_tmp_public)
{
    memcpy(m_cli_tmp_public, cli_tmp_public, crypto_box_PUBLICKEYBYTES);
}
