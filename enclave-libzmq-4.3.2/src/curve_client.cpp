/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include "macros.hpp"

#ifdef ZMQ_HAVE_CURVE

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "curve_client.hpp"
#include "wire.hpp"
#include "curve_client_tools.hpp"

#include "enclave_curve_u.h"
#define USE_ENCLAVE

zmq::curve_client_t::curve_client_t (session_base_t *session_,
                                     const options_t &options_) :
    mechanism_base_t (session_, options_),
    curve_mechanism_base_t (
      session_, options_, "CurveZMQMESSAGEC", "CurveZMQMESSAGES"),
    _state (send_hello),
    _tools (options_.curve_public_key,
            options_.curve_secret_key,
            options_.curve_server_key)
{
}

zmq::curve_client_t::~curve_client_t ()
{
}

int zmq::curve_client_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (_state) {
        case send_hello:
            rc = produce_hello (msg_);
            if (rc == 0)
                _state = expect_welcome;
            break;
        case send_initiate:
            rc = produce_initiate (msg_);
            if (rc == 0)
                _state = expect_ready;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
    }
    return rc;
}

int zmq::curve_client_t::process_handshake_command (msg_t *msg_)
{
    const unsigned char *msg_data =
      static_cast<unsigned char *> (msg_->data ());
    const size_t msg_size = msg_->size ();

    int rc = 0;
    if (curve_client_tools_t::is_handshake_command_welcome (msg_data, msg_size))
        rc = process_welcome (msg_data, msg_size);
    else if (curve_client_tools_t::is_handshake_command_ready (msg_data,
                                                               msg_size))
        rc = process_ready (msg_data, msg_size);
    else if (curve_client_tools_t::is_handshake_command_error (msg_data,
                                                               msg_size))
        rc = process_error (msg_data, msg_size);
    else {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        rc = -1;
    }

    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    return rc;
}

int zmq::curve_client_t::encode (msg_t *msg_)
{
    zmq_assert (_state == connected);
    return curve_mechanism_base_t::encode (msg_);
}

int zmq::curve_client_t::decode (msg_t *msg_)
{
    zmq_assert (_state == connected);
    return curve_mechanism_base_t::decode (msg_);
}

zmq::mechanism_t::status_t zmq::curve_client_t::status () const
{
    if (_state == connected)
        return mechanism_t::ready;
    if (_state == error_received)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

int zmq::curve_client_t::produce_hello (msg_t *msg_)
{
    int rc = msg_->init_size (200);
    errno_assert (rc == 0);

#ifdef USE_ENCLAVE
    oe_result_t result = OE_OK;
    oe_enclave_t* enclave = (oe_enclave_t *)_enclave;
    uint8_t *helloMsg=NULL;
    size_t helloMsgLen;
    enclave_ProduceHello(enclave, &result, &helloMsg, &helloMsgLen);
    if(result!=OE_OK){
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        return -1;
    }
    uint8_t *hello = static_cast<uint8_t *> (msg_->data());
    memcpy(hello, helloMsg, helloMsgLen);
    if(helloMsg)
	    free(helloMsg);
#else    
    rc = _tools.produce_hello (msg_->data (), cn_nonce);
    if (rc == -1) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);

        // TODO this is somewhat inconsistent: we call init_size, but we may
        // not close msg_; i.e. we assume that msg_ is initialized but empty
        // (if it were non-empty, calling init_size might cause a leak!)

        // msg_->close ();
        return -1;
    }
#endif    

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_welcome (const uint8_t *msg_data_,
                                          size_t msg_size_)
{
#ifdef USE_ENCLAVE
    int rc = 0;
    oe_result_t result;
    oe_enclave_t *enclave = (oe_enclave_t *)_enclave;
    uint8_t *welcomeMsg = (u_int8_t *)malloc(msg_size_);
    memcpy(welcomeMsg, msg_data_, msg_size_); 
    enclave_ProcessWelcome(enclave, &result, welcomeMsg, msg_size_);
    free(welcomeMsg);
    if(result!=OE_OK)
	    rc = -1;
#else	
    int rc = _tools.process_welcome (msg_data_, msg_size_, cn_precom);
#endif

    if (rc == -1) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);

        errno = EPROTO;
        return -1;
    }

    _state = send_initiate;

    return 0;
}

int zmq::curve_client_t::produce_initiate (msg_t *msg_)
{
    const size_t metadata_length = basic_properties_len ();
    unsigned char *metadata_plaintext =
      static_cast<unsigned char *> (malloc (metadata_length));
    alloc_assert (metadata_plaintext);

    add_basic_properties (metadata_plaintext, metadata_length);

    size_t msg_size = 113 + 128 + crypto_box_BOXZEROBYTES + metadata_length;
    int rc = msg_->init_size (msg_size);
    errno_assert (rc == 0);

#ifdef USE_ENCLAVE
    oe_result_t result;
    oe_enclave_t *enclave = (oe_enclave_t *)_enclave;
    uint8_t *initiateMsg=NULL;
    size_t initiateMsgLen;


    enclave_ProduceInitiate(enclave, &result, metadata_plaintext, metadata_length,
        &initiateMsg, &initiateMsgLen);
    if(result!=OE_OK)
	rc = -1;
    else{
        uint8_t *initiate = static_cast<uint8_t *> (msg_->data());
	memcpy( initiate, initiateMsg, initiateMsgLen);
	free(initiateMsg);
	rc = 0;
    }
#else    
    rc = _tools.produce_initiate (msg_->data (), msg_size, cn_nonce,
                                  metadata_plaintext, metadata_length);
#endif

    free (metadata_plaintext);

    if (-1 == rc) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);

        // TODO see comment in produce_hello
        return -1;
    }

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_ready (const uint8_t *msg_data_,
                                        size_t msg_size_)
{
    if (msg_size_ < 30) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY);
        errno = EPROTO;
        return -1;
    }

#ifdef USE_ENCLAVE   
    int rc=0;
    oe_result_t result;
    oe_enclave_t *enclave = (oe_enclave_t *)_enclave;
    uint8_t *readyMsg = (uint8_t *)malloc(msg_size_);
    memcpy(readyMsg, msg_data_, msg_size_);
    cn_peer_nonce = get_uint64 (msg_data_ + 6);

    uint8_t *metaMsgOut;
    size_t metaMsgLen;

    enclave_ProcessReady(enclave, &result, readyMsg, msg_size_, &metaMsgOut, &metaMsgLen);
    free(readyMsg);
    if(result!=OE_OK){
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        return -1;
    }
    rc = parse_metadata ( metaMsgOut, metaMsgLen );
    _state = connected;
    free(metaMsgOut);
    if (rc == 0)
        _state = connected;
    else {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);
        errno = EPROTO;
    }


    return rc;
#else    
    const size_t clen = (msg_size_ - 14) + crypto_box_BOXZEROBYTES;

    uint8_t ready_nonce[crypto_box_NONCEBYTES];
    uint8_t *ready_plaintext =
      static_cast<uint8_t *> (malloc (crypto_box_ZEROBYTES + clen));
    alloc_assert (ready_plaintext);
    uint8_t *ready_box =
      static_cast<uint8_t *> (malloc (crypto_box_BOXZEROBYTES + 16 + clen));
    alloc_assert (ready_box);

    memset (ready_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (ready_box + crypto_box_BOXZEROBYTES, msg_data_ + 14,
            clen - crypto_box_BOXZEROBYTES);

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    memcpy (ready_nonce + 16, msg_data_ + 6, 8);
    cn_peer_nonce = get_uint64 (msg_data_ + 6);

    int rc = crypto_box_open_afternm (ready_plaintext, ready_box, clen,
                                      ready_nonce, cn_precom);
    free (ready_box);

    if (rc != 0) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        return -1;
    }

    rc = parse_metadata (ready_plaintext + crypto_box_ZEROBYTES,
                         clen - crypto_box_ZEROBYTES);
    free (ready_plaintext);

    if (rc == 0)
        _state = connected;
    else {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);
        errno = EPROTO;
    }

    return rc;
#endif    
}

int zmq::curve_client_t::process_error (const uint8_t *msg_data_,
                                        size_t msg_size_)
{
    if (_state != expect_welcome && _state != expect_ready) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    if (msg_size_ < 7) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);
        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len = static_cast<size_t> (msg_data_[6]);
    if (error_reason_len > msg_size_ - 7) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);
        errno = EPROTO;
        return -1;
    }
    const char *error_reason = reinterpret_cast<const char *> (msg_data_) + 7;
    handle_error_reason (error_reason, error_reason_len);
    _state = error_received;
    return 0;
}

#endif
