#ifndef CURVE_SERVER_H_
#define CURVE_SERVER_H_

namespace curve_zmq
{

class curve_server_t
{
  public:
    curve_server_t ();
    virtual ~curve_server_t ();

    void set_srv_public_key(uint8_t *srv_public_key);
    void set_srv_secret_key(uint8_t *srv_secret_key);

    void set_srv_tmp_public(uint8_t *srv_tmp_public);
    void set_srv_tmp_secret(uint8_t *srv_tmp_secret);

    void set_cli_tmp_public(uint8_t *cli_tmp_public);

    oe_result_t process_hello(uint8_t* hello_data_, int hello_data_len); 
    oe_result_t produce_welcome(uint8_t** welcome_data_, size_t *welcome_data_len); 
    oe_result_t process_initiate(uint8_t* initiate_data_, int initiate_data_len,
                            uint8_t **metadata_plaintext, size_t *metadata_length); 
    oe_result_t produce_ready(uint8_t *metadata_, size_t metadata_length,
        uint8_t** ready_data_, size_t *ready_data_len); 

    oe_result_t produceMessage( uint8_t* msg,
                        size_t msg_len,
                        uint8_t** enc_msg,
                        size_t* enc_msg_len);
    oe_result_t processMessage(
                        uint8_t* enc_msg,
                        size_t enc_msg_len,
                        uint8_t** msg,
                        size_t* msg_len);

  private:
    enum state_t
    {
        waiting_for_hello,
        sending_welcome,
        waiting_for_initiate,
        waiting_for_zap_reply,
        sending_ready,
        sending_error,
        error_sent,
        ready
    };

    //  Current FSM state
    state_t state;

    //  Server public key (C)
    uint8_t m_srv_public_key[crypto_box_PUBLICKEYBYTES];

    //  Server secret key (c)
    uint8_t m_srv_secret_key[crypto_box_SECRETKEYBYTES];

    //  Server short-term public key (C')
    uint8_t m_srv_tmp_public[crypto_box_PUBLICKEYBYTES];

    //  Server short-term secret key (c')
    uint8_t m_srv_tmp_secret[crypto_box_SECRETKEYBYTES];  

    //  Client short-term public key (C')
    uint8_t m_cli_tmp_public[crypto_box_PUBLICKEYBYTES];

    //  Key used to produce cookie
    uint8_t _cookie_key[crypto_secretbox_KEYBYTES];

    //  Our secret key (s)
    //uint8_t _secret_key[crypto_box_SECRETKEYBYTES];

    //  Intermediary buffer used to speed up boxing and unboxing.
    uint8_t cn_precom[crypto_box_BEFORENMBYTES];

    uint64_t cn_nonce;
    uint64_t cn_peer_nonce;
};

}

#endif