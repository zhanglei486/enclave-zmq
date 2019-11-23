#ifndef CURVE_CLIENT_H_
#define CURVE_CLIENT_H_

namespace curve_zmq
{

class curve_client_t
{
  public:
    curve_client_t ();
    virtual ~curve_client_t ();

    void set_cli_public_key(uint8_t *cli_public_key);
    void set_cli_secret_key(uint8_t *cli_secret_key);

    void set_cli_tmp_public(uint8_t *cli_tmp_public);
    void set_cli_tmp_secret(uint8_t *cli_tmp_secret);

    void set_srv_public_key(uint8_t *srv_public_key);
    void set_srv_tmp_public(uint8_t *srv_tmp_public);


    oe_result_t produce_hello(uint8_t* hello_data_);
    oe_result_t process_welcome(uint8_t* welcome_data_, int welcome_data_len);

    oe_result_t produce_initiate(const uint8_t *metadata_plaintext_,
                          const size_t metadata_length_,
                          uint8_t** initiate_data_, size_t *initiate_data_len
                        );
    oe_result_t process_ready(uint8_t* ready_data_, int ready_data_len, 
         uint8_t **metadata_, size_t *metadata_length);

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
        send_hello,
        expect_welcome,
        send_initiate,
        expect_ready,
        error_received,
        connected
    };

    //  Current FSM state
    state_t _state;

    //  Client public key (C)
    uint8_t m_cli_public_key[crypto_box_PUBLICKEYBYTES];

    //  Client secret key (c)
    uint8_t m_cli_secret_key[crypto_box_SECRETKEYBYTES];

    //  Client short-term public key (C')
    uint8_t m_cli_tmp_public[crypto_box_PUBLICKEYBYTES];

    //  Client short-term secret key (c')
    uint8_t m_cli_tmp_secret[crypto_box_SECRETKEYBYTES];

    //  Server public key (S)
    uint8_t m_srv_public_key[crypto_box_PUBLICKEYBYTES];
    //  Server short-term public key (S')
    uint8_t m_srv_tmp_public[crypto_box_PUBLICKEYBYTES];

    //  Cookie received from server
    uint8_t cn_cookie[16 + 80];

    //  Intermediary buffer used to speed up boxing and unboxing.
    uint8_t cn_precom[crypto_box_BEFORENMBYTES];

    uint64_t cn_nonce;
    uint64_t cn_peer_nonce;
};

}


#endif //CURVE_CLIENT_H_