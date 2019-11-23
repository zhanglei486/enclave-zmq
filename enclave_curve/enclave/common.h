// common.h
// zhanglei486@126.com
//

extern const char* enclave_name;

#define TRACE_ENCLAVE(fmt, ...)    \
                                   \
    printf(                        \
        "%s ***%s(%d): " fmt "\n", \
        enclave_name,              \
        __FILE__,                  \
        __LINE__,                  \
        ##__VA_ARGS__)


inline void put_uint64 (unsigned char *buffer_, uint64_t value_)
{
    buffer_[0] = static_cast<unsigned char> (((value_) >> 56) & 0xff);
    buffer_[1] = static_cast<unsigned char> (((value_) >> 48) & 0xff);
    buffer_[2] = static_cast<unsigned char> (((value_) >> 40) & 0xff);
    buffer_[3] = static_cast<unsigned char> (((value_) >> 32) & 0xff);
    buffer_[4] = static_cast<unsigned char> (((value_) >> 24) & 0xff);
    buffer_[5] = static_cast<unsigned char> (((value_) >> 16) & 0xff);
    buffer_[6] = static_cast<unsigned char> (((value_) >> 8) & 0xff);
    buffer_[7] = static_cast<unsigned char> (value_ & 0xff);
}

inline uint64_t get_uint64 (const unsigned char *buffer_)
{
    return ((static_cast<uint64_t> (buffer_[0])) << 56)
           | ((static_cast<uint64_t> (buffer_[1])) << 48)
           | ((static_cast<uint64_t> (buffer_[2])) << 40)
           | ((static_cast<uint64_t> (buffer_[3])) << 32)
           | ((static_cast<uint64_t> (buffer_[4])) << 24)
           | ((static_cast<uint64_t> (buffer_[5])) << 16)
           | ((static_cast<uint64_t> (buffer_[6])) << 8)
           | (static_cast<uint64_t> (buffer_[7]));
}
