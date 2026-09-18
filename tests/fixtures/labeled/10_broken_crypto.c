#include <openssl/md5.h>
#include <stddef.h>

void password_digest(
    const unsigned char *password,
    size_t length,
    unsigned char output[MD5_DIGEST_LENGTH])
{
    MD5(password, length, output);
}
