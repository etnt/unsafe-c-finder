#include <sodium.h>
#include <stddef.h>

int password_digest(
    const char *password,
    size_t length,
    const unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char output[32])
{
    return crypto_pwhash(
        output, 32, password, length, salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13);
}
