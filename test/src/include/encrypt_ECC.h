#ifndef ENCRYPT_ECC_H
#define ENCRYPT_ECC_H

#include <openssl/evp.h>

EVP_PKEY *ECC_generate_keys(EVP_PKEY *rtrn_key);

int ECC_write(EVP_PKEY *ECC_key, const char *pubkey_file, const char *privkey_file);

EVP_PKEY *ECC_read(const char *pubkey_file, const char *privkey_file);

unsigned char *ECC_pub_encrypt(EVP_PKEY *ECC_key, const unsigned char *msg, size_t *encrypted_msg_length);

unsigned char *ECC_priv_decrypt(EVP_PKEY *ECC_key, const unsigned char *encrypted_msg, 
                                size_t encrypted_msg_length, size_t *decrypted_msg_length);

#endif /* ENCRYPT_ECC_H */









