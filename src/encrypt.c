#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>

EVP_PKEY * RSA_generate_keys(EVP_PKEY *rtrn_key) {
    const char *rt_err = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        rt_err="EVP_PKEY_CTX_new_id failed";
        goto err;
    }
    if(EVP_PKEY_keygen_init(ctx)<=0) {
        rt_err="EVP_PKEY_keygen_init failed";
        goto err;
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)<=0) {
        rt_err="EVP_PKEY_CTX_set_rsa_keygen_bits failed";
        goto err;
    }
    if(EVP_PKEY_keygen(ctx, &pkey)<=0) {
        rt_err="EVP_PKEY_keygen failed";
        goto err;
    }
    else if(pkey) {
        rtrn_key = pkey;
        EVP_PKEY_CTX_free(ctx);
        return rtrn_key;
    }
    
err:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) return pkey;
    printf("[ERROR]: %s\n", rt_err);
    return NULL;
}
int RSA_write(EVP_PKEY *RSA_key, const char *pubkey_file, const char *privkey_file) {
    FILE *fp = NULL;
    if ((fp = fopen(pubkey_file, "wb")) == NULL) {
        printf("Failed to open public key file for writing.\n");
        return -1;
    }
    PEM_write_PUBKEY(fp, RSA_key);
    fclose(fp);
    if ((fp = fopen(privkey_file, "wb")) == NULL) {
        printf("Failed to open private key file for writing.\n");
        return -1;
    }
    PEM_write_PrivateKey(fp, RSA_key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    return 0;
}
EVP_PKEY *RSA_read(const char *pubkey_file, const char *privkey_file){
    FILE *fp = NULL;
    EVP_PKEY *RSA_key = NULL;
    if ((fp = fopen(pubkey_file, "rb")) == NULL) {
        printf("Failed to open public key file for reading.\n");
        return NULL;
    }
    RSA_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!RSA_key) {
        printf("Failed to read public key from file.\n");
        return NULL;
    }
    if ((fp = fopen(privkey_file, "rb")) == NULL) {
        printf("Failed to open private key file for reading.\n");
        return NULL;
    }
    RSA_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!RSA_key) {
        printf("Failed to read private key from file.\n");
        return NULL;
    }
    return RSA_key;
}

int main() {
    EVP_PKEY *key = NULL;
    key = RSA_generate_keys(key);
    if (key) {
        printf("RSA key pair generated successfully.\n");
    } else {
        printf("Failed to generate RSA key pair.\n");
    }
    if(RSA_write(key, "pubkey.pem", "privkey.pem") != 0) {
        printf("Failed to write RSA key pair to files.\n");
    }
    else {
        printf("RSA key pair written to files successfully.\n");
    }
    EVP_PKEY_free(key);
    key = RSA_read("pubkey.pem", "privkey.pem");
    if (key) {
        printf("RSA key pair read from files successfully.\n");
    } else {
        printf("Failed to read RSA key pair from files.\n");
    }
    EVP_PKEY_free(key);
    return 0;
}