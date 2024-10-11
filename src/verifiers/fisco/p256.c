#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "fisco/p256.h"

// Function declarations
void generate_keys(const char* private_path, const char* public_path);
EC_KEY* load_private_key(const char* path);
void save_public_key(EC_POINT *pubkey, EC_GROUP *group, const char *filepath);
void save_signature(ECDSA_SIG* sig, const char* filepath);
unsigned char* sign_message(EC_KEY* eckey, const char* msg, const char* sign_path, const char* public_path);

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

unsigned char* sign(const char* msg, const char* sk_path, const char* sign_path, const char* pk_path) {
    // Check if private key exists
    struct stat st = {0};

    EC_KEY *eckey = NULL;

    eckey = load_private_key(sk_path);

    // Sign a message
    unsigned char *output = sign_message(eckey, msg, sign_path, pk_path);
	unsigned char *hex_output = (char*)malloc(321);
    memset(hex_output, 0, 321);
	for (size_t i = 0; i < 160; i++) {
		sprintf(hex_output+2*i, "%02x", output[i]);
    }
	hex_output[320] = '\0';
	free(output);
    EC_KEY_free(eckey);
    return hex_output;
}

void generate_keys(const char* private_path, const char* public_path) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(eckey);

    // Save private key
    FILE *pFile = fopen(private_path, "w");
    PEM_write_ECPrivateKey(pFile, eckey, NULL, NULL, 0, NULL, NULL);
    fclose(pFile);

    // Save public key
    pFile = fopen(public_path, "w");
    PEM_write_EC_PUBKEY(pFile, eckey);
    fclose(pFile);

    EC_KEY_free(eckey);
}

EC_KEY* load_private_key(const char* path) {
    FILE *pFile = fopen(path, "r");
    EC_KEY *eckey = PEM_read_ECPrivateKey(pFile, NULL, NULL, NULL);
    fclose(pFile);
    return eckey;
}

unsigned char* sign_message(EC_KEY* eckey, const char* msg, const char* sign_path, const char* public_path) {
    struct stat st = {0};
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)msg, strlen(msg), hash);

    ECDSA_SIG *sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, eckey);
    if (!sig) {
        fprintf(stderr, "Failed to sign message\n");
        return NULL;
    }

    save_signature(sig, sign_path);

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);

    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);
    int x_len, y_len;

    const EC_POINT *pubkey = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if(stat(public_path, &st) == -1){
        save_public_key(pubkey, group, public_path);
    }
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!x || !y || !EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, NULL)) {
        fprintf(stderr, "Failed to get EC coordinates\n");
        BN_free(x);
        BN_free(y);
        ECDSA_SIG_free(sig);
        return NULL;
    }

    x_len = BN_num_bytes(x);
    y_len = BN_num_bytes(y);

    unsigned char* output = (unsigned char*)malloc(r_len + s_len + x_len + y_len + SHA256_DIGEST_LENGTH);
    if (!output) {
        fprintf(stderr, "Failed to allocate output buffer\n");
        BN_free(x);
        BN_free(y);
        ECDSA_SIG_free(sig);
        return NULL;
    }

    int offset = 0;
    memcpy(output + offset, hash, SHA256_DIGEST_LENGTH);
    offset += SHA256_DIGEST_LENGTH;
    offset += BN_bn2bin(r, output + offset);
    offset += BN_bn2bin(s, output + offset);
    offset += BN_bn2bin(x, output + offset);
    offset += BN_bn2bin(y, output + offset);

    // Free resources
    BN_free(x);
    BN_free(y);
    ECDSA_SIG_free(sig);

    return output;
}

void save_public_key(EC_POINT *pubkey, EC_GROUP *group, const char *filepath) {
    char *hex = EC_POINT_point2hex(group, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (!hex) {
        fprintf(stderr, "Failed to convert EC_POINT to hex.\n");
        return;
    }

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("Failed to open file");
        OPENSSL_free(hex);
        return;
    }

//    fprintf(fp, "%s\n", hex);
    fclose(fp);
    OPENSSL_free(hex);
}

void save_signature(ECDSA_SIG* sig, const char* filepath) {

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char sig_path[256];
    // Ensure the directory ends with a slash
    snprintf(sig_path, sizeof(sig_path), "%s/signature_%04d%02d%02d%02d%02d%02d.sig",
             filepath, // Directory path
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    unsigned char *der = NULL;
    int derlen = i2d_ECDSA_SIG(sig, &der);
    if (derlen < 0 || der == NULL) {
        fprintf(stderr, "Failed to encode signature in DER format\n");
        return;
    }

    FILE *file = fopen(sig_path, "wb");
    if (file == NULL) {
        perror("Failed to open file");
        OPENSSL_free(der);
        return;
    }

    fwrite(der, 1, derlen, file);
    fclose(file);
    OPENSSL_free(der);

}

char* read_public_key_hex(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        perror("Failed to open file");
        return NULL;
    }

    // 移动文件指针到文件末尾以计算文件长度
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);  // 回到文件开头

    // 分配内存以存储16进制公钥字符串
    char *hex = (char*)malloc(filesize + 1);
    if (!hex) {
        fprintf(stderr, "Memory allocation error.\n");
        fclose(fp);
        return NULL;
    }

    // 读取文件内容
    if (fread(hex, 1, filesize, fp) != filesize) {
        fprintf(stderr, "Error reading file.\n");
        free(hex);
        fclose(fp);
        return NULL;
    }
    
    hex[filesize] = '\0';  // 确保以空字符结尾
    fclose(fp);
    return hex;
}

