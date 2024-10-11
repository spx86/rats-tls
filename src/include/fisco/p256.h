#ifndef P256_H
#define P256_H

void generate_keys(const char* private_path, const char* public_path); 
unsigned char* sign(const char* msg, const char* sk_path, const char* sign_path, const char* pk_path);
char* read_public_key_hex(const char *filepath);
#endif // P256_H  
