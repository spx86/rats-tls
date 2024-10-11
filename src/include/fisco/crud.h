#ifndef CRUD_H
#define CRUD_H

#include "bcos-c-sdk/bcos_sdk_c.h"
 
#define INSERT 1
#define UPDATE 2
#define REMOVE 3
#define SELECT 4
#define DESC   5

// Define the Config structure
typedef struct Config{
    char* contract_addr;
    char* abi;
    int sm_crypto;
    char* config_ini;
    char* group_id;
    char* pk_path;
    char* sk_path;
    char* sign_path;
} Config;

typedef struct BlockchainConfig{
    Config config;
    void* sdk;
    const char* chain_id;
    int64_t block_limit;
    void* key_pair;
} BlockchainConfig;

// Define the Table structure
typedef struct Table{
    char* p256_sign;
    char* id;   //did
    char* name; //platform name, such as "SGX" "Occlum"
    char* status; //verified or not
    char* owner;
    char* last_update;
    char* pk; 
} Table;

// Function declarations
void init(char* config_file);
void tee_table_handle(char* op);
void get_data();
void destory_sdk();
#endif // CRUD_H




