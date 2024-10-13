#include "fisco/crud.h"
#include "fisco/p256.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "bcos-c-sdk/bcos_sdk_c_error.h"
#include "bcos-c-sdk/bcos_sdk_c_rpc.h"
#include "bcos-c-sdk/bcos_sdk_c_uti_abi.h"
#include "bcos-c-sdk/bcos_sdk_c_uti_keypair.h"
#include "bcos-c-sdk/bcos_sdk_c.h"
#include "bcos-c-sdk/bcos_sdk_c_uti_tx.h"

void init(char* config_file);
void get_chain_id(void* sdk, char* group_id);
void get_block_limit(void* sdk, char* group_id);
void get_key_pair(int sm_crypto);

BlockchainConfig blockchain_config={0};
Table table = {0};

Config process_config(const char* config_file) {
    Config config;

    json_object *parsed_json;
    json_object *jcontract_addr;
    json_object *jabi_path;
    json_object *jsm_crypto;
    json_object *jconfig_ini;
    json_object *jgroup_id;
    json_object *jpk_path;
	json_object *jsk_path;
	json_object *jsign_path;

    parsed_json = json_object_from_file(config_file);
    if (!parsed_json) {
        fprintf(stderr, "Error parsing JSON file\n");
        exit(EXIT_FAILURE);
    }

    json_object_object_get_ex(parsed_json, "contractAddr", &jcontract_addr);
    json_object_object_get_ex(parsed_json, "abi", &jabi_path);
    json_object_object_get_ex(parsed_json, "smCrypto", &jsm_crypto);
    json_object_object_get_ex(parsed_json, "configIni", &jconfig_ini);
    json_object_object_get_ex(parsed_json, "groupId", &jgroup_id);
	json_object_object_get_ex(parsed_json, "pk_path", &jpk_path);
	json_object_object_get_ex(parsed_json, "sk_path", &jsk_path);
	json_object_object_get_ex(parsed_json, "sign_path", &jsign_path);

    json_object *jabi = json_object_from_file(json_object_get_string(jabi_path));
    const char* abi_str = json_object_to_json_string_ext(jabi, JSON_C_TO_STRING_PRETTY);
    
	config.contract_addr = strdup(json_object_get_string(jcontract_addr));
	config.abi = abi_str;
    config.sm_crypto = json_object_get_int(jsm_crypto);
    config.config_ini = strdup(json_object_get_string(jconfig_ini));
    config.group_id = strdup(json_object_get_string(jgroup_id));
	config.pk_path = strdup(json_object_get_string(jpk_path));
	config.sk_path = strdup(json_object_get_string(jsk_path));
	config.sign_path = strdup(json_object_get_string(jsign_path));
    
	json_object_put(parsed_json); // free json object
    return config;
}

void parse_output_from_response(const char* response) {
    // Parse the JSON response
    json_object *jobj = json_tokener_parse(response);
    json_object *jresult, *joutput;

    // Navigate through the JSON structure
    if (json_object_object_get_ex(jobj, "result", &jresult)) {
        if (json_object_object_get_ex(jresult, "output", &joutput)) {
            const char *output = json_object_get_string(joutput);
            const char* decode_get_data = bcos_sdk_abi_decode_method_output(blockchain_config.config.abi, "select", output, blockchain_config.config.sm_crypto);
            //bcos_rpc_call(sdk, config.group_id, "", config.contract_addr, decode_get_data, on_call_resp_callback, NULL);
            printf("decode_get_data: %s\n", decode_get_data);
            // Further processing can be done here depending on the format of 'output'
        } else {
            printf("field not found.\n");
        }
    } else {
        printf("Result object not found.\n");
    }

    // Clean up
    json_object_put(jobj);
}

void on_send_tx_resp_callback(struct bcos_sdk_c_struct_response* resp)
{
    if (resp->error != BCOS_SDK_C_SUCCESS)
    {
        printf("\t send tx failed, error: %d, message: %s\n", resp->error, resp->desc);
        exit(-1);
    }

//    printf(" ===>> send tx resp: %s\n", (char*)resp->data);
}

void on_call_resp_callback(struct bcos_sdk_c_struct_response* resp)
{
    if (resp->error != BCOS_SDK_C_SUCCESS)
    {
        printf("\t call failed, error: %d, message: %s\n", resp->error, resp->desc);
        exit(-1);
    }
    parse_output_from_response((char*)resp->data);
}

void init(char* config_file){
	printf("starting init\n");
    Config config = process_config(config_file);
    blockchain_config.config = config;
    blockchain_config.sdk = bcos_sdk_create_by_config_file(config.config_ini);
	bcos_sdk_start(blockchain_config.sdk);
    get_chain_id(blockchain_config.sdk, config.group_id);
    get_block_limit(blockchain_config.sdk, config.group_id);
    get_key_pair(config.sm_crypto);
	printf("init successfully\n");
}

void get_chain_id(void* sdk, char* group_id){
    const char* chain_id = bcos_sdk_get_group_chain_id(sdk, group_id);
    if (!bcos_sdk_is_last_opr_success())
    {
        printf("bcos_sdk_get_group_chain_id failed, error: %s\n",
            bcos_sdk_get_last_error_msg());
        exit(-1);
    }
    blockchain_config.chain_id = chain_id;
}

void get_block_limit(void* sdk, char* group_id){
    int64_t block_limit = bcos_rpc_get_block_limit(sdk, group_id);
    if (block_limit < 0)
    {
        printf("group not exist, group: %s\n", group_id);
        exit(-1);
    }
    blockchain_config.block_limit = block_limit;
}

void get_key_pair(int sm_crypto){
    void* key_pair = bcos_sdk_create_keypair(sm_crypto);
    if (!key_pair)
    {
        printf("create keypair failed, error: %s\n", bcos_sdk_get_last_error_msg());
        exit(-1);
    }
    blockchain_config.key_pair = key_pair;
}

//insert or update tee table in smart contract
void I_U_tee_table(char* data, char* op){
    char* tx_hash = NULL;
    char* signed_tx = NULL;
    const char* extra_data = op;
    const char* set_data = bcos_sdk_abi_encode_method(blockchain_config.config.abi, \
                op, \
                data, \
                blockchain_config.config.sm_crypto);
    if (!set_data)
    {
        printf("bcos_sdk_abi_encode_method failed, error: %s\n", bcos_sdk_get_last_error_msg());
        exit(-1);
    }
    {
        void* transaction_data = bcos_sdk_create_transaction_data(blockchain_config.config.group_id, \
                blockchain_config.chain_id, \
                blockchain_config.config.contract_addr, \
                set_data, \
                blockchain_config.config.abi, \
                blockchain_config.block_limit);
        const char* transaction_data_hash = bcos_sdk_calc_transaction_data_hash(blockchain_config.config.sm_crypto, \
                transaction_data);
        const char* signed_hash = bcos_sdk_sign_transaction_data_hash(blockchain_config.key_pair, transaction_data_hash);
        const char* signed_tx = bcos_sdk_create_signed_transaction_with_signed_data_ver_extra_data(transaction_data, signed_hash, transaction_data_hash, 0, extra_data);
        bcos_rpc_send_transaction(blockchain_config.sdk, \
                blockchain_config.config.group_id, \
                "", \
                signed_tx, \
                0, \
                on_send_tx_resp_callback, \
                NULL);
        sleep(1);
        bcos_sdk_destroy_transaction_data(transaction_data);
        bcos_sdk_c_free((void*)transaction_data_hash);
        bcos_sdk_c_free((void*)signed_hash);
        bcos_sdk_c_free((void*)signed_tx);
    }
    bcos_sdk_c_free((void*)tx_hash);
    bcos_sdk_c_free((void*)signed_tx);
}

void select_tee_table(char* data){
    const char* get_data = bcos_sdk_abi_encode_method(blockchain_config.config.abi, \
                "select", \
                data, \
                blockchain_config.config.sm_crypto);
    if (!get_data)
    {
        printf("bcos_sdk_abi_encode_method failed, error: %s\n", bcos_sdk_get_last_error_msg());
        exit(-1);
    }
    bcos_rpc_call(blockchain_config.sdk, \
            blockchain_config.config.group_id, \
            "", \
            blockchain_config.config.contract_addr, \
            get_data, \
            on_call_resp_callback, \
            NULL);
	sleep(1);
}

void get_table_info(){
        const char* get_data = bcos_sdk_abi_encode_method(blockchain_config.config.abi, \
                "desc", \
                "[]", \
                blockchain_config.config.sm_crypto);
    if (!get_data)
    {
        printf("bcos_sdk_abi_encode_method failed, error: %s\n", bcos_sdk_get_last_error_msg());
        exit(-1);
    }
    bcos_rpc_call(blockchain_config.sdk, \
            blockchain_config.config.group_id, \
            "", \
            blockchain_config.config.contract_addr, \
            get_data, \
            on_call_resp_callback, \
            NULL);
	sleep(1);
}

void destory_sdk(){
    // free chain_id
    bcos_sdk_c_free((void*)blockchain_config.chain_id);
    if (blockchain_config.config.contract_addr)
    {
        bcos_sdk_c_free((void*)blockchain_config.config.contract_addr);
    }
    // stop sdk
    bcos_sdk_stop(blockchain_config.sdk);
    // release sdk
    bcos_sdk_destroy(blockchain_config.sdk);
    // release keypair
    bcos_sdk_destroy_keypair(blockchain_config.key_pair);
}

int op_to_int(const char* op) {
    if (strcmp(op, "insert") == 0) return INSERT;
    if (strcmp(op, "update") == 0) return UPDATE;
    if (strcmp(op, "remove") == 0) return REMOVE;
    if (strcmp(op, "select") == 0) return SELECT;
    if (strcmp(op, "desc") == 0)   return DESC;
    return -1;  // Unknown operation
}

char* get_current_time() {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char *buffer = (char*)malloc(20 * sizeof(char));
    if (buffer == NULL) {
        return NULL;  // 处理内存分配失败
    }
    
    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;  // 返回分配好的字符串
}

char* format_insert_data(int op) {
    char* formatted_string;
    int needed_size;

    switch (op) {
        case INSERT:
        case UPDATE:
            needed_size = snprintf(NULL, 0, 
                           "[\"hex://%s\",\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]", 
                           table.p256_sign, table.id, table.name, table.status, table.owner, table.last_update, table.pk) + 1;
            break;
        case REMOVE:
            needed_size = snprintf(NULL, 0, 
                           "[\"hex://%s\",\"%s\"]", 
                           table.p256_sign, table.id) + 1;
            break;
        case SELECT:
            needed_size = snprintf(NULL, 0, 
                           "[\"%s\"]", 
                           table.id) + 1;
            break;
        case DESC:
            break;
        default:
            printf("Unknown operation: %d\n", op);
            break;
    }
    // Allocate memory for the formatted string
    formatted_string = malloc(needed_size);
    if (formatted_string == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    switch (op) {
        case INSERT:
        case UPDATE:
            sprintf(formatted_string, 
                "[\"hex://%s\",\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"]", 
                table.p256_sign, table.id, table.name, table.status, table.owner, table.last_update, table.pk);
            break;
        case REMOVE:
            sprintf(formatted_string, 
                "[\"hex://%s\",\"%s\"]", 
                table.p256_sign, table.id);
            break;
        case SELECT:
            sprintf(formatted_string, 
                "[\"%s\"]", 
                table.id);
            break;
        case DESC:
            break;
        default:
            printf("Unknown operation: %d\n", op);
            break;
    }
//	printf("%d formatted string: %s\n", op, formatted_string);
    return formatted_string;
}

char* format_sign_data(){
	char* formatted_string;
	int needed_size = snprintf(NULL, 0,
		"%s%s%s%s%s%s",
		table.id, table.name, table.status, table.owner, table.last_update, table.pk) + 1;
    formatted_string = malloc(needed_size);
   	if (formatted_string == NULL) {
        // 如果内存分配失败，返回 NULL
        printf("Failed to allocate memory for formatted string\n");
        return NULL;
    }
	sprintf(formatted_string,
		"%s%s%s%s%s%s",
		 table.id, table.name, table.status, table.owner, table.last_update, table.pk);
	return formatted_string;
}

void get_data(){
	struct stat st = {0};
	#ifdef SGX
    table.name="SGX";
	#elif OCCLUM
    table.name="Occlum";
	#else
    table.name="Unknown";
	#endif
    table.status="true";
    table.last_update=get_current_time();
	
	if (stat(blockchain_config.config.sk_path, &st) == -1) {
        // Key doesn't exist, generate new keys
        generate_keys(blockchain_config.config.sk_path, 
					  blockchain_config.config.pk_path);
    }
	char* pk= read_public_key_hex(blockchain_config.config.pk_path);
	table.id = pk;
	table.pk = pk;
	table.owner = pk;
	char* formatted_string = format_sign_data();
    table.p256_sign=sign(formatted_string,  \
                         blockchain_config.config.sk_path, \
                         blockchain_config.config.sign_path, \
                         blockchain_config.config.pk_path);
	printf("get data successfully\n");
}

void tee_table_handle(char* op){
    switch (op_to_int(op)) {
        case INSERT:
            // Insert data into the blockchain
			printf("INSERT\n");
            I_U_tee_table(format_insert_data(INSERT), op);
            break;
        case UPDATE:
            // Update data in the blockchain
			printf("UPDATE\n");
            I_U_tee_table(format_insert_data(UPDATE), op);
            break;
        case REMOVE:
            // Remove data from the blockchain
			printf("REMOVE\n");
            I_U_tee_table(format_insert_data(REMOVE), op);
            break;
        case SELECT:
            // Fetch data from the blockchain
			printf("SELECT\n");
            select_tee_table(format_insert_data(SELECT));
            break;
        case DESC:
            // Describe data or structure
            get_table_info();
            break;
        default:
            printf("Unknown operation: %s\n", op);
            break;
    }
}

int main(int argc, char** argv){
    const char* config_file = argv[1];

    init(config_file);
	get_data();
    //get_table_info();
    // char* insert_data = "[\"hex://0x32f4985f385cf93ead0bb8f374b36031cd395e0715a89475996f34854fc32973043ab5c0dff0f771df039a9caa93fdd0d4dfb5886ca7bc5671d314d7f09d630f0c739e34fed785565823ab10b81a2e988b739197e47a684b1cfbb09178ce5cec700ce49f838b79c6e5d8b3e1f06f414232204225fd261a0cb1f6da8a5186e5892dff57ab16ca9885f8ecec3edeb0c4600e7e9a6e37963c3cd2b03952c09ab8ae\",\"fuf1234\", \"DUN\", \"is\", \"a\", \"good\", \"person\"]";
    //printf("data:%s\n", insert_data);
	 // tee_table_handle(insert_data, INSERT);
    // char* select_data = "[\"fuf1234\"]";
    // select_tee_table(select_data);
    // char* update_data = "[\"hex://0x32f4985f385cf93ead0bb8f374b36031cd395e0715a89475996f34854fc32973043ab5c0dff0f771df039a9caa93fdd0d4dfb5886ca7bc5671d314d7f09d630f0c739e34fed785565823ab10b81a2e988b739197e47a684b1cfbb09178ce5cec700ce49f838b79c6e5d8b3e1f06f414232204225fd261a0cb1f6da8a5186e5892dff57ab16ca9885f8ecec3edeb0c4600e7e9a6e37963c3cd2b03952c09ab8ae\",\"fuf1234\", \"DUN1\", \"is1\", \"a1\", \"good1\", \"person1\"]";
    // tee_table_handle(update_data, UPDATE);
    // select_tee_table(select_data);
    // char* remove_data = "[\"hex://0x32f4985f385cf93ead0bb8f374b36031cd395e0715a89475996f34854fc32973043ab5c0dff0f771df039a9caa93fdd0d4dfb5886ca7bc5671d314d7f09d630f0c739e34fed785565823ab10b81a2e988b739197e47a684b1cfbb09178ce5cec700ce49f838b79c6e5d8b3e1f06f414232204225fd261a0cb1f6da8a5186e5892dff57ab16ca9885f8ecec3edeb0c4600e7e9a6e37963c3cd2b03952c09ab8ae\",\"fuf1234\"]";
    // char* remove_data = "[\"hex://0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd28084824ee243396b683054100db5ac57660f248f6c77e81c531599c90799e75fa01b4532ea863e6ef8cfd242b2b3d06436c94214a823852da75c61ca31968346b0d5bec2875540b7bec28755000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"fuf1234\"]";
    // tee_table_handle(remove_data, REMOVE);
    // select_tee_table(select_data);
    tee_table_handle("insert");
    tee_table_handle("select");
	tee_table_handle("remove");
    destory_sdk();
}



