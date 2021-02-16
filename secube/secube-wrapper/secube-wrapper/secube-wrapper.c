#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include "L1.h"

se3_device* se3_device_alloc() {
	return (se3_device*)calloc(1, sizeof(se3_device));
}
se3_disco_it* se3_disco_it_alloc() {
	return (se3_disco_it*)calloc(1, sizeof(se3_disco_it));
}
se3_device_info* se3_disco_it_get_device_info(se3_disco_it* it) {
	return &(it->device_info);
}
void* se3_device_info_get_path(se3_device_info* info) {
	return (void*)info->path;
}
unsigned char* se3_device_info_get_serialno(se3_device_info* info) {
	return info->serialno;
}
unsigned char* se3_device_info_get_hello_msg(se3_device_info* info) {
	return info->hello_msg;
}
unsigned int se3_device_info_get_status(se3_device_info* info) {
	return (unsigned int)info->status;
}
se3_session* se3_session_alloc() {
	return (se3_session*)calloc(1, sizeof(se3_session));
}
int se3_session_logged_in(se3_session* s) {
	return s->logged_in ? 1 : 0;
}
se3_key* se3_key_alloc(unsigned int n) {
	return (se3_key*)calloc(n, sizeof(se3_key));
}
void se3_key_set_id(se3_key* k, unsigned int index, unsigned int id) {
	k += index;
	k->id = (uint32_t)id;
}
void se3_key_set_validity(se3_key* k, unsigned int index, unsigned int validity) {
	k += index;
	k->validity = (uint32_t)validity;
}
void se3_key_set_data(se3_key* k, unsigned int index, unsigned int data_size, unsigned char* data) {
	k += index;
	k->data_size = (uint16_t)data_size;
	k->data = data;
}
void se3_key_set_name(se3_key* k, unsigned int index, unsigned int name_size, unsigned char* name) {
	k += index;
	if (name_size > SE3_KEY_NAME_MAX) {
		name_size = SE3_KEY_NAME_MAX;
	}
	k->name_size = (uint16_t)name_size;
	memcpy(k->name, name, name_size);
}
unsigned int se3_key_get_id(se3_key* k, unsigned int index) {
	k += index;
	return (unsigned int)k->id;
}
unsigned int se3_key_get_validity(se3_key* k, unsigned int index) {
	k += index;
	return (unsigned int)k->validity;
}
unsigned int se3_key_get_data_size(se3_key* k, unsigned int index) {
	k += index;
	return (unsigned int)k->data_size;
}
unsigned int se3_key_get_name_size(se3_key* k, unsigned int index) {
	k += index;
	return (unsigned int)k->name_size;
}
unsigned char* se3_key_get_fingerprint(se3_key* k, unsigned int index) {
	k += index;
	return k->fingerprint;
}
unsigned char* se3_key_get_data(se3_key* k, unsigned int index) {
	k += index;
	return k->data;
}
unsigned char* se3_key_get_name(se3_key* k, unsigned int index) {
	k += index;
	return k->name;
}
se3_algo* se3_algo_alloc(unsigned int n) {
	return (se3_algo*)calloc(n, sizeof(se3_algo));
}
unsigned char* se3_algo_get_name(se3_algo* algo, unsigned int index) {
	algo += index;
	return algo->name;
}
unsigned int se3_algo_get_block_size(se3_algo* algo, unsigned int index) {
	algo += index;
	return algo->block_size;
}
unsigned int se3_algo_get_key_size(se3_algo* algo, unsigned int index) {
	algo += index;
	return algo->key_size;
}
unsigned int se3_algo_get_type(se3_algo* algo, unsigned int index) {
	algo += index;
	return algo->type;
}

void se3_free(void* p) {
	free(p);
}

