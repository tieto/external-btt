/*
 * Copyright 2014 Tieto Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef BTT_GATT_SERVER_H
	#error Included twince
#endif

#define BTT_GATT_SERVER_H
#define BTGATT_MAX_ATTR_LEN 600

#include "btt.h"
#include <hardware/bt_gatt_types.h>
#include <hardware/bt_gatt_server.h>

enum btt_gatt_server_req_t {
	BTT_GATT_SERVER_REQ_REGISTER_SERVER = 3000,
	BTT_GATT_SERVER_REQ_UNREGISTER_SERVER,
	BTT_GATT_SERVER_REQ_CONNECT,
	BTT_GATT_SERVER_REQ_DISCONNECT,
	BTT_GATT_SERVER_REQ_ADD_SERVICE,
	BTT_GATT_SERVER_REQ_ADD_INCLUDED_SERVICE,
	BTT_GATT_SERVER_REQ_ADD_CHARACTERISTIC,
	BTT_GATT_SERVER_REQ_ADD_DESCRIPTOR,
	BTT_GATT_SERVER_REQ_START_SERVICE,
	BTT_GATT_SERVER_REQ_STOP_SERVICE,
	BTT_GATT_SERVER_REQ_DELETE_SERVICE,
	BTT_GATT_SERVER_REQ_SEND_INDICATION,
	BTT_GATT_SERVER_REQ_SEND_RESPONSE,
	BTT_GATT_SERVER_REQ_END
};

enum btt_gatt_server_cb_t {
	BTT_GATT_SERVER_CB_REGISTER_SERVER = 2000,
	BTT_GATT_SERVER_CB_CONNECT,
	BTT_GATT_SERVER_CB_ADD_SERVICE,
	BTT_GATT_SERVER_CB_ADD_INCLUDED_SERVICE,
	BTT_GATT_SERVER_CB_ADD_CHARACTERISTIC,
	BTT_GATT_SERVER_CB_ADD_DESCRIPTOR,
	BTT_GATT_SERVER_CB_START_SERVICE,
	BTT_GATT_SERVER_CB_STOP_SERVICE,
	BTT_GATT_SERVER_CB_DELETE_SERVICE,
	BTT_GATT_SERVER_CB_REQUEST_READ,
	BTT_GATT_SERVER_CB_REQUEST_WRITE,
	BTT_GATT_SERVER_CB_REQUEST_EXEC_WRITE,
	BTT_GATT_SERVER_CB_RESPONSE_CONFIRMATION,
	BTT_GATT_SERVER_CB_END
};

struct btt_gatt_server_reg {
	struct btt_message hdr;

	bt_uuid_t UUID;
};

struct btt_gatt_server_unreg {
	struct btt_message hdr;

	int server_if;
};

struct btt_gatt_server_connect {
	struct btt_message hdr;

	int server_if;
	bt_bdaddr_t bd_addr;
	int is_direct;
};

struct btt_gatt_server_disconnect {
	struct btt_message hdr;

	int server_if;
	bt_bdaddr_t bd_addr;
	int conn_id;
};

struct btt_gatt_server_add_service {
	struct btt_message hdr;

	int server_if;
	btgatt_srvc_id_t srvc_id;
	int num_handles;
};

struct btt_gatt_server_add_included_srvc {
	struct btt_message hdr;

	int server_if;
	int service_handle;
	int included_handle;
};

struct btt_gatt_server_add_characteristic {
	struct btt_message hdr;

	int server_if;
	int service_handle;
	bt_uuid_t uuid;
	int properties;
	int permissions;
};

struct btt_gatt_server_add_descriptor {
	struct btt_message hdr;

	int server_if;
	int service_handle;
	bt_uuid_t uuid;
	int permissions;
};

struct btt_gatt_server_start_service {
	struct btt_message hdr;

	int server_if;
	int service_handle;
	int transport;
};

struct btt_gatt_server_stop_service {
	struct btt_message hdr;

	int server_if;
	int service_handle;
};

struct btt_gatt_server_delete_service {
	struct btt_message hdr;

	int server_if;
	int service_handle;
};

struct btt_gatt_server_send_indication {
	struct btt_message hdr;

	int server_if;
	int attribute_handle;
	int conn_id;
	int len;
	int confirm;
	char p_value[BTGATT_MAX_ATTR_LEN];
};

struct btt_gatt_server_send_response {
	struct btt_message hdr;

	int conn_id;
	int trans_id;
	int status;
	btgatt_response_t response;
};

/* Structures for callbacks */

struct btt_gatt_server_cb_hdr {
	enum btt_gatt_server_cb_t type;

	uint16_t length;
};

struct btt_gatt_server_cb_reg_result {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	bt_uuid_t app_uuid;
};

struct btt_gatt_server_cb_connect {
	struct btt_gatt_server_cb_hdr hdr;

	int conn_id;
	int server_if;
	int connected;
	bt_bdaddr_t bda;
};

struct btt_gatt_server_cb_add_service {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	btgatt_srvc_id_t srvc_id;
	int srvc_handle;
};

struct btt_gatt_server_cb_add_included_srvc {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	int srvc_handle;
	int incl_srvc_handle;
};

struct btt_gatt_server_cb_add_characteristic {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	bt_uuid_t uuid;
	int srvc_handle;
	int char_handle;
};

struct btt_gatt_server_cb_add_descriptor {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	bt_uuid_t uuid;
	int srvc_handle;
	int descr_handle;
};

struct btt_gatt_server_cb_start_service {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	int srvc_handle;
};

struct btt_gatt_server_cb_stop_service {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	int srvc_handle;
};

struct btt_gatt_server_cb_delete_service {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int server_if;
	int srvc_handle;
};

struct btt_gatt_server_cb_status {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
};

struct btt_gatt_server_cb_request_read {
	struct btt_gatt_server_cb_hdr hdr;

	int conn_id;
	int trans_id;
	bt_bdaddr_t bda;
	int attr_handle;
	int offset;
	int is_long;
};

struct btt_gatt_server_cb_request_write {
	struct btt_gatt_server_cb_hdr hdr;

	int conn_id;
	int trans_id;
	bt_bdaddr_t bda;
	int attr_handle;
	int offset;
	int length;
	int need_rsp;
	int is_prep;
	uint8_t value[BTGATT_MAX_ATTR_LEN];
};

struct btt_gatt_server_cb_request_exec_write {
	struct btt_gatt_server_cb_hdr hdr;

	int conn_id;
	int trans_id;
	bt_bdaddr_t bda;
	int exec_write;
};

struct btt_gatt_server_cb_response_confirmation {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
	int handle;
};

extern void run_gatt_server(int argc, char **argv);
