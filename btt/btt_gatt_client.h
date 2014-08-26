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

#ifdef BTT_GATT_CLIENT_H
	#error Included twince
#endif

#define BTT_GATT_CLIENT_H

#include "btt.h"

enum btt_gatt_client_req_t {
	/*TODO: better number */
	BTT_GATT_CLIENT_REQ_REGISTER_CLIENT = 3000,
	BTT_GATT_CLIENT_REQ_UNREGISTER_CLIENT,
	BTT_GATT_CLIENT_REQ_SCAN,
	BTT_GATT_CLIENT_REQ_CONNECT,
	BTT_GATT_CLIENT_REQ_DISCONNECT,
	BTT_GATT_CLIENT_REQ_LISTEN,
	BTT_GATT_CLIENT_REQ_REFRESH,
	BTT_GATT_CLIENT_REQ_SEARCH_SERVICE,
	BTT_GATT_CLIENT_REQ_GET_INCLUDED_SERVICE,
	BTT_GATT_CLIENT_REQ_GET_CHARAKTERISTIC,
	BTT_GATT_CLIENT_REQ_GET_DESCRIPTOR,
	BTT_GATT_CLIENT_REQ_READ_CHARAKTERISTIC,
	BTT_GATT_CLIENT_REQ_WRITE_CHARAKTERISTIC,
	BTT_GATT_CLIENT_REQ_READ_DESCRIPTOR,
	BTT_GATT_CLIENT_REQ_WRITE_DESCRIPTOR,
	BTT_GATT_CLIENT_REQ_EXECUTE_WRITE,
	BTT_GATT_CLIENT_REQ_REGISTER_FOR_NOTIFICATION,
	BTT_GATT_CLIENT_REQ_DEREGISTER_FOR_NOTIFICATION,
	BTT_GATT_CLIENT_REQ_READ_REMOTE_RSSI,
	BTT_GATT_CLIENT_REQ_GET_DEVICE_TYPE,
	BTT_GATT_CLIENT_REQ_SET_ADV_DATA,
	BTT_GATT_CLIENT_REQ_TEST_COMMAND,
	BTT_GATT_CLIENT_REQ_END
};

struct btt_gatt_client_scan {
	struct btt_message hdr;

	int client_if;
	unsigned int start;
};

struct btt_gatt_client_register_client {
	struct btt_message hdr;

	bt_uuid_t UUID;
};

struct btt_gatt_client_unregister_client {
	struct btt_message hdr;

	int client_if;
};

struct btt_gatt_client_connect {
	struct btt_message hdr;

	int client_if;
	bt_bdaddr_t addr;
	int is_direct;
};

struct btt_gatt_client_disconnect {
	struct btt_message hdr;

	int client_if;
	bt_bdaddr_t addr;
	int conn_id;
};

struct btt_gatt_client_read_remote_rssi {
	struct btt_message hdr;

	int client_if;
	bt_bdaddr_t addr;
};

struct btt_gatt_client_listen {
	struct btt_message hdr;

	int client_if;
	int start;
};

enum btt_gatt_client_cb_t {
	/*TODO: better number */
	BTT_GATT_CLIENT_CB_REGISTER_CLIENT = 2000,
	BTT_GATT_CLIENT_CB_SCAN_RESULT,
	BTT_GATT_CLIENT_CB_CONNECT,
	BTT_GATT_CLIENT_CB_DISCONNECT,
	BTT_GATT_CLIENT_CB_SEARCH_COMPLETE,
	BTT_GATT_CLIENT_CB_SEARCH_RESULT,
	BTT_GATT_CLIENT_CB_GET_CHARAKTERISTIC,
	BTT_GATT_CLIENT_CB_GET_DESCRIPTOR,
	BTT_GATT_CLIENT_CB_GET_INCLUDED_SERVICE,
	BTT_GATT_CLIENT_CB_REGISTER_FOR_NOTIFICATION,
	BTT_GATT_CLIENT_CB_NOTIFY,
	BTT_GATT_CLIENT_CB_READ_CHARAKTERISTIC,
	BTT_GATT_CLIENT_CB_WRITE_CHARAKTERISTIC,
	BTT_GATT_CLIENT_CB_EXECUTE_WRITE,
	BTT_GATT_CLIENT_CB_READ_DESCRIPTOR,
	BTT_GATT_CLIENT_CB_WRITE_DESCIPTOR,
	BTT_GATT_CLIENT_CB_READ_REMOTE_RSSI,
	BTT_GATT_CLIENT_CB_LISTEN,
	BTT_GATT_CLIENT_CB_BT_STATUS,
	BTT_GATT_CLIENT_CB_END
};

struct btt_gatt_client_cb_hdr {
	enum btt_gatt_client_cb_t type;

	uint16_t length;
};

struct btt_gatt_client_cb_scan_result {
	struct btt_gatt_client_cb_hdr hdr;

	uint8_t bd_addr[BD_ADDR_LEN];
	char name[NAME_MAX_LEN];
	int rssi;
	/* 0 - LE Undiscoverable
	 * 1 - LE Limited Discoverable Mode
	 * 2 - LE General Discoverable Mode
	 */
	uint8_t discoverable_mode;
};

static const char *discoverable_mode[3] = {
		"Undiscoverable",
		"LE Limited",
		"LE General"
};

struct btt_gatt_client_cb_register_client {
	struct btt_gatt_client_cb_hdr hdr;

	int status;
	int client_if;
	bt_uuid_t app_uuid;
};

struct btt_gatt_client_cb_bt_status {
	struct btt_gatt_client_cb_hdr hdr;

	bt_status_t status;
};

struct btt_gatt_client_cb_connect {
	struct btt_gatt_client_cb_hdr hdr;

	int conn_id;
	int status;
	int client_if;
	bt_bdaddr_t bda;
};

struct btt_gatt_client_cb_disconnect {
	struct btt_gatt_client_cb_hdr hdr;

	int conn_id;
	int status;
	int client_if;
	bt_bdaddr_t bda;
};

struct btt_gatt_client_cb_read_remote_rssi {
	struct btt_gatt_client_cb_hdr hdr;

	int client_if;
	bt_bdaddr_t addr;
	int rssi;
	int status;
};

struct btt_gatt_client_cb_listen {
	struct btt_gatt_client_cb_hdr hdr;

	int server_if;
	int status;
};

extern void run_gatt_client(int argc, char **argv);
