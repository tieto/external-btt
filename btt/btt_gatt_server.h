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

#include "btt.h"

enum btt_gatt_server_req_t {
	BTT_GATT_SERVER_REQ_REGISTER_SERVER = 3000,
	BTT_GATT_SERVER_REQ_UNREGISTER_SERVER,
	BTT_GATT_SERVER_REQ_CONNECT,
	BTT_GATT_SERVER_REQ_END
};

enum btt_gatt_server_cb_t {
	BTT_GATT_SERVER_CB_REGISTER_SERVER = 2000,
	BTT_GATT_SERVER_CB_CONNECT,
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

struct btt_gatt_server_cb_status {
	struct btt_gatt_server_cb_hdr hdr;

	int status;
};

extern void run_gatt_server(int argc, char **argv);
