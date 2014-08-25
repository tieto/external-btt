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

#include "btt.h"
#include "btt_daemon_gatt_server.h"
#include "btt_gatt_server.h"
#include "btt_utils.h"

#include <hardware/bt_gatt.h>

extern const btgatt_server_interface_t *gatt_server_if;
extern int socket_remote;

void handle_gatt_server_cmd(const struct btt_message *btt_msg,
		const int socket_remote)
{
	switch (btt_msg->command) {
	case BTT_GATT_SERVER_CMD_REGISTER_SERVER:
	{
		struct btt_gatt_server_reg msg;

		if (!RECV(&msg, socket_remote)) {
			BTT_LOG_E("Received invalid btt_gatt_server_reg\n");
			close(socket_remote);
			return;
		}

		gatt_server_if->register_server(&msg.UUID);
		break;
	}
	default: break;
	}
}

/*************************************************************/
/* Gatt server: callbacks, necessary functions and structure */
/*************************************************************/

static void register_server_cb(int status, int server_if, bt_uuid_t *app_uuid)
{
	struct btt_gatt_server_cb_reg_result btt_cb;

	btt_cb.hdr.type = BTT_GATT_SERVER_CB_REGISTER_SERVER;
	btt_cb.hdr.length = sizeof(struct btt_gatt_server_cb_reg_result)
			- sizeof(struct btt_gatt_server_cb_hdr);
	btt_cb.status = status;
	btt_cb.server_if = server_if;
	memcpy(&btt_cb.app_uuid, app_uuid, sizeof(bt_uuid_t));

	BTT_LOG_D("Callback_GS Server Register");

	if (send(socket_remote, &btt_cb,
			sizeof(struct btt_gatt_server_cb_reg_result), 0) == -1)
		 BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
}

static btgatt_server_callbacks_t sGattServerCallbacks = {
		register_server_cb,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
};

btgatt_server_callbacks_t *getGattServerCallbacks(void)
{
	return &sGattServerCallbacks;
}
