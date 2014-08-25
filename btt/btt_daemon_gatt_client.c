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
#include "btt_utils.h"
#include "btt_gatt_client.h"
#include "btt_eir_data_types.h"

#include <hardware/bt_gatt.h>

extern const bt_interface_t *bluetooth_if;
extern const btgatt_client_interface_t *gatt_client_if;
extern const btgatt_interface_t *gatt_if;
extern struct list_element *list;
extern int socket_remote;

/*TODO: add checking condition, like adapter status*/
void handle_gatt_client_cmd(const struct btt_message *btt_msg,
		const int socket_remote)
{
	struct btt_gatt_client_cb_bt_status bt_stat;
	bt_status_t status = BT_STATUS_SUCCESS;

	bt_stat.hdr.type = BTT_GATT_CLIENT_CB_BT_STATUS;
	bt_stat.hdr.length = sizeof(struct btt_gatt_client_cb_bt_status)
					- sizeof(struct btt_gatt_client_cb_hdr);
	bt_stat.status = BT_STATUS_SUCCESS;

	switch (btt_msg->command) {
	case BTT_CMD_GATT_CLIENT_REGISTER_CLIENT:
	{
		struct btt_gatt_client_register_client msg;

		if (!RECV(&msg, socket_remote)) {
			BTT_LOG_E("Error: incorrect size of received structure.\n");
			status = BT_STATUS_FAIL;
			break;
		}

		gatt_client_if->register_client(&msg.UUID);
		break;
	}
	case BTT_CMD_GATT_CLIENT_SCAN:
	{
		struct btt_gatt_client_scan msg;

		if (!RECV(&msg, socket_remote)) {
			BTT_LOG_E("Error: incorrect size of received structure.\n");
			status = BT_STATUS_FAIL;
			break;
		}

		status = gatt_client_if->scan(msg.client_if, msg.start);
		break;
	}
	case BTT_CMD_GATT_CLIENT_UNREGISTER_CLIENT:
	{
		struct btt_gatt_client_unregister_client msg;

		if (!RECV(&msg, socket_remote)) {
			BTT_LOG_E("Error: incorrect size of received structure.\n");
			status = BT_STATUS_FAIL;
			break;
		}

		status = gatt_client_if->unregister_client((msg.client_if));
		break;
	}
	default:
		status = BT_STATUS_UNHANDLED;
		break;
	}

	bt_stat.status = status;
	BTT_LOG_E("%d\n", fcntl(socket_remote, F_GETFL));

	if (send(socket_remote, (const char *) &bt_stat,
			sizeof(struct btt_gatt_client_cb_bt_status), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
}

/************************************************************/
/* Gatt client: callbacks, necessary functions and structure */
/************************************************************/

/*Search Complete or Shortened Local Name in adv_data
 * by type, function return length of name*/
static uint8_t name_searcher( uint8_t *adv_data, char *name)
{
	uint8_t temp_len = adv_data[0];
	uint8_t temp_type = adv_data[1];
	uint8_t *temp_ptr = adv_data;
	uint8_t name_len;

	while (1) {
		if (temp_type == COMPLETE_LOCAL_NAME ||
				temp_type == SHORTENED_LOCAL_NAME) {
			if (temp_len > 1) {
				name_len = temp_len;
				strncpy(name, (char *) (temp_ptr + sizeof(uint8_t) * 2),
						temp_len - 1);
				name[temp_len - 1] = '\0';
				return name_len;
			} else {
				name = "";
				return 1;
			}
		}

		if (temp_len == 0) {
			name = "N/A";
			return 4;
		}

		temp_ptr += sizeof(uint8_t) * (temp_len + 1);
		temp_len = temp_ptr[0];
		temp_type = temp_ptr[1];
	}
}

/*Search Flags in adv_data by type,
 * function return discoverable mode of device*/
static uint8_t discoverable_mode_searcher(uint8_t *adv_data)
{
	uint8_t temp_len = adv_data[0];
	uint8_t temp_type = adv_data[1];
	uint8_t *temp_ptr = adv_data;

	while (1) {
		if (temp_type == FLAGS) {
			if (temp_len == 2)
				return *(temp_ptr + sizeof(uint8_t) * 2) & 0x03;
			else
				return 0x00;
		}

		if (temp_len == 0) {
			return 0x00;
		}

		temp_ptr += sizeof(uint8_t) * (temp_len + 1);
		temp_len = temp_ptr[0];
		temp_type = temp_ptr[1];

	}
}

bool equal_BD_ADDR(void *first, void *second)
{
	if (!memcmp(first, second, BD_ADDR_LEN))
		return TRUE;
	else
		return FALSE;
}

/*adding address bda to list of scanned address*/
static bool add_address(uint8_t *bda)
{
	if (!bda)
		return FALSE;

	if (!list_contains(list, bda, equal_BD_ADDR)) {
		list = list_append(list, bda);
		return TRUE;
	}

	return FALSE;
}

static void register_client_cb(int status, int client_if,
		bt_uuid_t *app_uuid)
{
	struct btt_gatt_client_cb_register_client btt_cb;

	btt_cb.hdr.type = BTT_GATT_CLIENT_CB_REGISTER_CLIENT;
	btt_cb.hdr.length = sizeof(struct btt_gatt_client_cb_register_client)
					- sizeof(struct btt_gatt_client_cb_hdr);
	btt_cb.status = status;
	btt_cb.client_if = client_if;
	memcpy(&btt_cb.app_uuid, app_uuid, sizeof(*app_uuid));

	BTT_LOG_D("Callback_GC Client Register");

	if (send(socket_remote, (const char *) &btt_cb,
			sizeof(struct btt_gatt_client_cb_register_client), 0) == -1)
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
}

static void scan_result_cb(bt_bdaddr_t *bda, int rssi, uint8_t *adv_data)
{
	struct btt_gatt_client_cb_scan_result btt_cb;
	char name[256];
	char tekst[adv_data[0]];
	uint8_t *bt_address = (bda->address);
	uint8_t name_len;
	uint8_t *bdacpy;

	memset(name, 0, sizeof(name));

	bdacpy = malloc(BD_ADDR_LEN);
	memcpy(bdacpy, bda->address, BD_ADDR_LEN);
	name_len = 0;
	memset(&btt_cb, 0, sizeof(btt_cb));
	btt_cb.hdr.type = BTT_GATT_CLIENT_CB_SCAN_RESULT;
	btt_cb.hdr.length = sizeof(struct btt_gatt_client_cb_scan_result)
					- sizeof(struct btt_gatt_client_cb_hdr);
	BTT_LOG_D("Callback_GC Scan Result");

	if (!list || !list_contains(list, bda, equal_BD_ADDR)) {
		add_address(bdacpy);
		name_len = name_searcher(adv_data, &name[0]);
		strncpy(btt_cb.name, (const char *) name, name_len);
		memcpy(btt_cb.bd_addr, bda, BD_ADDR_LEN);
		btt_cb.discoverable_mode = discoverable_mode_searcher(adv_data);
		BTT_LOG_E("%d\n", fcntl(socket_remote, F_GETFL));

		if (send(socket_remote, (const char *) &btt_cb,
				sizeof(struct btt_gatt_client_cb_scan_result), 0) == -1) {
			BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
		}
	}
	/* do NOT close(socket_remote) here,
	 * we will continue sending the found device info to client one by one
	 */
}

static void connect_cb(int conn_id, int status, int client_if,
		bt_bdaddr_t* bda)
{
	BTT_LOG_D("Callback_GC Connect");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void disconnect_cb(int conn_id, int status, int client_if,
		bt_bdaddr_t* bda)
{
	BTT_LOG_D("Callback_GC Disconnect");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void search_complete_cb(int conn_id, int status)
{
	BTT_LOG_D("Callback_GC Search Complete");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void search_result_cb(int conn_id, btgatt_srvc_id_t *srvc_id)
{
	BTT_LOG_D("Callback_GC Search Result");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void get_characteristic_cb(int conn_id, int status,
		btgatt_srvc_id_t *srvc_id, btgatt_gatt_id_t *char_id, int char_prop)
{
	BTT_LOG_D("Callback_GC Get Charakteristic");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void get_descriptor_cb(int conn_id, int status, btgatt_srvc_id_t
		*srvc_id, btgatt_gatt_id_t *char_id, btgatt_gatt_id_t *descr_id)
{
	BTT_LOG_D("Callback_GC Get Descriptor");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void get_included_service_cb(int conn_id, int status,
		btgatt_srvc_id_t *srvc_id, btgatt_srvc_id_t *incl_srvc_id)
{
	BTT_LOG_D("Callback_GC Get Included Service");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void register_for_notification_cb(int conn_id, int registered,
		int status, btgatt_srvc_id_t *srvc_id, btgatt_gatt_id_t *char_id)
{
	BTT_LOG_D("Callback_GC Register For Notification");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void notify_cb(int conn_id, btgatt_notify_params_t *p_data)
{
	BTT_LOG_D("Callback_GC Notify");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void read_characteristic_cb(int conn_id, int status,
		btgatt_read_params_t *p_data)
{
	BTT_LOG_D("Callback_GC Read Charakteristic");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void write_characteristic_cb(int conn_id, int status,
		btgatt_write_params_t *p_data)
{
	BTT_LOG_D("Callback_GC Write Charakteristic");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void execute_write_cb(int conn_id, int status)
{
	BTT_LOG_D("Callback_GC Write Execute Write");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void read_descriptor_cb(int conn_id, int status,
		btgatt_read_params_t *p_data)
{
	BTT_LOG_D("Callback_GC Read Descriptor");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void write_descriptor_cb(int conn_id, int status,
		btgatt_write_params_t *p_data)
{
	BTT_LOG_D("Callback_GC Write Descriptor");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void read_remote_rssi_cb(int client_if, bt_bdaddr_t* bda,
		int rssi, int status)
{
	BTT_LOG_D("Callback_GC Read Remote RSSI");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static void listen_cb(int status, int server_if)
{
	BTT_LOG_D("Callback_GC Listen");
	BTT_LOG_E("NOT IMPLEMENTED");
}

static btgatt_client_callbacks_t sGattClientCallbacks = {
		register_client_cb,
		scan_result_cb,
		connect_cb,
		disconnect_cb,
		search_complete_cb,
		search_result_cb,
		get_characteristic_cb,
		get_descriptor_cb,
		get_included_service_cb,
		register_for_notification_cb,
		notify_cb,
		read_characteristic_cb,
		write_characteristic_cb,
		read_descriptor_cb,
		write_descriptor_cb,
		execute_write_cb,
		read_remote_rssi_cb,
		listen_cb
};

btgatt_client_callbacks_t *getGattClientCallbacks(void)
{
	return &sGattClientCallbacks;
}
