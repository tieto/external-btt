/*
 * Copyright 2013 Tieto Corporation
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
#include "btt_adapter.h"

extern const bt_interface_t *bluetooth_if;
extern int socket_remote;

bool turning_on_adapter = FALSE;
bool bonding_peer_dev   = FALSE;

void handle_adapter_cmd(const struct btt_message *btt_msg,
		const int socket_remote)
{
	switch (btt_msg->command) {
	case BTT_CMD_ADAPTER_UP:
		/* TODO: detect status of adapter and fix reply*/
		if (bluetooth_if->enable() == BT_STATUS_SUCCESS)
			turning_on_adapter = TRUE;
		break;
	case BTT_CMD_ADAPTER_DOWN:
		bluetooth_if->disable();
		break;
	case BTT_CMD_ADAPTER_NAME:
		bluetooth_if->get_adapter_property(BT_PROPERTY_BDNAME);
		break;
	case BTT_CMD_ADAPTER_ADDRESS:
		bluetooth_if->get_adapter_property(BT_PROPERTY_BDADDR);
		break;
	case BTT_CMD_ADAPTER_SCAN:
		bluetooth_if->start_discovery();
		break;
	case BTT_CMD_ADAPTER_SCAN_MODE: {
		struct btt_msg_cmd_adapter_scan_mode msg;
		bt_property_t  prop;
		bt_scan_mode_t scan_mode;

		prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE;
		prop.len  = sizeof(bt_scan_mode_t);

		recv(socket_remote, &msg, sizeof(msg), 0);

		if (msg.mode == 0)
			scan_mode = BT_SCAN_MODE_NONE;
		else if (msg.mode == 1)
			scan_mode = BT_SCAN_MODE_CONNECTABLE;
		else if (msg.mode == 2)
			scan_mode = BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
		else
			scan_mode = BT_SCAN_MODE_NONE;

		prop.val = &scan_mode;

		bluetooth_if->set_adapter_property(&prop);
		break;
	}
	case BTT_CMD_ADAPTER_PAIR: {
		struct btt_msg_cmd_adapter_pair msg;

		recv(socket_remote, &msg, sizeof(msg), 0);

		if (bluetooth_if->create_bond((bt_bdaddr_t *)msg.addr) ==
				BT_STATUS_SUCCESS)
			bonding_peer_dev = TRUE;
		break;
	}
	case BTT_CMD_ADAPTER_UNPAIR: {
		struct btt_msg_cmd_adapter_pair msg;

		recv(socket_remote, &msg, sizeof(msg), 0);

		bluetooth_if->remove_bond((bt_bdaddr_t *)msg.addr);
		break;
	}
	case BTT_RSP_PIN_REPLY: {
		struct btt_msg_cmd_pin msg;

		recv(socket_remote, &msg, sizeof(msg), 0);

		bluetooth_if->pin_reply((bt_bdaddr_t const *)msg.addr,
				msg.accept, msg.pin_len,
				(bt_pin_code_t *)msg.pin_code);
		break;
	}
	case BTT_RSP_SSP_REPLY: {
		struct btt_msg_cmd_ssp msg;

		recv(socket_remote, &msg, sizeof(msg), 0);

		bluetooth_if->ssp_reply((bt_bdaddr_t const *)msg.addr,
				(bt_ssp_variant_t)msg.variant,
				msg.accept, msg.passkey);
		break;
	}
	default:
		break;
	}
}

/*
 * Be careful to close socket in the callback functions below.
 * Some of commands, like BTT_CMD_ADAPTER_UP, trigger calling
 * several callback fucntions in succession. You must make
 * sure that the socket is only be closed in the last callback
 * function which uses the socket to send message to client.
 */

static void btt_cb_adapter_state_changed(bt_state_t state)
{
	struct btt_cb_adapter_state btt_cb;

	BTT_LOG_I("Callback Adapter State Changed");

	FILL_HDR(btt_cb, BTT_ADAPTER_STATE_CHANGED);

	if (state == BT_STATE_OFF)
		btt_cb.state = false;
	else
		btt_cb.state = true;

	turning_on_adapter = FALSE;

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_state), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
	close(socket_remote);
}

static void btt_cb_adapter_properties(bt_status_t status,
		int num_properties, bt_property_t *properties)
{
	int i = num_properties;

	while (i-- > 0) {
		switch (properties[i].type) {
		case BT_PROPERTY_BDNAME: {
			struct btt_cb_adapter_name btt_cb;

			BTT_LOG_I("Callback Adapter Name");

			btt_cb.hdr.command   = BTT_ADAPTER_NAME;
			btt_cb.hdr.length = properties[i].len;

			strncpy(btt_cb.name,
					(const char *)properties[i].val, properties[i].len);
			btt_cb.name[btt_cb.hdr.length + 1] = '\0';

			if (send(socket_remote, (const char *)&btt_cb,
					sizeof(struct btt_cb_adapter_name), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
			}
			if (turning_on_adapter == FALSE)
				close(socket_remote);
			break;
		}
		case BT_PROPERTY_BDADDR: {
			struct btt_cb_adapter_addr btt_cb;

			BTT_LOG_I("Callback Adapter Address");

			btt_cb.hdr.command   = BTT_ADAPTER_ADDRESS;
			btt_cb.hdr.length = properties[i].len;

			memcpy(btt_cb.bd_addr, properties[i].val, sizeof(bt_bdaddr_t));

			if (send(socket_remote, (const char *)&btt_cb,
					sizeof(struct btt_cb_adapter_addr), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
			}
			if (turning_on_adapter == FALSE)
				close(socket_remote);
			break;
		}
		case BT_PROPERTY_UUIDS:
		case BT_PROPERTY_CLASS_OF_DEVICE:
		case BT_PROPERTY_TYPE_OF_DEVICE:
		case BT_PROPERTY_SERVICE_RECORD:
			break;
		case BT_PROPERTY_ADAPTER_SCAN_MODE: {
			struct btt_cb_adapter_scan_mode_changed btt_cb;
			bt_scan_mode_t *scan_mode = (bt_scan_mode_t *)properties[i].val;

			BTT_LOG_I("Callback Adapter Scan Mode");

			FILL_HDR(btt_cb, BTT_ADAPTER_SCAN_MODE_CHANGED);

			switch (*scan_mode) {
			case BT_SCAN_MODE_NONE:
				btt_cb.mode = 0;
				break;
			case BT_SCAN_MODE_CONNECTABLE:
				btt_cb.mode = 1;
				break;
			case BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE:
				btt_cb.mode = 2;
				break;
			default:
				break;
			}

			if (send(socket_remote, (const char *)&btt_cb,
					sizeof(struct btt_cb_adapter_addr), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 3\n", __FUNCTION__);
			}
			if (turning_on_adapter == FALSE)
				close(socket_remote);
			break;
		}
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
		default :
			break;
		}
	}
}

static void btt_cb_remote_device_properties(bt_status_t status,
		bt_bdaddr_t *bd_addr, int num_properties,
		bt_property_t *properties)
{
	BTT_LOG_I("Callback Remote Device Properties");
}

static void btt_cb_device_found(int num_properties, bt_property_t *properties)
{
	int i = num_properties;
	struct btt_cb_adapter_device_found btt_cb;

	memset(&btt_cb, 0, sizeof(btt_cb));
	FILL_HDR(btt_cb, BTT_ADAPTER_DEVICE_FOUND);

	BTT_LOG_I("Callback Device Found Properties");

	while (i-- > 0) {
		switch (properties[i].type) {
		case BT_PROPERTY_BDNAME:
			strncpy(btt_cb.name, (const char *)properties[i].val,
					properties[i].len);
			btt_cb.name[properties[i].len] = '\0';
			break;
		case BT_PROPERTY_BDADDR:
			memcpy(btt_cb.bd_addr, properties[i].val, properties[i].len);
			break;
		case BT_PROPERTY_CLASS_OF_DEVICE:
		case BT_PROPERTY_TYPE_OF_DEVICE:
		case BT_PROPERTY_SERVICE_RECORD:
		default :
			break;
		}
	}

	BTT_LOG_E("%d\n", fcntl(socket_remote, F_GETFL));

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_device_found), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
	/* do NOT close(socket_remote) here,
	 * we will continue sending the found device info to client one by one
	 */
}

static void btt_cb_discovery_state_changed(bt_discovery_state_t state)
{
	struct btt_cb_adapter_discovery btt_cb;

	FILL_HDR(btt_cb, BTT_ADAPTER_DISCOVERY);

	BTT_LOG_I("Callback Discovery State Changed");

	if (state == BT_DISCOVERY_STOPPED)
		btt_cb.state = false;
	else
		btt_cb.state = true;

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_discovery), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}

	if (state == BT_DISCOVERY_STOPPED)
		close(socket_remote);
}

static void btt_cb_pin_request(bt_bdaddr_t *remote_bd_addr,
		bt_bdname_t *bd_name, uint32_t cod)
{
	struct btt_cb_adapter_pin_request btt_cb;

	BTT_LOG_I("Callback Pin Request");

	FILL_HDR(btt_cb, BTT_ADAPTER_PIN_REQUEST);
	btt_cb.cod = cod;
	memcpy(btt_cb.bd_addr, remote_bd_addr->address, BD_ADDR_LEN);
	strcpy(btt_cb.name, (char *)bd_name->name);

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_pin_request), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
}

static void btt_cb_ssp_request(bt_bdaddr_t *remote_bd_addr,
		bt_bdname_t *bd_name, uint32_t cod,
		bt_ssp_variant_t pairing_variant, uint32_t pass_key)
{
	struct btt_cb_adapter_ssp_request btt_cb;

	BTT_LOG_I("Callback SSP Request");

	FILL_HDR(btt_cb, BTT_ADAPTER_SSP_REQUEST);
	btt_cb.cod     = cod;
	btt_cb.passkey = pass_key;

	memcpy(btt_cb.bd_addr, remote_bd_addr->address, BD_ADDR_LEN);

	strcpy(btt_cb.name, (char *)bd_name->name);

	btt_cb.variant = pairing_variant;

	if (send(socket_remote, (const char *) &btt_cb,
			sizeof(struct btt_cb_adapter_ssp_request), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
	}
}

static void btt_cb_bond_state_changed(bt_status_t status,
		bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state)
{
	struct btt_cb_adapter_bond_state_changed btt_cb;

	BTT_LOG_I("Callback Bond State Changed");

	FILL_HDR(btt_cb, BTT_ADAPTER_BOND_STATE_CHANGED);
	btt_cb.status   = status;
	btt_cb.state    = state;
	memcpy(btt_cb.bd_addr, remote_bd_addr->address, BD_ADDR_LEN);

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_bond_state_changed), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
	}

	if (BT_BOND_STATE_BONDED == state)
		bonding_peer_dev = FALSE;
}

static void btt_cb_acl_state_changed(bt_status_t status,
		bt_bdaddr_t *remote_bd_addr, bt_acl_state_t state)
{
	BTT_LOG_I("Callback ACL State Changed");
}

static void btt_cb_thread_event(bt_cb_thread_evt event)
{
	BTT_LOG_I("Callback Thread Event");
}

static void btt_cb_dut_mode_recv(uint16_t opcode, uint8_t *buf, uint8_t len)
{
	BTT_LOG_I("Callback Dut Mode Recv");
}

static void btt_cb_le_test_mode(bt_status_t status, uint16_t num_packets)
{
	BTT_LOG_I("Callback LE test mode");
}

static bt_callbacks_t sBluetoothCallbacks = {
		sizeof(sBluetoothCallbacks),
		btt_cb_adapter_state_changed,
		btt_cb_adapter_properties,
		btt_cb_remote_device_properties,
		btt_cb_device_found,
		btt_cb_discovery_state_changed,
		btt_cb_pin_request,
		btt_cb_ssp_request,
		btt_cb_bond_state_changed,
		btt_cb_acl_state_changed,
		btt_cb_thread_event,
		btt_cb_dut_mode_recv,
		btt_cb_le_test_mode
};

bt_callbacks_t *getBluetoothCallbacks(void)
{
	return &sBluetoothCallbacks;
}

