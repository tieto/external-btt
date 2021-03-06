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

#include "btt_gatt_server.h"
#include "btt.h"
#include "btt_utils.h"

extern int app_socket;

static void run_gatt_server_help(int argc, char **argv);
static void run_gatt_server_reg(int argc, char **argv);
static void run_gatt_server_unreg(int argc, char **argv);
static void run_gatt_server_connect(int argc, char **argv);
static void run_gatt_server_disconnect(int argc, char **argv);
static void run_gatt_server_add_service(int argc, char **argv);
static void run_gatt_server_add_included_service(int argc, char **argv);
static void run_gatt_server_add_characteristic(int argc, char **argv);
static void run_gatt_server_add_descriptor(int argc, char **argv);
static void run_gatt_server_start_service(int argc, char **argv);
static void run_gatt_server_stop_service(int argc, char **argv);
static void run_gatt_server_delete_service(int argc, char **argv);
static void run_gatt_server_send_indication(int argc, char **argv);
static void run_gatt_server_send_response(int argc, char **argv);

static const struct extended_command gatt_server_commands[] = {
		{{ "help",						"", run_gatt_server_help}, 1, MAX_ARGC},
		{{ "register_server",			"<16-bits UUID>", run_gatt_server_reg}, 2, 2},
		{{ "unregister_server",			"<server_if>", run_gatt_server_unreg}, 2, 2},
		{{ "connect",					"<server_if> <BD_ADDR> <is_direct>", run_gatt_server_connect}, 4, 4},
		{{ "disconnect",				"<server_if> <BD_ADDR> <conn_id>", run_gatt_server_disconnect}, 4, 4},
		{{ "add_service",				"<server_if> <16-bits UUID> <instance_id> <is_primary> <num_handles>",
				run_gatt_server_add_service}, 6, 6},
		{{ "add_included_service",		"<server_if> <service_handle> <included_handle>",
				run_gatt_server_add_included_service}, 4, 4},
		{{ "add_characteristic",		"<server_if> <service_handle> <16-bits UUID> <properties> <permissions>",
				run_gatt_server_add_characteristic}, 6, 6},
		{{ "add_descriptor",			"<server_if> <service_handle> <16-bits UUID> <permissions>",
				run_gatt_server_add_descriptor}, 5, 5},
		{{ "start_service",				"<server_if> <servcie_handle> <transport>",
				run_gatt_server_start_service}, 4, 4},
		{{ "stop_service",				"<server_if> <service_handle>", run_gatt_server_stop_service}, 3, 3},
		{{ "delete_service",			"<server_if> <service_handle>", run_gatt_server_delete_service}, 3, 3},
		{{ "send_indication",			"<server_if> <attr_handle> <conn_id> <confirm> <p_value>",
				run_gatt_server_send_indication}, 6, 6},
		{{ "send_response",				"<conn_id> <trans_id> <status> <value> <handle> <offset> <auth_req>",
				run_gatt_server_send_response				}, 8, 8}
};

#define GATT_SERVER_SUPPORTED_COMMANDS sizeof(gatt_server_commands)/sizeof(struct extended_command)

void run_gatt_server_help(int argc, char **argv)
{
	print_commands_extended(gatt_server_commands,
			GATT_SERVER_SUPPORTED_COMMANDS);
}

static void process_request(enum btt_gatt_server_req_t type, void *data)
{
	struct btt_message msg;
	struct timeval tv;
	struct btt_message btt_cb;

	errno = 0;

	switch (type) {
	case BTT_GATT_SERVER_REQ_END:
		break;
	case BTT_GATT_SERVER_REQ_REGISTER_SERVER:
	{
		struct btt_gatt_server_reg *register_server;

		FILL_MSG_P(data, register_server, BTT_GATT_SERVER_CMD_REGISTER_SERVER);

		if (send(app_socket, register_server,
				sizeof(struct btt_gatt_server_reg), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_UNREGISTER_SERVER:
	{
		struct btt_gatt_server_unreg *unregister_server;

		FILL_MSG_P(data, unregister_server,
				BTT_GATT_SERVER_CMD_UNREGISTER_SERVER);

		if (send(app_socket, unregister_server,
				sizeof(struct btt_gatt_server_unreg), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_CONNECT:
	{
		struct btt_gatt_server_connect *connect;

		FILL_MSG_P(data, connect, BTT_GATT_SERVER_CMD_CONNECT);

		if (send(app_socket, connect,
				sizeof(struct btt_gatt_server_connect), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_DISCONNECT:
	{
		struct btt_gatt_server_disconnect *disconnect;

		FILL_MSG_P(data, disconnect, BTT_GATT_SERVER_CMD_DISCONNECT);

		if (send(app_socket, disconnect,
				sizeof(struct btt_gatt_server_disconnect), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_SERVICE:
	{
		struct btt_gatt_server_add_service *add_service;

		FILL_MSG_P(data, add_service, BTT_GATT_SERVER_CMD_ADD_SERVICE);

		if (send(app_socket, add_service,
				sizeof(struct btt_gatt_server_add_service), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_INCLUDED_SERVICE:
	{
		struct btt_gatt_server_add_included_srvc *add;

		FILL_MSG_P(data, add, BTT_GATT_SERVER_CMD_ADD_INCLUDED_SERVICE);

		if (send(app_socket, add,
				sizeof(struct btt_gatt_server_add_included_srvc), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_CHARACTERISTIC:
	{
		struct btt_gatt_server_add_characteristic *add;

		FILL_MSG_P(data, add, BTT_GATT_SERVER_CMD_ADD_CHARACTERISTIC);

		if (send(app_socket, add,
				sizeof(struct btt_gatt_server_add_characteristic), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_DESCRIPTOR:
	{
		struct btt_gatt_server_add_descriptor *add;

		FILL_MSG_P(data, add, BTT_GATT_SERVER_CMD_ADD_DESCRIPTOR);

		if (send(app_socket, add,
				sizeof(struct btt_gatt_server_add_descriptor), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_START_SERVICE:
	{
		struct btt_gatt_server_start_service *start;

		FILL_MSG_P(data, start, BTT_GATT_SERVER_CMD_START_SERVICE);

		if (send(app_socket, start,
				sizeof(struct btt_gatt_server_start_service), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_STOP_SERVICE:
	{
		struct btt_gatt_server_stop_service *stop_service;

		FILL_MSG_P(data, stop_service, BTT_GATT_SERVER_CMD_STOP_SERVICE);

		if (send(app_socket, stop_service,
				sizeof(struct btt_gatt_server_stop_service), 0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_DELETE_SERVICE:
	{
		struct btt_gatt_server_delete_service *delete;

		FILL_MSG_P(data, delete, BTT_GATT_SERVER_CMD_DELETE_SERVICE);

		if (send(app_socket, delete,
				sizeof(struct btt_gatt_server_delete_service),0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_SEND_RESPONSE:
	{
		struct btt_gatt_server_send_response *send_res;

		FILL_MSG_P(data, send_res, BTT_GATT_SERVER_CMD_SEND_RESPONSE);

		if (send(app_socket, send_res,
				sizeof(struct btt_gatt_server_send_response),0) == -1)
			return;

		break;
	}
	case BTT_GATT_SERVER_REQ_SEND_INDICATION:
	{
		struct btt_gatt_server_send_indication *send_ind;

		FILL_MSG_P(data, send_ind, BTT_GATT_SERVER_CMD_SEND_INDICATION);

		if (send(app_socket, send_ind,
				sizeof(struct btt_gatt_server_send_indication),0) == -1)
			return;

		break;
	}
	default:
		break;
	}
}

void handle_gatts_cb(const struct btt_message *btt_cb)
{
	char *buffer;

	switch (btt_cb->command) {
	case BTT_GATT_SERVER_CB_BT_STATUS:
	{
		struct btt_gatt_server_cb_bt_status cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Request status: %s\n",
				bt_status_string[cb.status]);

		break;
	}
	case BTT_GATT_SERVER_CB_REGISTER_SERVER:
	{
		struct btt_gatt_server_cb_reg_result cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Register server.\n");
		BTT_LOG_S("\n");
		printf_UUID_128(cb.app_uuid.uu, FALSE, FALSE);
		BTT_LOG_S("Status: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n\n", cb.server_if);

		break;
	}
	case BTT_GATT_SERVER_CB_CONNECT:
	{
		struct btt_gatt_server_cb_connect cb;

		if (!RECV(&cb,app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Connect.\n");
		BTT_LOG_S("Address: ");
		print_bdaddr(cb.bda.address);
		BTT_LOG_S("\nConnection ID: %d\n", cb.conn_id);
		BTT_LOG_S("%s\n", (cb.connected) ? "CONNECT" : "DISCONNECT");
		BTT_LOG_S("Server interface: %d\n\n", cb.server_if);

		break;
	}
	case BTT_GATT_SERVER_CB_ADD_SERVICE:
	{
		struct btt_gatt_server_cb_add_service cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Add service.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		printf_UUID_128(cb.srvc_id.id.uuid.uu, FALSE, FALSE);
		BTT_LOG_S("Instance ID: %d\n", cb.srvc_id.id.inst_id);
		BTT_LOG_S("Is Primary: %s\n", (cb.srvc_id.is_primary) ?
				"True" : "False");
		BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_ADD_INCLUDED_SERVICE:
	{
		struct btt_gatt_server_cb_add_included_srvc cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Add included service.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		BTT_LOG_S("Service Handle: %d\n", cb.srvc_handle);
		BTT_LOG_S("Included Service Handle: %d\n\n",
				cb.incl_srvc_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_ADD_CHARACTERISTIC:
	{
		struct btt_gatt_server_cb_add_characteristic cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Add characteristic.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		printf_UUID_128(cb.uuid.uu, FALSE, FALSE);
		BTT_LOG_S("Service Handle: %d\n", cb.srvc_handle);
		BTT_LOG_S("Characteristic Handle: %d\n\n", cb.char_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_ADD_DESCRIPTOR:
	{
		struct btt_gatt_server_cb_add_descriptor cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Add descriptor.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		printf_UUID_128(cb.uuid.uu, FALSE, FALSE);
		BTT_LOG_S("Service Handle: %d\n", cb.srvc_handle);
		BTT_LOG_S("Descriptor Handle: %d\n\n", cb.descr_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_START_SERVICE:
	{
		struct btt_gatt_server_cb_start_service cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Start service.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_STOP_SERVICE:
	{
		struct btt_gatt_server_cb_stop_service cb;

		if (!RECV(&cb,app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Stop service.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_DELETE_SERVICE:
	{
		struct btt_gatt_server_cb_delete_service cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Register server.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Server interface: %d\n", cb.server_if);
		BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);

		break;
	}
	case BTT_GATT_SERVER_CB_RESPONSE_CONFIRMATION:
	{
		struct btt_gatt_server_cb_response_confirmation cb;

		if (!RECV(&cb, app_socket)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return;
		}

		BTT_LOG_S("\nGATTS: Register server.\n");
		BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
		BTT_LOG_S("Handle: %d\n", cb.handle);

		break;
	}
	default:
		buffer = malloc(btt_cb->length);

		if (buffer) {
			recv(app_socket, buffer, btt_cb->length, 0);
			free(buffer);
		}

		break;
	}
}

static void run_gatt_server_reg(int argc, char **argv)
{
	struct btt_gatt_server_reg req;

	if (!sscanf_UUID(argv[1], req.UUID.uu, FALSE, FALSE)) {
			BTT_LOG_S("Error: Incorrect UUID\n");
			return;
	}

	process_request(BTT_GATT_SERVER_REQ_REGISTER_SERVER, &req);
}

static void run_gatt_server_unreg(int argc, char **argv)
{
	struct btt_gatt_server_unreg req;

	sscanf(argv[1], "%d", &req.server_if);

	process_request(BTT_GATT_SERVER_REQ_UNREGISTER_SERVER, &req);
}

static void run_gatt_server_connect(int argc, char **argv)
{
	struct btt_gatt_server_connect req;

	sscanf(argv[1], "%d", &req.server_if);

	if (!sscanf_bdaddr(argv[2], req.bd_addr.address)) {
			BTT_LOG_S("Error: Incorrect address\n");
			return;
	}

	sscanf(argv[3], "%d", &req.is_direct);

	process_request(BTT_GATT_SERVER_REQ_CONNECT, &req);
}

static void run_gatt_server_disconnect(int argc, char **argv)
{
	struct btt_gatt_server_disconnect req;

	sscanf(argv[1], "%d", &req.server_if);

	if (!sscanf_bdaddr(argv[2], req.bd_addr.address)) {
		BTT_LOG_S("Error: Incorrect address\n");
		return;
	}

	sscanf(argv[3], "%d", &req.conn_id);

	process_request(BTT_GATT_SERVER_REQ_DISCONNECT, &req);
}

static void run_gatt_server_add_service(int argc, char **argv)
{
	struct btt_gatt_server_add_service req;

	sscanf(argv[1], "%d", &req.server_if);

	if (!sscanf_UUID(argv[2], req.srvc_id.id.uuid.uu, FALSE, FALSE)) {
			BTT_LOG_S("Error: Incorrect UUID\n");
			return;
	}

	sscanf(argv[3], "%d", (int*)&req.srvc_id.id.inst_id);
	sscanf(argv[4], "%d", (int*)&req.srvc_id.is_primary);
	sscanf(argv[5], "%d", &req.num_handles);

	process_request(BTT_GATT_SERVER_REQ_ADD_SERVICE, &req);
}

static void run_gatt_server_add_included_service(int argc, char **argv)
{
	struct btt_gatt_server_add_included_srvc req;

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.service_handle);
	sscanf(argv[3], "%d", &req.included_handle);

	process_request(BTT_GATT_SERVER_REQ_ADD_INCLUDED_SERVICE, &req);
}

static void run_gatt_server_add_characteristic(int argc, char **argv)
{
	struct btt_gatt_server_add_characteristic req;
	uint8_t tab[2];

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.service_handle);

	if (!sscanf_UUID(argv[3], req.uuid.uu, FALSE, FALSE)) {
			BTT_LOG_S("Error: Incorrect UUID\n");
			return;
	}

	sscanf(argv[4], "%d", &req.properties);
	sscanf(argv[5], "%d", &req.permissions);

	process_request(BTT_GATT_SERVER_REQ_ADD_CHARACTERISTIC, &req);
}

static void run_gatt_server_add_descriptor(int argc, char **argv)
{
	struct btt_gatt_server_add_descriptor req;

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.service_handle);

	if (!sscanf_UUID(argv[3], req.uuid.uu, FALSE, FALSE)) {
			BTT_LOG_S("Error: Incorrect UUID\n");
			return;
	}

	sscanf(argv[4], "%d", &req.permissions);

	process_request(BTT_GATT_SERVER_REQ_ADD_DESCRIPTOR, &req);
}

static void run_gatt_server_start_service(int argc, char **argv)
{
	struct btt_gatt_server_start_service req;

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.service_handle);
	sscanf(argv[3], "%d", &req.transport);

	process_request(BTT_GATT_SERVER_REQ_START_SERVICE, &req);
}

static void run_gatt_server_stop_service(int argc, char **argv)
{
	struct btt_gatt_server_stop_service req;

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.service_handle);

	process_request(BTT_GATT_SERVER_REQ_STOP_SERVICE, &req);
}

static void run_gatt_server_delete_service(int argc, char **argv)
{
	struct btt_gatt_server_delete_service req;

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.service_handle);

	process_request(BTT_GATT_SERVER_REQ_DELETE_SERVICE, &req);
}

static void run_gatt_server_send_indication(int argc, char **argv)
{
	struct btt_gatt_server_send_indication req;
	char input[BTGATT_MAX_ATTR_LEN * 2];

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.attribute_handle);
	sscanf(argv[3], "%d", &req.conn_id);
	sscanf(argv[4], "%d", &req.confirm);
	sscanf(argv[5], "%s", input);
	req.len = string_to_hex(input, (uint8_t *) req.p_value);

	if (req.len < 0) {
		BTT_LOG_S("Error: Incorrect hex value\n");
		return;
	}

	process_request(BTT_GATT_SERVER_REQ_SEND_INDICATION, &req);
}

static void run_gatt_server_send_response(int argc, char **argv)
{
	struct btt_gatt_server_send_response req;
	char input[BTGATT_MAX_ATTR_LEN * 2];
	int len;

	sscanf(argv[1], "%d", &req.conn_id);
	sscanf(argv[2], "%d", &req.trans_id);
	sscanf(argv[3], "%d", &req.status);
	sscanf(argv[4], "%s", input);
	 len = string_to_hex(input,
			req.response.attr_value.value);

	if (len < 0) {
		BTT_LOG_S("Error: Incorrect hex value\n");
		return;
	}

	req.response.attr_value.len = (uint16_t) len;
	sscanf(argv[5], "%"SCNd16"", &req.response.attr_value.handle);
	sscanf(argv[6], "%"SCNd16"", &req.response.attr_value.offset);
	sscanf(argv[7], "%"SCNd8"", &req.response.attr_value.auth_req);

	process_request(BTT_GATT_SERVER_REQ_SEND_RESPONSE, &req);
}

void run_gatt_server(int argc, char **argv)
{
	run_generic_extended(gatt_server_commands, GATT_SERVER_SUPPORTED_COMMANDS,
			run_gatt_server_help, argc, argv);
}
