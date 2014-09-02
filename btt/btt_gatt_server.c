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

#define MAX_ARGC 20

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

static const struct extended_command gatt_server_commands[] = {
		{{ "help",						"",									run_gatt_server_help}, 1, MAX_ARGC},
		{{ "register_server",			"<16-bits UUID>",					run_gatt_server_reg}, 2, 2},
		{{ "unregister_server",			"<server_if>",						run_gatt_server_unreg}, 2, 2},
		{{ "connect",					"<server_if><BD_ADDR><is_direct>",	run_gatt_server_connect}, 4, 4},
		{{ "disconnect",				"<server_if><BD_ADDR><conn_id>",	run_gatt_server_disconnect}, 4, 4},
		{{ "add_service",				"<server_if><16-bits UUID><instance_id><is_primary><num_handles>",
				run_gatt_server_add_service}, 6, 6},
		{{ "add_included_service",		"<server_if><service_handle><included_handle>",
				run_gatt_server_add_included_service}, 4, 4},
		{{ "add_characteristic",		"<server_if><service_handle><16-bits UUID><properties><permissions>",
				run_gatt_server_add_characteristic}, 6, 6},
		{{ "add_descriptor",			"<server_if><service_handle><16-bits UUID><permissions>",
				run_gatt_server_add_descriptor}, 5, 5},
		{{ "start_service",				"<server_if><servcie_handle><transport>",
				run_gatt_server_start_service}, 4, 4},
		{{ "stop_service",				"<server_if><service_handle>",		run_gatt_server_stop_service}, 3, 3},
		{{ "delete_service",			"<server_if><service_handle>", 		run_gatt_server_delete_service}, 3, 3},
		{{ "send_indication",			"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "send_response",				"NOT IMPLEMENTED YET",	NULL				}, 1, 1}
};

#define GATT_SERVER_SUPPORTED_COMMANDS sizeof(gatt_server_commands)/sizeof(struct extended_command)

void run_gatt_server_help(int argc, char **argv)
{
	print_commands_extended(gatt_server_commands,
			GATT_SERVER_SUPPORTED_COMMANDS);
	exit(EXIT_SUCCESS);
}

static void process_request(enum btt_gatt_server_req_t type, void *data)
{
	int server_sock;
	unsigned int len;
	struct sockaddr_un server;
	struct btt_message msg;
	struct timeval tv;
	struct btt_gatt_server_cb_hdr btt_cb;
	char *buffer;
	unsigned int i;

	errno = 0;

	if ((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return;

	server.sun_family = AF_UNIX;

	strcpy(server.sun_path, SOCK_PATH);

	len = strlen(server.sun_path) + sizeof(server.sun_family);

	if (connect(server_sock, (struct sockaddr *)&server, len) == -1) {
		close(server_sock);
		return;
	}

	switch (type) {
	case BTT_GATT_SERVER_REQ_END:
		break;
	case BTT_GATT_SERVER_REQ_REGISTER_SERVER:
	{
		struct btt_gatt_server_reg *register_server =
				(struct btt_gatt_server_reg *) data;

		register_server->hdr.command = BTT_GATT_SERVER_CMD_REGISTER_SERVER;
		register_server->hdr.length = sizeof(struct btt_gatt_server_reg)
				- sizeof(struct btt_message);

		if (send(server_sock, register_server,
				sizeof(struct btt_gatt_server_reg), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_UNREGISTER_SERVER:
	{
		struct btt_gatt_server_unreg *unregister_server =
				(struct btt_gatt_server_unreg *) data;

		unregister_server->hdr.command = BTT_GATT_SERVER_CMD_UNREGISTER_SERVER;
		unregister_server->hdr.length = sizeof(struct btt_gatt_server_unreg)
				- sizeof(struct btt_message);

		if (send(server_sock, unregister_server,
				sizeof(struct btt_gatt_server_unreg), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_CONNECT:
	{
		struct btt_gatt_server_connect *connect =
				(struct btt_gatt_server_connect*) data;

		connect->hdr.command = BTT_GATT_SERVER_CMD_CONNECT;
		connect->hdr.length = sizeof(struct btt_gatt_server_connect)
				- sizeof(struct btt_message);

		if (send(server_sock, connect,
				sizeof(struct btt_gatt_server_connect), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_DISCONNECT:
	{
		struct btt_gatt_server_disconnect *disconnect =
				(struct btt_gatt_server_disconnect*) data;

		disconnect->hdr.command = BTT_GATT_SERVER_CMD_DISCONNECT;
		disconnect->hdr.length = sizeof(struct btt_gatt_server_disconnect)
				- sizeof(struct btt_message);

		if (send(server_sock, disconnect,
				sizeof(struct btt_gatt_server_disconnect), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_SERVICE:
	{
		struct btt_gatt_server_add_service *add_service =
				(struct btt_gatt_server_add_service*) data;

		add_service->hdr.command = BTT_GATT_SERVER_CMD_ADD_SERVICE;
		add_service->hdr.length = sizeof(struct btt_gatt_server_add_service)
				- sizeof(struct btt_message);

		if (send(server_sock, add_service,
				sizeof(struct btt_gatt_server_add_service), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_INCLUDED_SERVICE:
	{
		struct btt_gatt_server_add_included_srvc *add_included_srvc =
				(struct btt_gatt_server_add_included_srvc*) data;

		add_included_srvc->hdr.command = BTT_GATT_SERVER_CMD_ADD_INCLUDED_SERVICE;
		add_included_srvc->hdr.length = sizeof(struct btt_gatt_server_add_included_srvc)
						- sizeof(struct btt_message);

		if (send(server_sock, add_included_srvc,
				sizeof(struct btt_gatt_server_add_included_srvc), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_CHARACTERISTIC:
	{
		struct btt_gatt_server_add_characteristic *add_characteristic =
				(struct btt_gatt_server_add_characteristic*) data;

		add_characteristic->hdr.command = BTT_GATT_SERVER_CMD_ADD_CHARAKTERISTIC;
		add_characteristic->hdr.length = sizeof(struct btt_gatt_server_add_characteristic)
						- sizeof(struct btt_message);

		if (send(server_sock, add_characteristic,
				sizeof(struct btt_gatt_server_add_characteristic), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_ADD_DESCRIPTOR:
	{
		struct btt_gatt_server_add_descriptor *add_descriptor =
				(struct btt_gatt_server_add_descriptor*) data;

		add_descriptor->hdr.command = BTT_GATT_SERVER_CMD_ADD_DESCRIPTOR;
		add_descriptor->hdr.length = sizeof(struct btt_gatt_server_add_descriptor)
				- sizeof(struct btt_message);

		if (send(server_sock, add_descriptor,
				sizeof(struct btt_gatt_server_add_descriptor), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_START_SERVICE:
	{
		struct btt_gatt_server_start_service *start_service =
				(struct btt_gatt_server_start_service*) data;

		start_service->hdr.command = BTT_GATT_SERVER_CMD_START_SERVICE;
		start_service->hdr.length = sizeof(struct btt_gatt_server_start_service)
				- sizeof(struct btt_message);

		if (send(server_sock, start_service,
				sizeof(struct btt_gatt_server_start_service), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_STOP_SERVICE:
	{
		struct btt_gatt_server_stop_service *stop_service =
				(struct btt_gatt_server_stop_service*) data;

		stop_service->hdr.command = BTT_GATT_SERVER_CMD_STOP_SERVICE;
		stop_service->hdr.length = sizeof(struct btt_gatt_server_stop_service)
						- sizeof(struct btt_message);

		if (send(server_sock, stop_service,
				sizeof(struct btt_gatt_server_stop_service), 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_GATT_SERVER_REQ_DELETE_SERVICE:
	{
		struct btt_gatt_server_delete_service *delete_service =
				(struct btt_gatt_server_delete_service*) data;

		delete_service->hdr.command = BTT_GATT_SERVER_CMD_DELETE_SERVICE;
		delete_service->hdr.length = sizeof(struct btt_gatt_server_delete_service)
						- sizeof(struct btt_message);

		if(send(server_sock, delete_service,
				sizeof(struct btt_gatt_server_delete_service),0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	default:
		break;
	}

	len = 0;

	while (1) {
		len = recv(server_sock, &btt_cb, sizeof(btt_cb), MSG_PEEK);

		if (len == 0 || errno) {
			BTT_LOG_S("Timeout\n");
			close(server_sock);
			return;
		}
        /* here we receive all messages on the socket. But only requested
         * messages are printed (i.e. type == BTT_REQ_AGENT)
         */
		switch (btt_cb.type) {
		case BTT_GATT_SERVER_CB_END:
		{
			struct btt_gatt_server_cb_status cb;

			memset(&cb, 0, sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			BTT_LOG_S("\nStatus: %s\n\n",!cb.status ? "OK" : "ERROR");
			return;
		}
		case BTT_GATT_SERVER_CB_REGISTER_SERVER:
		{
			struct btt_gatt_server_cb_reg_result cb;

			memset(&cb, 0, sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if (type == BTT_GATT_SERVER_REQ_REGISTER_SERVER) {
				BTT_LOG_S("\n");
				printf_UUID_128(cb.app_uuid.uu, FALSE);
				BTT_LOG_S("Status: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n\n", cb.server_if);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_CONNECT:
		{
			struct btt_gatt_server_cb_connect cb;

			memset(&cb, 0, sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if (type == BTT_GATT_SERVER_REQ_CONNECT || BTT_GATT_SERVER_REQ_DISCONNECT) {
				BTT_LOG_S("Address: ");
				print_bdaddr(cb.bda.address);
				BTT_LOG_S("\nConnection ID: %d\n", cb.conn_id);
				BTT_LOG_S("%s\n", (cb.connected) ? "CONNECT" : "DISCONNECT");
				BTT_LOG_S("Server interface: %d\n\n", cb.server_if);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_ADD_SERVICE:
		{
			struct btt_gatt_server_cb_add_service cb;

			memset(&cb, 0, sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if (type == BTT_GATT_SERVER_REQ_ADD_SERVICE) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				printf_UUID_128(cb.srvc_id.id.uuid.uu, FALSE);
				BTT_LOG_S("Instance ID: %d\n", cb.srvc_id.id.inst_id);
				BTT_LOG_S("Is Primary: %s\n", (cb.srvc_id.is_primary) ?
						"True" : "False");
				BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_ADD_INCLUDED_SERVICE:
		{
			struct btt_gatt_server_cb_add_included_srvc cb;

			memset(&cb,0,sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if (type == BTT_GATT_SERVER_REQ_ADD_INCLUDED_SERVICE) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				BTT_LOG_S("Service Handle: %d\n", cb.srvc_handle);
				BTT_LOG_S("Included Service Handle: %d\n\n", cb.incl_srvc_handle);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_ADD_CHARACTERISTIC:
		{
			struct btt_gatt_server_cb_add_characteristic cb;

			memset(&cb,0,sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if (type == BTT_GATT_SERVER_REQ_ADD_CHARACTERISTIC) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				printf_UUID_128(cb.uuid.uu, FALSE);
				BTT_LOG_S("Service Handle: %d\n", cb.srvc_handle);
				BTT_LOG_S("Characteristic Handle: %d\n\n", cb.char_handle);
			}
			return;
		}
		case BTT_GATT_SERVER_CB_ADD_DESCRIPTOR:
		{
			struct btt_gatt_server_cb_add_descriptor cb;

			memset(&cb,0,sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if (type == BTT_GATT_SERVER_REQ_ADD_DESCRIPTOR) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				printf_UUID_128(cb.uuid.uu, FALSE);
				BTT_LOG_S("Service Handle: %d\n", cb.srvc_handle);
				BTT_LOG_S("Descriptor Handle: %d\n\n", cb.descr_handle);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_START_SERVICE:
		{
			struct btt_gatt_server_cb_start_service cb;

			memset(&cb,0,sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if(type == BTT_GATT_SERVER_REQ_START_SERVICE) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_STOP_SERVICE:
		{
			struct btt_gatt_server_cb_stop_service cb;

			memset(&cb,0,sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if(type == BTT_GATT_SERVER_REQ_STOP_SERVICE) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);
			}

			return;
		}
		case BTT_GATT_SERVER_CB_DELETE_SERVICE:
		{
			struct btt_gatt_server_cb_delete_service cb;

			memset(&cb,0,sizeof(cb));

			if (!RECV(&cb,server_sock)) {
				BTT_LOG_S("Error: incorrect size of received structure.\n");
				return;
			}

			if(type == BTT_GATT_SERVER_REQ_DELETE_SERVICE) {
				BTT_LOG_S("\nStatus: %s\n",!cb.status ? "OK" : "ERROR");
				BTT_LOG_S("Server interface: %d\n", cb.server_if);
				BTT_LOG_S("Service Handle: %d\n\n", cb.srvc_handle);
			}

			return;
		}
		default:
			buffer = malloc(btt_cb.length);

			if (buffer) {
				recv(server_sock, buffer, btt_cb.length, 0);
				free(buffer);
			}

			break;
		}
	}
}

static void run_gatt_server_reg(int argc, char **argv)
{
	struct btt_gatt_server_reg req;

	if (!sscanf_UUID(argv[1], req.UUID.uu)) {
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

	if (!sscanf_UUID(argv[2], req.srvc_id.id.uuid.uu)) {
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

	if (!sscanf_UUID(argv[3], req.uuid.uu)) {
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

	if (!sscanf_UUID(argv[3], req.uuid.uu)) {
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

void run_gatt_server(int argc, char **argv)
{
	run_generic_extended(gatt_server_commands, GATT_SERVER_SUPPORTED_COMMANDS,
			run_gatt_server_help, argc, argv);
}
