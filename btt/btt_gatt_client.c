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

#include "btt_gatt_client.h"
#include "btt.h"
#include "btt_utils.h"

#define DEFAULT_TIME_SEC 3
#define LONG_TIME_SEC 10
#define MAX_ARGC 20

static void run_gatt_client_help(int argc, char **argv);
static void run_gatt_client_scan(int argc, char **argv);
static void run_gatt_client_register_client(int argc, char **argv);
static void run_gatt_client_un_register_client(int argc, char **argv);
static void run_gatt_client_connect(int argc, char **argv);
static void run_gatt_client_disconnect(int argc, char **argv);
static void run_gatt_client_read_remote_rssi(int argc, char **argv);
static void run_gatt_client_listen(int argc, char **argv);
static void run_gatt_client_set_adv_data_basic(int argc, char **argv);
static void run_gatt_client_set_adv_data(int argc, char **argv);
static void run_gatt_client_get_device_type(int argc, char **argv);
static void run_gatt_client_refresh(int argc, char **argv);
static void run_gatt_client_search_service(int argc, char **argv);
static void run_gatt_client_get_included_service(int argc, char **argv);

static int create_daemon_socket(void);
static void set_sock_rcv_time(unsigned int sec, unsigned int usec,
		int server_sock);
static bool send_by_socket(int server_sock, void *data, size_t len, int flags);
static bool process_send_to_daemon(enum btt_gatt_client_req_t type, void *data,
		int server_sock, bool *select_used);
static bool process_receive_from_daemon(enum btt_gatt_client_req_t type,
		bool *wait_for_msg, int server_sock);
static bool process_stdin(bool *select_used, int client_if);
static void printf_service(btgatt_srvc_id_t srv);
static bool process_UUID_sscanf(char *src, uint8_t *dest);

static const struct extended_command gatt_client_commands[] = {
		{{ "help",							"",							run_gatt_client_help}, 1, MAX_ARGC},
		{{ "scan",							"<client_if>",				run_gatt_client_scan}, 2, 2},
		{{ "register_client",				"<16-bits UUID>", run_gatt_client_register_client}, 2, 2},
		{{ "unregister_client",				"<client_if>", run_gatt_client_un_register_client}, 2, 2},
		{{ "connect",						"<client_if> <BD_ADDR> <is_direct>", run_gatt_client_connect}, 4, 4},
		{{ "disconnect",					"<client_if> <BD_ADDR> <conn_id>", run_gatt_client_disconnect}, 4, 4},
		{{ "listen",						"<client_if> <start>", run_gatt_client_listen}, 3, 3},
		{{ "refresh",						"<client_if> <BD_ADDR>", run_gatt_client_refresh}, 3, 3},
		{{ "search_service",				"<conn_id> [16bit_UUID_filter | 128bit_UUID_filter]", run_gatt_client_search_service}, 2, 3},
		{{ "get_included_service",			"<conn_id> <16bit_UUID | 128bit_UUID> <is_primary> <inst_id> [<16bit_UUID | 128bit_UUID> <is_primary> <inst_id>]", run_gatt_client_get_included_service}, 5, 8},
		{{ "get_charakteristic",			"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "get_descriptor",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "read_descriptor",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "write_descriptor",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "execute_write",					"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "register_for_notification",		"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "deregister_for_notification",	"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "read_remote_rssi",				"<BD_ADDR> <client_if>", run_gatt_client_read_remote_rssi}, 3, 3},
		{{ "get_device_type",				"<BD_ADDR>", run_gatt_client_get_device_type}, 2, 2},
		{{ "set_adv_data_basic",			"<client_if> <set_scan_rsp> <include_name> <include_txpower> <min_interval> <max_interval> <appearance>", run_gatt_client_set_adv_data_basic}, 8, 8},
		{{ "set_adv_data",					"<client_if> <manuf_data> <service_data> <service_uuid>", run_gatt_client_set_adv_data}, 5, 5},
		{{ "test_command",					"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
};

#define GATT_CLIENT_SUPPORTED_COMMANDS sizeof(gatt_client_commands)/sizeof(struct extended_command)

void run_gatt_client_help(int argc, char **argv)
{
	print_commands_extended(gatt_client_commands,
			GATT_CLIENT_SUPPORTED_COMMANDS);
	exit(EXIT_SUCCESS);
}

static void process_request(enum btt_gatt_client_req_t type, void *data,
		unsigned int recv_time_sec)
{
	int server_sock;
	bool wait_for_msg = TRUE;
	int client_if = -1;

	/*select variables*/
	/*presently select is needed only by scan*/
	bool select_used = FALSE;
	fd_set set_cp;
	fd_set set;

	FD_ZERO(&set);
	FD_ZERO(&set_cp);

	errno = 0;

	server_sock = create_daemon_socket();
	set_sock_rcv_time(recv_time_sec, 0, server_sock);
	if (!process_send_to_daemon(type, data, server_sock, &select_used))
		return;

	if (select_used) {
		FD_SET(fileno(stdin), &set);
		FD_SET(server_sock, &set);
	}

	if (type == BTT_GATT_CLIENT_REQ_SCAN)
		client_if = ((struct btt_gatt_client_scan *) data)->client_if;

	while (1) {

		if (select_used) {
			set_cp = set;

			if (select(server_sock + 1, &set_cp, NULL, NULL, NULL) == -1) {
				BTT_LOG_D("Select error. ");
				return;
			}
		}

		if (!select_used || FD_ISSET(server_sock, &set_cp)) {
			if (!process_receive_from_daemon(type, &wait_for_msg,
					server_sock)) {
				BTT_LOG_D("Error while receiving from daemon. ");
				return;
			}
		} else if (select_used && FD_ISSET(fileno(stdin), &set_cp))
			if (process_stdin(&select_used, client_if))
				return;

		if (!wait_for_msg) {
			close(server_sock);
			return;
		}
	}
}

void run_gatt_client(int argc, char **argv)
{
	run_generic_extended(gatt_client_commands, GATT_CLIENT_SUPPORTED_COMMANDS,
			run_gatt_client_help, argc, argv);
}

static void run_gatt_client_scan(int argc, char **argv)
{
	struct btt_gatt_client_scan req;

	sscanf(argv[1], "%d", &req.client_if);
	req.start = 1;
	process_request(BTT_GATT_CLIENT_REQ_SCAN, &req, DEFAULT_TIME_SEC);
}

/* function return connected-socket file descriptor */
/* or -1 when error occurred */
static int create_daemon_socket(void)
{
	int server_sock = -1;
	struct sockaddr_un server;
	unsigned int len;

	if ((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCK_PATH);

	len = strlen(server.sun_path) + sizeof(server.sun_family);

	if (connect(server_sock, (struct sockaddr *) &server, len) == -1) {
		close(server_sock);
		return -1;
	}

	return server_sock;
}

static void set_sock_rcv_time(unsigned int sec, unsigned int usec,
		int server_sock)
{
	struct timeval tv;

	tv.tv_sec = sec;
	tv.tv_usec = usec;
	setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
			(char *) &tv, sizeof(struct timeval));
}

static bool send_by_socket(int server_sock, void *data, size_t len, int flags)
{
	if (send(server_sock, data, len, flags) == -1) {
		close(server_sock);
		return FALSE;
	}

	return TRUE;
}

/* server_sock must be correct socket descriptor */
static bool process_send_to_daemon(enum btt_gatt_client_req_t type, void *data,
		int server_sock, bool *select_used)
{
	switch (type) {
	case BTT_GATT_CLIENT_REQ_SCAN:
	{
		struct btt_gatt_client_scan *cmd_scan;

		cmd_scan = (struct btt_gatt_client_scan *) data;
		cmd_scan->hdr.command = BTT_CMD_GATT_CLIENT_SCAN;
		cmd_scan->hdr.length = sizeof(struct btt_gatt_client_scan)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, cmd_scan,
				sizeof(struct btt_gatt_client_scan), 0))
			return FALSE;

		if (cmd_scan->start == 1)
			*select_used = TRUE;
		else
			*select_used = FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_REGISTER_CLIENT:
	{
		struct btt_gatt_client_register_client *register_client;

		register_client = (struct btt_gatt_client_register_client *) data;
		register_client->hdr.command = BTT_CMD_GATT_CLIENT_REGISTER_CLIENT;
		register_client->hdr.length = sizeof(struct btt_gatt_client_register_client)
						- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, register_client,
				sizeof(struct btt_gatt_client_register_client), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_UNREGISTER_CLIENT:
	{
		struct btt_gatt_client_unregister_client *unregister_client;

		unregister_client = (struct btt_gatt_client_unregister_client *) data;
		unregister_client->hdr.command = BTT_CMD_GATT_CLIENT_UNREGISTER_CLIENT;
		unregister_client->hdr.length = sizeof(struct btt_gatt_client_unregister_client)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, unregister_client,
				sizeof(struct btt_gatt_client_unregister_client), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_CONNECT:
	{
		struct btt_gatt_client_connect *connect;

		connect = (struct btt_gatt_client_connect *) data;
		connect->hdr.command = BTT_CMD_GATT_CLIENT_CONNECT;
		connect->hdr.length = sizeof(struct btt_gatt_client_connect)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, connect,
				sizeof(struct btt_gatt_client_connect), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_DISCONNECT:
	{
		struct btt_gatt_client_disconnect *disconnect;

		disconnect = (struct btt_gatt_client_disconnect *) data;
		disconnect->hdr.command = BTT_CMD_GATT_CLIENT_DISCONNECT;
		disconnect->hdr.length = sizeof(struct btt_gatt_client_disconnect)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, disconnect,
				sizeof(struct btt_gatt_client_disconnect), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_READ_REMOTE_RSSI:
	{
		struct btt_gatt_client_read_remote_rssi *read_rssi;

		read_rssi = (struct btt_gatt_client_read_remote_rssi *) data;
		read_rssi->hdr.command = BTT_CMD_GATT_CLIENT_READ_REMOTE_RSSI;
		read_rssi->hdr.length = sizeof(struct btt_gatt_client_read_remote_rssi)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, read_rssi,
				sizeof(struct btt_gatt_client_read_remote_rssi), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_LISTEN:
	{
		struct btt_gatt_client_listen *listen;

		listen = (struct btt_gatt_client_listen *) data;
		listen->hdr.command = BTT_CMD_GATT_CLIENT_LISTEN;
		listen->hdr.length = sizeof(struct btt_gatt_client_listen)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, listen,
				sizeof(struct btt_gatt_client_listen), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_SET_ADV_DATA:
	{
		struct btt_gatt_client_set_adv_data *adv;

		adv = (struct btt_gatt_client_set_adv_data *) data;
		adv->hdr.command = BTT_CMD_GATT_CLIENT_SET_ADV_DATA;
		adv->hdr.length = sizeof(struct btt_gatt_client_set_adv_data)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, adv,
				sizeof(struct btt_gatt_client_set_adv_data), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_GET_DEVICE_TYPE:
	{
		struct btt_gatt_client_get_device_type *get;

		get = (struct btt_gatt_client_get_device_type *) data;
		get->hdr.command = BTT_CMD_GATT_CLIENT_GET_DEVICE_TYPE;
		get->hdr.length = sizeof(struct btt_gatt_client_get_device_type)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, get,
				sizeof(struct btt_gatt_client_listen), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_REFRESH:
	{
		struct btt_gatt_client_refresh *refresh;

		refresh = (struct btt_gatt_client_refresh *) data;
		refresh->hdr.command = BTT_CMD_GATT_CLIENT_REFRESH;
		refresh->hdr.length = sizeof(struct btt_gatt_client_refresh)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, refresh,
				sizeof(struct btt_gatt_client_refresh), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_SEARCH_SERVICE:
	{
		struct btt_gatt_client_search_service *search;

		search = (struct btt_gatt_client_search_service *) data;
		search->hdr.command = BTT_CMD_GATT_CLIENT_SEARCH_SERVICE;
		search->hdr.length = sizeof(struct btt_gatt_client_search_service)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, search,
				sizeof(struct btt_gatt_client_search_service), 0))
			return FALSE;

		break;
	}
	case BTT_GATT_CLIENT_REQ_GET_INCLUDED_SERVICE:
	{
		struct btt_gatt_client_get_included_service *get;

		get = (struct btt_gatt_client_get_included_service *) data;
		get->hdr.command = BTT_CMD_GATT_CLIENT_GET_INCLUDE_SERVICE;
		get->hdr.length = sizeof(struct btt_gatt_client_get_included_service)
				- sizeof(struct btt_message);

		if (!send_by_socket(server_sock, get,
				sizeof(struct btt_gatt_client_get_included_service), 0))
			return FALSE;

		break;
	}
	default:
		BTT_LOG_S("ERROR: Unknown command - %d", type);
		close(server_sock);
		return FALSE;
	}

	return TRUE;
}

/* server_sock must be correct socket descriptor */
static bool process_receive_from_daemon(enum btt_gatt_client_req_t type,
		bool *wait_for_msg, int server_sock)
{
	unsigned int len, i;
	struct btt_gatt_client_cb_hdr btt_cb;
	uint8_t empty_BD_ADDR[BD_ADDR_LEN];

	errno = 0;
	memset(empty_BD_ADDR, 0, BD_ADDR_LEN);

	len = recv(server_sock, &btt_cb, sizeof(btt_cb), MSG_PEEK);

	if ((len == 0 || errno)) {
		BTT_LOG_S("Timeout\n");
		close(server_sock);
		return FALSE;
	}

	switch (btt_cb.type) {
	case BTT_GATT_CLIENT_CB_BT_STATUS:
	{
		struct btt_gatt_client_cb_bt_status stat;

		if (!RECV(&stat, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		BTT_LOG_S("GATT Client request status: %s\n",
				bt_status_string[stat.status]);
		*wait_for_msg = (((stat.status != BT_STATUS_SUCCESS) || (type
				== BTT_GATT_CLIENT_REQ_UNREGISTER_CLIENT) || (type
						== BTT_GATT_CLIENT_REQ_SET_ADV_DATA) || (type
								== BTT_GATT_CLIENT_REQ_REFRESH)) ?
										FALSE : TRUE);
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_SCAN_RESULT:
	{
		struct btt_gatt_client_cb_scan_result device;

		if (!RECV(&device, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_SCAN) {
			if (memcmp(device.bd_addr, empty_BD_ADDR, BD_ADDR_LEN)) {
				print_bdaddr(device.bd_addr);
				BTT_LOG_S("%s, ", device.name);
				BTT_LOG_S("%s\n", discoverable_mode[device.discoverable_mode]);
			}
		}

		*wait_for_msg = TRUE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_REGISTER_CLIENT:
	{
		struct btt_gatt_client_cb_register_client cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_REGISTER_CLIENT) {
			printf_UUID_128(cb.app_uuid.uu, FALSE, FALSE);
			BTT_LOG_S("Status: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Client interface: %d\n\n", cb.client_if);
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_CONNECT:
	{
		struct btt_gatt_client_cb_connect cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_CONNECT) {
			BTT_LOG_S("Address: ");
			print_bdaddr(cb.bda.address);
			BTT_LOG_S("\nConnection ID: %d\n", cb.conn_id);
			BTT_LOG_S("Status: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Client interface: %d\n\n", cb.client_if);
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_DISCONNECT:
	{
		struct btt_gatt_client_cb_disconnect cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_DISCONNECT) {
			BTT_LOG_S("Address: ");
			print_bdaddr(cb.bda.address);
			BTT_LOG_S("\nConnection ID: %d\n", cb.conn_id);
			BTT_LOG_S("Status: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Client interface: %d\n\n", cb.client_if);
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_READ_REMOTE_RSSI:
	{
		struct btt_gatt_client_cb_read_remote_rssi cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_READ_REMOTE_RSSI) {
			BTT_LOG_S("Address: ");
			print_bdaddr(cb.addr.address);
			BTT_LOG_S("\nStatus: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("RSSI: %d \n", cb.rssi);
			BTT_LOG_S("(higher RSSI level = stronger signal)\n\n");
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_LISTEN:
	{
		struct btt_gatt_client_cb_listen cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_LISTEN) {
			BTT_LOG_S("Status: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Client interface: %d\n\n", cb.server_if);
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_GET_DEVICE_TYPE:
	{
		struct btt_gatt_client_cb_get_device_type cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_GET_DEVICE_TYPE) {
			BTT_LOG_S("Device type: ");

			switch (cb.type) {
			case BT_DEVICE_DEVTYPE_BREDR:
				BTT_LOG_S("BR/EDR\n");
				break;
			case BT_DEVICE_DEVTYPE_BLE:
				BTT_LOG_S("LE\n");
				break;
			case BT_DEVICE_DEVTYPE_DUAL:
				BTT_LOG_S("DUAL\n");
				break;
			default:
				BTT_LOG_S("Unknown type or error: %d\n", cb.type);
			}
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_SEARCH_RESULT:
	{
		struct btt_gatt_client_cb_search_result cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_SEARCH_SERVICE) {
			BTT_LOG_S("Connection Id: %d.\n", cb.conn_id);
			printf_service(cb.srvc_id);
			BTT_LOG_S("\n");
		}

		*wait_for_msg = TRUE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_SEARCH_COMPLETE:
	{
		struct btt_gatt_client_cb_search_complete cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_SEARCH_SERVICE) {
			BTT_LOG_S("Status: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Connection Id: %d.\n", cb.conn_id);
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	case BTT_GATT_CLIENT_CB_GET_INCLUDED_SERVICE:
	{
		struct btt_gatt_client_cb_get_included_service cb;

		if (!RECV(&cb, server_sock)) {
			BTT_LOG_S("Error: incorrect size of received structure.\n");
			return FALSE;
		}

		if (type == BTT_GATT_CLIENT_REQ_GET_INCLUDED_SERVICE) {
			BTT_LOG_S("Status: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Connection Id: %d.\n", cb.conn_id);

			if (!cb.status) {
				BTT_LOG_S("SERVICE: \n");
				printf_service(cb.srvc_id);
				BTT_LOG_S("\nINCLUDED SERVICE: \n");
				printf_service(cb.incl_srvc_id);
				BTT_LOG_S("\n");
			}
		}

		*wait_for_msg = FALSE;
		return TRUE;
	}
	default:
		*wait_for_msg = FALSE;
		break;
	}

	return TRUE;
}

static void printf_service(btgatt_srvc_id_t srv)
{
	BTT_LOG_S("Service is %s.\n", (srv.is_primary ?
			"primary" : "secondary"));
	BTT_LOG_S("Instance Id: %d.\n", srv.id.inst_id);
	printf_UUID_128(srv.id.uuid.uu, TRUE, FALSE);
}

/* presently used only by scan */
static bool process_stdin(bool *select_used, int client_if)
{
	char buf[256];
	struct btt_gatt_client_scan tmp;
	int server_sock;

	scanf("%s", buf);

	if (!strncmp(buf, "stop", 4)) {
		server_sock = create_daemon_socket();
		tmp.start = 0;
		tmp.client_if = client_if;

		if (process_send_to_daemon(BTT_GATT_CLIENT_REQ_SCAN, &tmp,
				server_sock, select_used)) {
			BTT_LOG_S("GATT Client: Scan stopped. \n");
			return TRUE;
		} else {
			BTT_LOG_S("Error while stopping scan. \n");
		}

	} else {
		BTT_LOG_S("Write 'stop' to stop scanning. \n");
	}

	return FALSE;
}

/* 4 hex-number as argument, like FFFF */
static void run_gatt_client_register_client(int argc, char **argv)
{
	char input[256];
	struct btt_gatt_client_register_client req;

	sscanf(argv[1], "%s", input);

	if (!sscanf_UUID(input, req.UUID.uu, FALSE, FALSE)) {
		BTT_LOG_S("Error: Incorrect UUID\n");
		return;
	}

	process_request(BTT_GATT_CLIENT_REQ_REGISTER_CLIENT, &req,
			DEFAULT_TIME_SEC);
}

static void run_gatt_client_un_register_client(int argc, char **argv)
{
	struct btt_gatt_client_unregister_client req;

	sscanf(argv[1], "%d", &req.client_if);
	process_request(BTT_GATT_CLIENT_REQ_UNREGISTER_CLIENT, &req,
			DEFAULT_TIME_SEC);
}

static void run_gatt_client_connect(int argc, char **argv)
{
	struct btt_gatt_client_connect req;

	sscanf(argv[1], "%d", &req.client_if);

	if(!sscanf_bdaddr(argv[2], req.addr.address)) {
		BTT_LOG_S("Error: Incorrect address\n");
		return;
	}

	sscanf(argv[3], "%d", &req.is_direct);

	process_request(BTT_GATT_CLIENT_REQ_CONNECT, &req, DEFAULT_TIME_SEC);
}

static void run_gatt_client_disconnect(int argc, char **argv)
{
	struct btt_gatt_client_disconnect req;

	sscanf(argv[1], "%d", &req.client_if);

	if(!sscanf_bdaddr(argv[2], req.addr.address)) {
		BTT_LOG_S("Error: Incorrect address\n");
		return;
	}

	sscanf(argv[3], "%d", &req.conn_id);

	process_request(BTT_GATT_CLIENT_REQ_DISCONNECT, &req, DEFAULT_TIME_SEC);
}

static void run_gatt_client_read_remote_rssi(int argc, char **argv)
{
	struct btt_gatt_client_read_remote_rssi req;

	if(!sscanf_bdaddr(argv[1], req.addr.address)) {
		BTT_LOG_S("Error: Incorrect address\n");
		return;
	}

	sscanf(argv[2], "%d", &req.client_if);
	process_request(BTT_GATT_CLIENT_REQ_READ_REMOTE_RSSI, &req,
			DEFAULT_TIME_SEC);
}

static void run_gatt_client_listen(int argc, char **argv)
{
	struct btt_gatt_client_listen req;

	sscanf(argv[1], "%d", &req.client_if);
	sscanf(argv[2], "%d", &req.start);
	process_request(BTT_GATT_CLIENT_REQ_LISTEN, &req, DEFAULT_TIME_SEC);
}

static void run_gatt_client_set_adv_data_basic(int argc, char **argv)
{
	struct btt_gatt_client_set_adv_data req;

	sscanf(argv[1], "%d", &req.server_if);
	sscanf(argv[2], "%d", &req.set_scan_rsp);
	sscanf(argv[3], "%d", &req.include_name);
	sscanf(argv[4], "%d", &req.include_txpower);
	sscanf(argv[5], "%d", &req.min_interval);
	sscanf(argv[6], "%d", &req.max_interval);
	sscanf(argv[7], "%d", &req.appearance);

	req.service_data_len = 0;
	req.manufacturer_len = 0;
	req.service_uuid_len = 0;
	process_request(BTT_GATT_CLIENT_REQ_SET_ADV_DATA, &req, DEFAULT_TIME_SEC);
}

/* default settings of advertisement data taken:
 * - include name
 * - include txpower
 * - exclude appearance info
 * - exclude info about interval
 * - set scan response */
static void run_gatt_client_set_adv_data(int argc, char **argv)
{
	struct btt_gatt_client_set_adv_data req;
	unsigned char hex[256];
	int len = 0;

	sscanf(argv[1], "%d", &req.server_if);

	if ((len = string_to_hex(argv[2], hex)) < 0)
		return;

	memcpy(req.manufacturer_data, hex, len);
	req.manufacturer_len = (uint16_t) len;

	if ((len = string_to_hex(argv[3], hex)) < 0)
		return;

	memcpy(req.service_data, hex, len);
	req.service_data_len = (uint16_t) len;

	if ((len = string_to_hex(argv[4], hex)) < 0)
		return;

	memcpy(req.service_uuid, hex, len);
	req.service_uuid_len = (uint16_t) len;

	req.include_name = 1;
	req.include_txpower = 1;
	req.appearance = 0;
	req.min_interval = 0;
	req.max_interval = 0;
	req.set_scan_rsp = 1;

	process_request(BTT_GATT_CLIENT_REQ_SET_ADV_DATA, &req, DEFAULT_TIME_SEC);
}

static void run_gatt_client_get_device_type(int argc, char **argv)
{
	struct btt_gatt_client_get_device_type req;

	if (!sscanf_bdaddr(argv[1], req.addr.address)) {
		BTT_LOG_S("Error: Incorrect address\n");
		return;
	}

	process_request(BTT_GATT_CLIENT_REQ_GET_DEVICE_TYPE, &req, DEFAULT_TIME_SEC);
}

static void run_gatt_client_refresh(int argc, char **argv)
{
	struct btt_gatt_client_refresh req;

	sscanf(argv[1], "%d", &req.client_if);

	if (!sscanf_bdaddr(argv[2], req.addr.address)) {
		BTT_LOG_S("Error: Incorrect address\n");
		return;
	}

	process_request(BTT_GATT_CLIENT_REQ_REFRESH, &req, DEFAULT_TIME_SEC);
}

static bool process_UUID_sscanf(char *src, uint8_t *dest)
{
	if (strlen(src) == 4) {
		if (!sscanf_UUID(src, dest, TRUE, FALSE)) {
			BTT_LOG_S("Error: Incorrect UUID\n");
			return FALSE;
		}
	} else if (strlen(src) == 36) {
		if (!sscanf_UUID_128(src, dest, TRUE, FALSE)) {
			BTT_LOG_S("Error: Incorrect UUID\n");
			return FALSE;
		}
	} else {
		BTT_LOG_S("Error: Incorrect UUID\n");
		return FALSE;
	}

	return TRUE;
}

static void run_gatt_client_search_service(int argc, char **argv)
{
	struct btt_gatt_client_search_service req;
	char input[256];

	sscanf(argv[1], "%d", &req.conn_id);

	if (argc == 3) {
		sscanf(argv[2], "%s", input);
		req.is_filter = 1;

		if (!process_UUID_sscanf(input, req.filter_uuid.uu))
			return;
	} else {
		req.is_filter = 0;
	}

	process_request(BTT_GATT_CLIENT_REQ_SEARCH_SERVICE, &req, LONG_TIME_SEC);
}

static void run_gatt_client_get_included_service(int argc, char **argv)
{
	struct btt_gatt_client_get_included_service req;
	char input[256];

	if (argc == 5) {
		req.is_start = 0;
	} else if (argc == 8) {
		req.is_start = 1;
	} else {
		BTT_LOG_S("Error: Incorrect number of arguments\n");
		return;
	}

	sscanf(argv[1], "%d", &req.conn_id);
	sscanf(argv[2], "%s", input);

	if (!process_UUID_sscanf(input, req.srvc_id.id.uuid.uu))
		return;

	sscanf(argv[3], "%"SCNd8"", &req.srvc_id.is_primary);
	sscanf(argv[4], "%"SCNd8"", &req.srvc_id.id.inst_id);

	if (req.is_start) {
		sscanf(argv[5], "%s", input);

		if (!process_UUID_sscanf(input, req.start_incl_srvc_id.id.uuid.uu))
			return;

		sscanf(argv[6], "%"SCNd8, &req.start_incl_srvc_id.is_primary);
		sscanf(argv[7], "%"SCNd8, &req.start_incl_srvc_id.id.inst_id);
	}

	process_request(BTT_GATT_CLIENT_REQ_GET_INCLUDED_SERVICE, &req,
			DEFAULT_TIME_SEC);
}
