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
#define MAX_ARGC 20

static void run_gatt_client_help(int argc, char **argv);
static void run_gatt_client_scan(int argc, char **argv);
static void run_gatt_client_register_client(int argc, char **argv);
static void run_gatt_client_un_register_client(int argc, char **argv);

static int create_daemon_socket(void);
static void set_sock_rcv_time(unsigned int sec, unsigned int usec,
		int server_sock);
static bool send_by_socket(int server_sock, void *data, size_t len, int flags);
static bool process_send_to_daemon(enum btt_gatt_client_req_t type, void *data,
		int server_sock, bool *select_used);
static bool process_receive_from_daemon(enum btt_gatt_client_req_t type,
		bool *wait_for_msg, int server_sock);
static bool process_stdin(bool *select_used);

static const struct extended_command gatt_client_commands[] = {
		{{ "help",							"",							run_gatt_client_help}, 1, MAX_ARGC},
		{{ "scan",							"<client_if>",				run_gatt_client_scan}, 2, 2},
		{{ "register_client",				"<16-bits UUID>", run_gatt_client_register_client}, 2, 2},
		{{ "unregister_client",				"<client_if>", run_gatt_client_un_register_client}, 2, 2},
		{{ "connect",						"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "disconnect",					"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "listen",						"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "refresh",						"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "search_service",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "get_included_service",			"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "get_charakteristic",			"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "get_descriptor",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "read_descriptor",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "write_descriptor",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "execute_write",					"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "register_for_notification",		"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "deregister_for_notification",	"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "read_remote_rssi",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "get_device_type",				"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "set_adv_data",					"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
		{{ "test_command",					"NOT IMPLEMENTED YET",	NULL					}, 1, 1},
};

#define GATT_CLIENT_SUPPORTED_COMMANDS sizeof(gatt_client_commands)/sizeof(struct extended_command)

void run_gatt_client_help(int argc, char **argv)
{
	print_commands_extended(gatt_client_commands,
			GATT_CLIENT_SUPPORTED_COMMANDS);
	exit(EXIT_SUCCESS);
}

static void process_request(enum btt_gatt_client_req_t type, void *data)
{
	int server_sock;
	bool wait_for_msg = TRUE;

	/*select variables*/
	/*presently select is needed only by scan*/
	bool select_used = FALSE;
	fd_set set_cp;
	fd_set set;

	FD_ZERO(&set);
	FD_ZERO(&set_cp);

	errno = 0;

	server_sock = create_daemon_socket();
	set_sock_rcv_time(DEFAULT_TIME_SEC, 0, server_sock);
	if (!process_send_to_daemon(type, data, server_sock, &select_used))
		return;

	if (select_used) {
		FD_SET(fileno(stdin), &set);
		FD_SET(server_sock, &set);
	}

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
			if (process_stdin(&select_used))
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
	process_request(BTT_GATT_CLIENT_REQ_SCAN, &req);
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
	if (send(server_sock, (const char *) data, len, flags) == -1) {
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
				sizeof(struct btt_gatt_client_register_client), 0) == -1)
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
				sizeof(struct btt_gatt_client_unregister_client), 0) == -1)
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
				== BTT_GATT_CLIENT_REQ_UNREGISTER_CLIENT)) ? FALSE : TRUE);
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
			BTT_LOG_S("UUID: ");

			for (i = 0; i < sizeof(cb.app_uuid); i++) {
				BTT_LOG_S("%.2X", cb.app_uuid.uu[i]);

				/* formating UUID */
				if (i == 3 || i == 5 || i==7 || i == 9)
					BTT_LOG_S("-");
			}

			BTT_LOG_S("\nStatus: %s\n", (!cb.status) ? "OK" : "ERROR");
			BTT_LOG_S("Client interface: %d\n\n", cb.client_if);
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

/* presently used only by scan */
static bool process_stdin(bool *select_used)
{
	char buf[256];
	unsigned int tmp = 0;
	int server_sock;

	scanf("%s", buf);

	if (!strncmp(buf, "stop", 4)) {
		server_sock = create_daemon_socket();

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

/* returned memory block must be free */
static bt_uuid_t *create_uuid(uint8_t *bit_16)
{
	uint8_t base[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};
	bt_uuid_t *pUUID = calloc(1, sizeof(bt_uuid_t));

	base[2] = bit_16[1];
	base[3] = bit_16[0];
	memcpy(pUUID->uu, base, sizeof(base));

	return pUUID;
}

/* 4 hex-number as argument, like FFFF */
static void run_gatt_client_register_client(int argc, char **argv)
{
	char input[256];
	unsigned long tmp;
	uint8_t tab[2];
	bt_uuid_t *UUID;
	struct btt_gatt_client_register_client req;

	sscanf(argv[1], "%s", input);
	if (strlen(input) != 4) {
		BTT_LOG_S("Error: Incorrect UUID\n");
		return;
	}

	tmp = strtoul(input, NULL, 16);
	tab[0] = (0x00FF & tmp);
	tab[1] = ((0xFF00 & tmp) >> 8);

	UUID = create_uuid(tab);
	memcpy(&req.UUID, UUID, sizeof(bt_uuid_t));
	free(UUID);
	UUID = NULL;

	process_request(BTT_GATT_CLIENT_REQ_REGISTER_CLIENT, &req);
}

static void run_gatt_client_un_register_client(int argc, char **argv)
{
	struct btt_gatt_client_unregister_client req;

	sscanf(argv[1], "%d", &req.client_if);
	process_request(BTT_GATT_CLIENT_REQ_UNREGISTER_CLIENT, &req);
}
