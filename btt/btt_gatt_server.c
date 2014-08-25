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

static const struct extended_command gatt_server_commands[] = {
		{{ "help",							"",						run_gatt_server_help}, 1, MAX_ARGC},
		{{ "register_server",				"<16-bits UUID>",		run_gatt_server_reg}, 2, 2},
		{{ "unregister_server",				"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "connect",						"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "disconnect",					"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "add_service",					"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "add_included_service",			"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "add_charakteristic",			"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "add_descriptor",				"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "start_service",					"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "stop_service",					"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "delete_service",				"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "send_indication",				"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
		{{ "send_response",					"NOT IMPLEMENTED YET",	NULL				}, 1, 1}
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

void run_gatt_server(int argc, char **argv)
{
	run_generic_extended(gatt_server_commands, GATT_SERVER_SUPPORTED_COMMANDS,
			run_gatt_server_help, argc, argv);
}
