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
#include "btt_adapter.h"
#include "btt_utils.h"

enum reguest_type_t {
	BTT_REQ_ADDRESS,
	BTT_REQ_NAME,
	BTT_REQ_UP,
	BTT_REQ_DOWN,
	BTT_REQ_SCAN,
	BTT_REQ_SSP_REPLY,
	BTT_REQ_PIN_REPLY,
	BTT_REQ_SCAN_MODE,
	BTT_REQ_PAIR,
	BTT_REQ_UNPAIR
};

struct btt_req_pair {
	uint8_t addr[BD_ADDR_LEN];
};

static void run_adapter_help(int argc, char **argv);
static void run_adapter_up(int argc, char **argv);
static void run_adapter_down(int argc, char **argv);
static void run_adapter_scan_mode(int argc, char **argv);
static void run_adapter_name(int argc, char **argv);
static void run_adapter_address(int argc, char **argv);
static void run_adapter_scan(int argc, char **argv);
static void run_adapter_pair(int argc, char **argv);
static void run_adapter_unpair(int argc, char **argv);
static void run_adapter_ssp_reply(int argc, char **argv);
static void run_adapter_pin_reply(int argc, char **argv);

static const struct extended_command adapter_commands[] = {
		{{ "help",                   "",                                           run_adapter_help           }, 1, MAX_ARGC},
		{{ "up",                     "",                                           run_adapter_up             }, 1, 1},
		{{ "down",                   "",                                           run_adapter_down           }, 1, 1},
		{{ "scan_mode",              "<none | connectable | connectable_discoverable >", run_adapter_scan_mode}, 2, 2},
		{{ "name",                   "",                                           run_adapter_name           }, 1, 1},
		{{ "address",                "",                                           run_adapter_address        }, 1, 1},
		{{ "scan",                   "",                                           run_adapter_scan           }, 1, 1},
		{{ "SSP_reply",              "<accept> <BD_ADDR> <passkey> <variant>",     run_adapter_ssp_reply      }, 5, 5},
		{{ "PIN_reply",              "<accept> <pin code> <BD_ADDR>",              run_adapter_pin_reply      }, 4, 4},
		{{ "pair",                   "<BD_ADDR>",                                  run_adapter_pair           }, 2, 2},
		{{ "unpair",                 "NOT IMPLEMENTED YET <BD_ADDR>",              NULL                       }, 2, 2},
		{{ "simple_pairing",         "NOT IMPLEMENTED YET [on | off]",             NULL                       }, 1, 2},
		{{ "class",                  "NOT IMPLEMENTED YET [NUMBER]",               NULL                       }, 1, 2},
		{{ "connect",                "NOT IMPLEMENTED YET <BD_ADDR>",              NULL                       }, 2, 2},
		{{ "send",                   "NOT IMPLEMENTED YET <HANDLE> <HEXLINES...>", NULL                       }, 3, MAX_ARGC},
		{{ "receive",                "NOT IMPLEMENTED YET <HANDLE> <print | print_all | check [HEXLINES...] | wait [HEXLINES...]>", NULL }, 3, MAX_ARGC},
		{{ "disconnect",             "NOT IMPLEMENTED YET <HANDLE>",               NULL                       }, 2, 2}
};

#define ADAPTER_SUPPORTED_COMMANDS sizeof(adapter_commands)/sizeof(struct extended_command)

void run_adapter(int argc, char **argv) {
	run_generic_extended(adapter_commands, ADAPTER_SUPPORTED_COMMANDS,
			run_adapter_help, argc, argv);
}

void run_adapter_help(int argc, char **argv) {
	print_commands_extended(adapter_commands, ADAPTER_SUPPORTED_COMMANDS);
}

/* TODO:
 * add method to print bt address
 * add pair method
 * add unpair method
 * add get properties method
 */
static void process_request(enum reguest_type_t type, void *data)
{
	int server_sock;
	unsigned int len;
	struct sockaddr_un server;
	struct btt_message msg;
	struct timeval     tv;
	struct btt_message  btt_cb;
	char *buffer;

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
	case BTT_REQ_ADDRESS:
		tv.tv_sec  = 1;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		msg.command = BTT_CMD_ADAPTER_ADDRESS;
		msg.length  = 0;
		if (send(server_sock, (const char *)&msg,
				sizeof(struct btt_message) + msg.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	case BTT_REQ_NAME:
		tv.tv_sec  = 1;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		msg.command = BTT_CMD_ADAPTER_NAME;
		msg.length  = 0;
		if (send(server_sock, (const char *)&msg,
				sizeof(struct btt_message) + msg.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	case BTT_REQ_UP:
		tv.tv_sec  = 3;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		msg.command = BTT_CMD_ADAPTER_UP;
		msg.length  = 0;
		if (send(server_sock, (const char *)&msg,
				sizeof(struct btt_message) + msg.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	case BTT_REQ_DOWN:
		tv.tv_sec  = 3;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		msg.command = BTT_CMD_ADAPTER_DOWN;
		msg.length  = 0;
		if (send(server_sock, (const char *)&msg,
				sizeof(struct btt_message) + msg.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	case BTT_REQ_SCAN:
		tv.tv_sec  = 15;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		msg.command = BTT_CMD_ADAPTER_SCAN;
		msg.length  = 0;
		if (send(server_sock, (const char *)&msg,
				sizeof(struct btt_message) + msg.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	case BTT_REQ_SSP_REPLY: {
		struct btt_msg_cmd_ssp *cmd_ssp;

		tv.tv_sec  = 4;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		FILL_MSG_P(data, cmd_ssp, BTT_RSP_SSP_REPLY);

		if (send(server_sock, (const char *) cmd_ssp,
				sizeof(struct btt_msg_cmd_ssp)
				+ cmd_ssp->hdr.length, 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_REQ_PIN_REPLY: {
		struct btt_msg_cmd_pin *cmd_pin;

		tv.tv_sec  = 4;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *) &tv, sizeof(struct timeval));

		FILL_MSG_P(data, cmd_pin, BTT_RSP_PIN_REPLY);

		if (send(server_sock, (const char *) cmd_pin,
				sizeof(struct btt_msg_cmd_pin)
				+ cmd_pin->hdr.length, 0) == -1) {
			close(server_sock);
			return;
		}

		break;
	}
	case BTT_REQ_SCAN_MODE: {
		struct btt_msg_cmd_adapter_scan_mode cmd_scan;

		tv.tv_sec  = 3;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		cmd_scan.mode = *(unsigned int *)data;
		FILL_HDR(cmd_scan, BTT_CMD_ADAPTER_SCAN_MODE);

		if (send(server_sock, (const char *)&cmd_scan,
				sizeof(struct btt_message) + cmd_scan.hdr.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	}
	case BTT_REQ_PAIR: {
		struct btt_msg_cmd_adapter_pair cmd_pair;
		struct btt_req_pair *req_pair;

		tv.tv_sec  = 15;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		req_pair = (struct btt_req_pair *)data;
		FILL_HDR(cmd_pair, BTT_CMD_ADAPTER_PAIR);
		memcpy(cmd_pair.addr, req_pair->addr, sizeof(req_pair->addr));
		if (send(server_sock, (const char *)&cmd_pair,
				sizeof(struct btt_message) + cmd_pair.hdr.length, 0) == -1) {
			close(server_sock);
			return;
		}
		break;
	}
	case BTT_REQ_UNPAIR: {
		struct btt_msg_cmd_adapter_pair cmd_unpair;
		struct btt_req_pair *req_unpair;

		tv.tv_sec  = 15;
		tv.tv_usec = 0;
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
				(char *)&tv,sizeof(struct timeval));

		req_unpair = (struct btt_req_pair *)data;
		FILL_HDR(cmd_unpair, BTT_CMD_ADAPTER_UNPAIR);
		memcpy(cmd_unpair.addr, req_unpair->addr, sizeof(req_unpair->addr));
		if (send(server_sock, (const char *)&cmd_unpair,
				sizeof(struct btt_message) + cmd_unpair.hdr.length, 0) == -1) {
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
		switch (btt_cb.command) {
		case BTT_ADAPTER_PIN_REQUEST: {
			struct btt_cb_adapter_pin_request pin_req;

			BTT_LOG_S("\nPIN request\n\n");

			recv(server_sock, &pin_req, sizeof(pin_req), 0);

			/* application can receive this callback asynchronously,
			 * so type condition is removed */
			BTT_LOG_S("COD: %u \n", pin_req.cod);
			BTT_LOG_S("Name: %s\n", pin_req.name);
			print_bdaddr(pin_req.bd_addr);
			BTT_LOG_S("\n");

			break;
		}
		case BTT_ADAPTER_SSP_REQUEST: {
			struct btt_cb_adapter_ssp_request ssp_request;

			BTT_LOG_S("\nSSP request\n\n");

			recv(server_sock, &ssp_request, sizeof(ssp_request), 0);

			/* application can receive this callback asynchronously,
			 * so type condition is removed */
			BTT_LOG_S("COD: %u \n", ssp_request.cod);
			BTT_LOG_S("Name: %s\n", ssp_request.name);
			print_bdaddr(ssp_request.bd_addr);
			BTT_LOG_S("\n");
			BTT_LOG_S("Passkey: %u\n", ssp_request.passkey);
			BTT_LOG_S("Variant: %u\n\n", ssp_request.variant);

			break;
		}
		case BTT_ADAPTER_BOND_STATE_CHANGED: {
			struct btt_cb_adapter_bond_state_changed state;

			len = recv(server_sock, &state, sizeof(state), 0);
			if (state.status == BT_STATUS_SUCCESS) {
				print_bdaddr(state.bd_addr);
				if (state.state == BT_BOND_STATE_BONDED) {
					BTT_LOG_S("Bonded successfully\n");
					close(server_sock);
					return;
				} else if (state.state == BT_BOND_STATE_BONDING) {
					BTT_LOG_S("Bonding\n");
				} else {
					BTT_LOG_S("Not bonded\n");
					close(server_sock);
					return;
				}
			} else {
				BTT_LOG_S("bt_status_t is %d\n", state.status);
				close(server_sock);
				return;
			}
			break;
		}
		case BTT_ADAPTER_DEVICE_FOUND: {
			struct btt_cb_adapter_device_found device;

			memset(&device, 0, sizeof(device));
			len = recv(server_sock, &device, sizeof(device), 0);
			if (type == BTT_REQ_SCAN) {
				print_bdaddr(device.bd_addr);
				BTT_LOG_S("%s\n", device.name);
			}
			break;
		}
		case BTT_ADAPTER_DISCOVERY: {
			struct btt_cb_adapter_discovery discovery;

			len = recv(server_sock, &discovery, sizeof(discovery), 0);
			if (type == BTT_REQ_SCAN) {
				if (discovery.state) {
					BTT_LOG_S("Discovery started\n");
				} else {
					BTT_LOG_S("Discovery stopped\n");
					close(server_sock);
					return;
				}
			}
			break;
		}
		case BTT_ADAPTER_ADDRESS: {
			struct btt_cb_adapter_addr address;

			len = recv(server_sock, &address, sizeof(address), 0);
			if (type == BTT_REQ_ADDRESS) {
				print_bdaddr(address.bd_addr);
				BTT_LOG_S("\n");
				close(server_sock);
				return;
			}
			break;
		}
		case BTT_ADAPTER_STATE_CHANGED: {
			struct btt_cb_adapter_state state;

			len = recv(server_sock, &state, sizeof(state), 0);
			if (BTT_REQ_UP && state.state) {
				BTT_LOG_S("Turned on\n");
				close(server_sock);
				return;
			}
			if (BTT_REQ_DOWN && !state.state) {
				BTT_LOG_S("Turned off\n");
				close(server_sock);
				return;
			}
			break;
		}
		case BTT_ADAPTER_SCAN_MODE_CHANGED: {
			struct btt_cb_adapter_scan_mode_changed scan_mode;

			len = recv(server_sock, &scan_mode, sizeof(scan_mode), 0);
			if (type == BTT_REQ_SCAN_MODE) {
				if (scan_mode.mode == 0) {
					BTT_LOG_S("Scan mode changed -> NONE\n");
				} else if (scan_mode.mode == 1) {
					BTT_LOG_S("Scan mode changed -> CONNECTABLE\n");
				} else if (scan_mode.mode == 2) {
					BTT_LOG_S("Scan mode changed -> CONNECTABLE & DISCOVERABLE\n");
				} else if (scan_mode.mode == 3) {
					BTT_LOG_S("Scan mode changed -> FAILED\n");
				} else if (scan_mode.mode == 4) {
					BTT_LOG_S("Scan mode changed -> ALREADY DONE\n");
				} else {
					BTT_LOG_S("WTF\n");
				}
				close(server_sock);
				return;
			}
			break;
		}
		case BTT_ADAPTER_NAME: {
			struct btt_cb_adapter_name name;

			memset(&name, 0, sizeof(name));
			len = recv(server_sock, &name, sizeof(name), 0);
			if (type == BTT_REQ_NAME) {
				BTT_LOG_S("%s\n",name.name);
				close(server_sock);
				return;
			}
			break;
		}
		default:
			buffer = malloc(btt_cb.length);
			if (buffer) {
				len = recv(server_sock, buffer, btt_cb.length, 0);
				free(buffer);
			}
			break;
		}
	}
}

static void run_adapter_address(int argc, char **argv)
{
	process_request(BTT_REQ_ADDRESS, NULL);
}

static void run_adapter_scan(int argc, char **argv)
{
	process_request(BTT_REQ_SCAN, NULL);
}

static void run_adapter_ssp_reply(int argc, char **argv)
{
	struct btt_msg_cmd_ssp cmd_rsp;

	sscanf(argv[1], "%u", &cmd_rsp.accept);
	sscanf_bdaddr(argv[2], cmd_rsp.addr);
	sscanf(argv[3], "%u", &cmd_rsp.passkey);
	sscanf(argv[4], "%d", &cmd_rsp.variant);

	process_request(BTT_REQ_SSP_REPLY, &cmd_rsp);
}

static void run_adapter_pin_reply(int argc, char **argv)
{
	struct btt_msg_cmd_pin cmd_rsp;
	char buff[256];

	sscanf(argv[1], "%"SCNx8"", &cmd_rsp.accept);
	sscanf(argv[2], "%s", buff);
	cmd_rsp.pin_len = string_to_hex(buff, cmd_rsp.pin_code);
	sscanf_bdaddr(argv[3], cmd_rsp.addr);

	process_request(BTT_REQ_PIN_REPLY, &cmd_rsp);
}

static void run_adapter_name(int argc, char **argv)
{
	process_request(BTT_REQ_NAME, NULL);
}

static void run_adapter_up(int argc, char **argv)
{
	process_request(BTT_REQ_UP, NULL);
}

static void run_adapter_down(int argc, char **argv)
{
	process_request(BTT_REQ_DOWN, NULL);
}

static void run_adapter_scan_mode(int argc, char **argv)
{
	unsigned int mode;

	if (strcmp(argv[1], "none") == 0)
		mode = 0;
	else if (strcmp(argv[1], "connectable") == 0)
		mode = 1;
	else if (strcmp(argv[1], "connectable_discoverable") == 0)
		mode = 2;
	else
		mode = strtoul(argv[1], NULL, 0);

	if (mode > 2) {
		BTT_LOG_S("Error: Unknown mode\n");
		return;
	}

	process_request(BTT_REQ_SCAN_MODE, &mode);
}

static void run_adapter_pair(int argc, char **argv)
{
	struct btt_req_pair req;

	sscanf(argv[1], "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
			&req.addr[0], &req.addr[1], &req.addr[2],
			&req.addr[3], &req.addr[4], &req.addr[5]);

	process_request(BTT_REQ_PAIR, &req);
}

static void run_adapter_unpair(int argc, char **argv)
{
	struct btt_req_pair req;

	sscanf(argv[1], "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
			&req.addr[0], &req.addr[1], &req.addr[2],
			&req.addr[3], &req.addr[4], &req.addr[5]);

	process_request(BTT_REQ_UNPAIR, &req);
}

