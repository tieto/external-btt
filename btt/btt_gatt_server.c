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

static const struct extended_command gatt_server_commands[] = {
		{{ "help",							"",						run_gatt_server_help}, 1, MAX_ARGC},
		{{ "register_server",				"NOT IMPLEMENTED YET",	NULL				}, 1, 1},
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
	/* TODO: add function's body */
}

void run_gatt_server(int argc, char **argv)
{
	run_generic_extended(gatt_server_commands, GATT_SERVER_SUPPORTED_COMMANDS,
			run_gatt_server_help, argc, argv);
}
