/*
 * Copyright 2013-2014 Tieto Corporation
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

#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include "btt.h"
#include "btt_adapter.h"
#include "btt_gatt_client.h"
#include "btt_gatt_server.h"

#include "btt_daemon_main.h"
#include "btt_utils.h"

int get_hexlines_length(int i_arg, int argc, char **argv)
{
	int length = 0;
	int arg_length;

	for (i_arg = 2; i_arg < argc; i_arg += 1) {
		arg_length = strlen(argv[i_arg]);
		length += arg_length / 2;
		if (arg_length % 2) {
			BTT_LOG_S("Error: Wrong argument length in hexline number %i\n",
					i_arg - 1);
			return -1;
		}
	}

	return length;
}

int hexlines_to_data(int i_arg, int argc, char **argv, unsigned char *data)
{
	unsigned int i_char;
	unsigned int arg_length;
	int          length = 0;
	char         num[3] = {0,0,0};

	for (i_arg = 2; i_arg < argc; i_arg += 1) {
		arg_length = strlen(argv[i_arg]);

		for (i_char = 0; i_char < arg_length - 1; i_char += 2) {
			num[0] = argv[i_arg][i_char];
			num[1] = argv[i_arg][i_char + 1];

			if (!isxdigit(num[0])) {
				BTT_LOG_S("Error: Wrong character in hexline number %i: <%c>\n",
						i_arg - 1, num[0]);
				return -1;
			}

			if (!isxdigit(num[1])) {
				BTT_LOG_S("Error: Wrong character in hexline number %i: <%c>\n",
						i_arg - 1, num[1]);
				return -2;
			}

			data[length] = strtoul(num, NULL, 16);
			length += 1;
		}
	}

	return length;
}

void print_bdaddr(uint8_t *source)
{
	BTT_LOG_S("%02X:%02X:%02X:%02X:%02X:%02X ",
			source[0], source[1], source[2],
			source[3], source[4], source[5]);
}

static void run_help(int argc, char **argv);

static struct command commands[] = {
		{ "help",    "", run_help    },
		{ "daemon",  "", run_daemon  },
		{ "adapter", "", run_adapter },
		{ "gatt_client","", run_gatt_client },
		{ "gatt_server", "", run_gatt_server }
};

#define UI_SUPPORTED_COMMANDS sizeof(commands)/sizeof(struct command)

static void run_help(int argc, char **argv)
{
	BTT_LOG_S("BTT - Bluedroid Test Tool aka Bluetooth Test Tool\n"
		"Copyright @ 2013 Tieto Corporation\n\n"
		"Version: %u.%u.%u\n\n"
		"Authors:\n"
		"\t""Marcin Kraglak         <marcin.kraglak@tieto.com>\n"
		"\t""Michal Labedzki        <michal.labedzki@tieto.com>\n"
		"\t""Wenjie Gong            <wenjie.gong@tieto.com>\n"
		"\t""Tianxiang Mi           <tianxiang.mi@tieto.com>\n"
		"\t""Aleksander Drewnicki   <ext.aleksander.drewnicki@tieto.com>\n"
		"\t""Wojciech Wojciechowski <ext.wojciech.wojciechowski@tieto.com>\n"
		"\n", VERSION_MAJOR, VERSION_MINOR, VERSION_RELEASE);

	print_commands(commands, UI_SUPPORTED_COMMANDS);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	unsigned int i;

	if (argc <= 1)
		run_help(0, NULL);

	mkdir(BTT_DIRECTORY, S_IRWXU|S_IRGRP|S_IXGRP);

	for (i = 0; i < UI_SUPPORTED_COMMANDS; i += 1) {
		if (strcmp(argv[1], commands[i].command) == 0) {
			if (!commands[i].run) {
				BTT_LOG_S("Not implemented yet");
			} else {
				commands[i].run(argc - 1, argv + 1);
			}
			break;
		}
	}
	if (i >= UI_SUPPORTED_COMMANDS) {
		BTT_LOG_S("Unknown main command: <%s>\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

