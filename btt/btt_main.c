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

static void run_help(int argc, char **argv);
static void run_exit(int argc, char **argv);

static struct command commands[] = {
		{ "help",    "", run_help    },
		{ "daemon",  "", run_daemon  },
		{ "adapter", "", run_adapter },
		{ "gattc","", run_gatt_client },
		{ "gatts", "", run_gatt_server },
		{ "exit", "", run_exit }
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

static void run_exit(int argc, char **argv)
{
	BTT_LOG_S("Bluedroid Test Tool exited. \n\n");
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

