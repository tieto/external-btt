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

int app_socket = -1;

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
}

static char **create_argv(char *str_line, int argc)
{
	char **argv, *tmp, cp[BUFSIZ];
	int i;

	argv = malloc(argc * sizeof(char*));
	strcpy(cp, str_line);
	tmp = strtok(cp, " \n");

	for (i = 0; i < argc -1 ; ++i) {
		argv[i] = malloc((strlen(tmp) + 1) * sizeof(char));
		strcpy(argv[i], tmp);
		tmp = strtok(NULL, " \n");
	}

	return argv;
}

static void free_argv(char **argv, int argc)
{
	int i;

	for (i = 0; i < argc - 1; ++i)
		free(argv[i]);

	if(argc > 1)
		free(argv);
}

static int create_argc(char *str_line)
{
	char cp[BUFSIZ], *buf;
	int argc = 1;

	strcpy(cp, str_line);
	buf = strtok(cp, " \n");

	for (; buf; ++argc)
		buf = strtok(NULL, " \n");

	return argc;
}

static void signal_handler(int sig)
{
	BTT_LOG_S("\nSignal catched: %d\n", sig);
	run_exit(0, NULL);
}

static void signal_init(void)
{
	signal(SIGABRT, signal_handler);
	signal(SIGFPE, signal_handler);
	signal(SIGILL, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGPIPE, SIG_IGN);
}

static void run_exit(int argc, char **argv)
{
	free_argv(argv, argc + 1);
	BTT_LOG_S("Bluedroid Test Tool exited. \n\n");
	close(app_socket);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	unsigned int i;
	int length = 0;
	int argc2, tmp;
	char buff[BUFSIZ], **argv2, *buffer;
	fd_set set;
	struct btt_message btt_cb;

	FD_ZERO(&set);
	FD_SET(fileno(stdin), &set);

	mkdir(BTT_DIRECTORY, S_IRWXU|S_IRGRP|S_IXGRP);
	print_commands(commands, UI_SUPPORTED_COMMANDS);

	signal_init();
	errno = 0;

	while (true) {
		FD_ZERO(&set);
		FD_SET(fileno(stdin), &set);

		if (app_socket > 0)
			FD_SET(app_socket, &set);

		if (select((app_socket > 0 ? app_socket : fileno(stdin)) + 1, &set,
				NULL, NULL, NULL) == -1) {
			BTT_LOG_E("ERROR: Select error. ");
			return 1;
		}

		if (FD_ISSET(fileno(stdin), &set)) {
			label:
			tmp = fgetc(stdin);

			if (tmp!= EOF && (char)tmp != '\n') {
				buff[0] = (char) tmp;

				if (fgets(buff + sizeof(char), BUFSIZ, stdin) != NULL) {
					argc2 = create_argc(buff);
					argv2 = create_argv(buff, argc2);
				} else {
					BTT_LOG_S("Error: incorrect input.\n");
					exit(EXIT_FAILURE);
				}
			} else {
				continue;
			}

			for (i = 0; i < UI_SUPPORTED_COMMANDS; i += 1) {
				if (strcmp(argv2[0], commands[i].command) == 0) {
					if (!commands[i].run) {
						BTT_LOG_S("Not implemented yet");
					} else {
						if (app_socket < 0) {
							BTT_LOG_S("Not connected to daemon.\n");
							app_socket = connect_to_daemon_socket();
						}

						commands[i].run(argc2 - 1, argv2);

						if (errno == EPIPE) {
							app_socket = -1;
							errno = 0;
						}
					}
					break;
				}
			}

			if (i >= UI_SUPPORTED_COMMANDS) {
				BTT_LOG_S("Unknown main command: <%s>\n", argv2[0]);
				free_argv(argv2, argc2);
				print_commands(commands, UI_SUPPORTED_COMMANDS);
			} else {
				free_argv(argv2, argc2);
			}
		}

		if (app_socket > 0 && FD_ISSET(app_socket, &set)) {
			length = (int) recv(app_socket, &btt_cb,
					sizeof(struct btt_message), MSG_PEEK);

			if ((length == 0 || errno)) {
				buffer = malloc(btt_cb.length);

				if (buffer) {
					recv(app_socket, buffer, 256, 0);
					free(buffer);
				}

				app_socket = -1;
				errno = 0;
				continue;
			}

			if (btt_cb.command >= BTT_ADAPTER_CB_START &&
					btt_cb.command <= BTT_ADAPTER_CB_END) {
				handle_adapter_cb(&btt_cb);
			} else if (btt_cb.command >= BTT_GATT_CLIENT_CB_START &&
					btt_cb.command <= BTT_GATT_CLIENT_CB_END) {
				handle_gattc_cb(&btt_cb);
			} else if (btt_cb.command >= BTT_GATT_SERVER_CB_START &&
					btt_cb.command <= BTT_GATT_SERVER_CB_END) {
				handle_gatts_cb(&btt_cb);
			} else {
				buffer = malloc(btt_cb.length);

				if (buffer) {
					recv(app_socket, buffer, btt_cb.length, 0);
					free(buffer);
				}
			}
		}

	}

	return EXIT_SUCCESS;
}

