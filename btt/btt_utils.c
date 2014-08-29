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

#include "btt.h"
#include "btt_utils.h"
#include "btt_daemon_main.h"

void print_commands(const struct command *commands, unsigned int cmds_num)
{
	unsigned int  i;
	unsigned int  max_len;
	char         *while_separator;

	BTT_LOG_S("Commands:\n");

	max_len = 0;
	for (i = 0; i < cmds_num; i += 1) {
		max_len = (max_len < strlen(commands[i].command)) ?
				strlen(commands[i].command) : max_len;
	}
	max_len += 11;

	while_separator = (char *)malloc(max_len);

	for (i = 0; i < cmds_num; i += 1) {
		memset(while_separator, ' ',
				max_len - strlen(commands[i].command));
		while_separator[max_len - strlen(commands[i].command) - 1] = '\0';

#ifndef DEVELOPMENT_VERSION
		if (commands[i].run)
#endif
			BTT_LOG_S("\t%s%s%s\n", commands[i].command, while_separator,
					commands[i].description);
	}

	free(while_separator);

	BTT_LOG_S("\n");
}

void print_commands_extended(const struct extended_command *commands,
		unsigned int cmds_num)
{
	unsigned int i;
	unsigned int max_len;
	char *while_separator;

	BTT_LOG_S("Commands:\n");

	max_len = 0;

	for (i = 0; i < cmds_num; i += 1) {
		max_len = (max_len < strlen(commands[i].comm.command)) ?
				strlen(commands[i].comm.command) : max_len;
	}

	max_len += 11;
	while_separator = (char *)malloc(max_len);

	for (i = 0; i < cmds_num; i += 1) {
		memset(while_separator, ' ',
				max_len - strlen(commands[i].comm.command));
		while_separator[max_len - strlen(commands[i].comm.command) - 1] = '\0';
#ifndef DEVELOPMENT_VERSION
		if (commands[i].comm.run)
#endif
			BTT_LOG_S("\t%s%s%s\n", commands[i].comm.command, while_separator,
					commands[i].comm.description);
	}

	free(while_separator);

	BTT_LOG_S("\n");
}

void run_generic(const struct command *commands, unsigned int cmds_num,
		void (*help)(int argc, char **argv), int argc, char **argv)
{
	unsigned int i;

	if (argc <= 1)
		help(0, NULL);

	if (strcmp(argv[1], "help") != 0)
		btt_daemon_check();

	for (i = 0; i < cmds_num; i += 1) {
		if (strcmp(argv[1], commands[i].command) == 0) {
			if (!commands[i].run)
				BTT_LOG_S("Not implemented yet\n");
			else
				commands[i].run(argc - 1, argv + 1);
			break;
		}
	}
	if (i >= cmds_num) {
		BTT_LOG_S("Unknown \"%s\" command: <%s>\n", argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}
}

void run_generic_extended(const struct extended_command *commands,
		unsigned int cmds_num, void (*help)(int argc, char **argv),
		int argc, char **argv)
{
	unsigned int i;

	if (argc <= 1)
		help(0, NULL);

	if (strcmp(argv[1], "help") != 0)
		btt_daemon_check();

	for (i = 0; i < cmds_num; i += 1) {

		if (strcmp(argv[1], commands[i].comm.command) == 0) {
			if (!commands[i].comm.run) {
				BTT_LOG_S("Not implemented yet\n");
			} else {

				if (argc - 1 > commands[i].argc_max) {
					BTT_LOG_S("Error: Too many arguments\n");
					exit(EXIT_FAILURE);
				} else if (argc - 1 < commands[i].argc_min) {
					BTT_LOG_S("Error: Too few arguments\n");
					exit(EXIT_FAILURE);
				}
				commands[i].comm.run(argc - 1, argv + 1);
			}

			break;
		}
	}

	if (i >= cmds_num) {
		BTT_LOG_S("Unknown \"%s\" command: <%s>\n", argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}
}

struct btt_message *btt_send_command(struct btt_message *msg)
{
	int server_socket;
	unsigned int len;
	unsigned int length;
	struct sockaddr_un  server;
	struct btt_message *msg_rsp;
	struct timeval      tv;

	/* Default timeout for client socket*/
	tv.tv_sec  = 2;
	tv.tv_usec = 0;

	if ((server_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		BTT_LOG_E("Error: System socket error\n");
		return NULL;
	}

	setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO,
			(char *)&tv, sizeof(struct timeval));

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCK_PATH);
	len = strlen(server.sun_path) + sizeof(server.sun_family);
	if (connect(server_socket, (struct sockaddr *)&server, len) == -1) {
		BTT_LOG_E("Error: Daemon not run\n");
		close(server_socket);
		return NULL;
	}

	if (send(server_socket, (const char *)msg,
			sizeof(struct btt_message) + msg->length, 0) == -1) {
		BTT_LOG_E("Error: System socket send error\n");
		close(server_socket);
		return NULL;
	}

	msg_rsp = (struct btt_message *)malloc(sizeof(struct btt_message));
	len = recv(server_socket, (char *)msg_rsp,
			sizeof(struct btt_message), MSG_PEEK);
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		BTT_LOG_E("Error: Timeout\n");
		free(msg_rsp);
		close(server_socket);
		return NULL;
	}
	length = msg_rsp->length;
	free(msg_rsp);

	msg_rsp = (struct btt_message *)malloc(sizeof(struct btt_message) + length);
	len = recv(server_socket, (char *)msg_rsp,
			sizeof(struct btt_message) + length, 0);


	BTT_LOG_V("btt msg length: %u %u, full length: %u, received length: %u\n",
			msg_rsp->length,
			length,
			(unsigned int)sizeof(struct btt_message) + length,
			len);
	if (len < sizeof(struct btt_message) + length) {
		BTT_LOG_E("Error: Truncated reply\n");
		free(msg_rsp);
		close(server_socket);
		return NULL;
	}

	if (msg_rsp->command == BTT_RSP_ERROR_NO_TEST_INTERFACE) {
		BTT_LOG_S("Error: no test_interface\n");
		free(msg_rsp);
		close(server_socket);
		return NULL;
	}

	close(server_socket);

	return msg_rsp;
}

int get_cmd_string_by_cmd(int cmd, int sub_cmd,
		struct ext_btt_message **send_ext_cmd)
{
	unsigned int i;
	int cmd_len;
	int sub_cmd_len;
	int total_len;

	for (i = 0; i < TOTAL_EXT_CMDS_IN_MAP; i++) {
		if (cmd     == ext_command_map[i].cmd  &&
				sub_cmd == ext_command_map[i].sub_cmd ) {
			if (ext_command_map[i].cmd_str     == NULL ||
					ext_command_map[i].sub_cmd_str == NULL)
				return FALSE;

			cmd_len     = strlen(ext_command_map[i].cmd_str);
			sub_cmd_len = strlen(ext_command_map[i].sub_cmd_str);

			/*+1 for the '|' cmd spliter and +1 is for the '\0'
			 * at the string end.
			 */
			total_len = cmd_len + sub_cmd_len + 2;

			*send_ext_cmd = (struct ext_btt_message *)malloc(
					sizeof(struct ext_btt_message) + total_len);
			if (*send_ext_cmd == NULL) {
				BTT_LOG_E("Can't alloc memory!\n");
				return FALSE;
			}

			(*send_ext_cmd)->cmd      = cmd;
			(*send_ext_cmd)->sub_cmd  = sub_cmd;
			(*send_ext_cmd)->data_len = total_len;
			/*copy the cmd string to send_ext_cmd*/
			strcpy((char *)((*send_ext_cmd)->data), ext_command_map[i].cmd_str);

			*(char *)((*send_ext_cmd)->data + cmd_len) = SUB_CMD_DIVIDER;

			/*copy the sub cmd string to send_ext_cmd*/
			strcpy((char *)((*send_ext_cmd)->data + cmd_len + 1),
					ext_command_map[i].sub_cmd_str);

			return TRUE;
		}
	}
	return FALSE;
}

int start_ext_daemon(void)
{
	char *argv_execv[] = {"btt_ext_daemon", NULL};

	if (fork() == 0) {
		execv(EXT_DAEMON, argv_execv);

		/*ext daemon havn't been started*/
		BTT_LOG_S("Error: ext daemon can't be started, check if '/system/bin/btt_ext_daemon' exit there!\n");
		return 0;
	}

	/*parent returned*/
	return 1;
}

struct btt_message *btt_send_ext_command(struct ext_btt_message *ext_cmd,
		char *data, int data_len)
{
	int server_socket;
	unsigned int len;
	/*It contains the content send to ext daemon*/
	struct ext_btt_message *send_ext_cmd = NULL;
	struct sockaddr_un server;

	if (!get_cmd_string_by_cmd(ext_cmd->cmd, ext_cmd->sub_cmd, &send_ext_cmd)) {
		BTT_LOG_E("Error: can't find command string by command\n");
		return NULL;
	}

	if ((server_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		BTT_LOG_E("Error: System socket error\n");
		free(send_ext_cmd);
		return NULL;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, EXT_SOCK_PATH);

	len = strlen(server.sun_path) + sizeof(server.sun_family);
	if (connect(server_socket, (struct sockaddr *)&server, len) == -1) {
		BTT_LOG_E("Connect to btt ext daemon failed!\n");

		if ( ext_cmd->cmd     == BTT_EXT_DEAMON_CMD &&
				ext_cmd->sub_cmd == BTT_EXT_DAEMON_STOP_CMD) {
			BTT_LOG_I("btt ext daemon already stoped\n");
			free(send_ext_cmd);
			close(server_socket);
			return NULL;
		}

		/*try to start the ext daemon.*/
		BTT_LOG_S("Try to start btt ext daemon...\n");
		if (start_ext_daemon() == 0) {
			BTT_LOG_E("Start ext daemon failed\n");
			free(send_ext_cmd);
			close(server_socket);
			return NULL;
		} else {
			sleep(1);
			if (connect(server_socket, (struct sockaddr *)&server, len) == -1) {
				BTT_LOG_E("Still can't Connect to btt ext daemon\n");
				free(send_ext_cmd);
				close(server_socket);
				return NULL;
			}
		}
	}

	/*Send command string to ext daemon.*/
	if (send(server_socket, (const char *)send_ext_cmd,
			sizeof(struct ext_btt_message) + send_ext_cmd->data_len, 0) == -1) {
		BTT_LOG_E("Send command to btt ext daemon failed!\n");
		free(send_ext_cmd);
		close(server_socket);
		return NULL;
	}

	free(send_ext_cmd);
	/*Check if there are data need to be sent.*/
	if(data_len != 0) {
		/*Send data to daemon.*/
		if (send(server_socket, data, data_len, 0) == -1) {
			BTT_LOG_E("Send data to ext daemon failed!\n");
			close(server_socket);
			return NULL;
		}
	}


	/*TODO: add the recv procedure, currrently not needed*/

	close(server_socket);
	return NULL;
}

struct list_element *list_init(void)
{
	struct list_element *list = NULL;

	list = malloc(sizeof(struct list_element));
	list->next = NULL;

	return list;
}

bool list_contains(struct list_element *list, void *data,
		bool (*equal)(void *, void *))
{
	struct list_element *el = list;

	if (!list)
		return FALSE;

	for (; el; el = el->next)
		if ((*equal)(el->data, data))
			return TRUE;

	return FALSE;
}

struct list_element *list_append(struct list_element *list, void *data)
{
	struct list_element *new_el;
	struct list_element *tmp;

	new_el = malloc(sizeof(struct list_element));

	if (!new_el) {
		BTT_LOG_E("List adding - malloc error.\n");
		return NULL;
	}

	if (!list) {
		list = list_init();

		if (list)
			list->data = data;

		/*if malloc in init failed, NULL is returned*/
		return list;
	}

	tmp = list;

	for (; tmp->next; tmp = tmp->next) {
		/* just iterate */
	}

	new_el->data = data;
	new_el->next = NULL;
	tmp->next = new_el;

	return list;
}

struct list_element *list_clear(struct list_element *list,
		void (*data_destroy)(void *))
{
	struct list_element *tmp;

	if (!list)
		return NULL;

	do {
		(*data_destroy)(list->data);
		tmp = list->next;
		free(list);
		list = tmp;
	} while (tmp);

	return NULL;
}

bool sscanf_bdaddr(char *src, uint8_t *dest)
{
	if(sscanf(src, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
			&dest[0], &dest[1], &dest[2], &dest[3], &dest[4], &dest[5]) != EOF)
		return TRUE;

	return FALSE;
}

/* function return length of hex number
 * or -1 and -2 if error occurred */
int string_to_hex(char *src, uint8_t *dest)
{
	int len_s = strlen(src);
	int len_h;
	char tmp[3] = {0, 0, '\0'};
	int i, j = 0;

	if (len_s % 2) {
		BTT_LOG_S("Error: Wrong argument length.\n");
		return -1;
	}

	len_h = len_s / 2;

	for (i = 0; i < len_s; ++i) {
		if (!isxdigit(src[i])) {
			BTT_LOG_S("Error: Wrong character in argument.\n");
			return -2;
		}

		tmp[(i % 2)] = src[i];

		if (i % 2)
			dest[j++] = strtoul(tmp, '\0', 16);
	}

	return len_h;
}
