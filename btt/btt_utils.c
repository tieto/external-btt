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

void run_generic_extended(const struct extended_command *commands,
		unsigned int cmds_num, void (*help)(int argc, char **argv),
		int argc, char **argv)
{
	unsigned int i;

	if (argc <= 1) {
		help(0, NULL);
		return;
	}

	if (strcmp(argv[1], "help") != 0)
		btt_daemon_check();

	for (i = 0; i < cmds_num; i += 1) {

		if (strcmp(argv[1], commands[i].comm.command) == 0) {
			if (!commands[i].comm.run) {
				BTT_LOG_S("Not implemented yet\n");
			} else {

				if (argc - 1 > commands[i].argc_max) {
					BTT_LOG_S("Error: Too many arguments\n");
					return;
				} else if (argc - 1 < commands[i].argc_min) {
					BTT_LOG_S("Error: Too few arguments\n");
					return;
				}
				commands[i].comm.run(argc - 1, argv + 1);
			}

			break;
		}
	}

	if (i >= cmds_num) {
		BTT_LOG_S("Unknown \"%s\" command: <%s>\n", argv[0], argv[1]);
		return;
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

void print_bdaddr(uint8_t *source)
{
	BTT_LOG_S("%02X:%02X:%02X:%02X:%02X:%02X ",
			source[0], source[1], source[2],
			source[3], source[4], source[5]);
}

/* swap hex digits in one byte, like 0x1A -> 0xA1 */
void byte_swap(uint8_t *src, uint8_t *dest)
{
	*dest = (((*src) & 0x0F) << 4);
	*dest += (((*src) & 0xF0) >> 4);
}

/* inverting UUID in hex array */
void invert_hex_UUID(uint8_t *src, uint8_t *dest, bool swap_bytes)
{
	unsigned int i, ulen = sizeof(bt_uuid_t);
	uint8_t tmp;

	memcpy(dest, src, ulen);

	for (i = 0; i < ulen / 2; i++) {
		tmp = dest[i];
		dest[i] = dest[(ulen - 1) - i];
		dest[(ulen - 1) - i] = tmp;

		if (swap_bytes) {
			byte_swap(&dest[i], &dest[i]);
			byte_swap(&dest[(ulen - 1) - i], &dest[(ulen - 1) - i]);
		}
	}
}

bool sscanf_UUID(char *src, uint8_t *dest, bool invert, bool swap_bytes)
{
	uint8_t tab[2];
	char *checkString = NULL;
	long convertedString = strtoul(src, &checkString, 16);

	if(strlen(checkString))
		return FALSE;

	tab[0] = (convertedString >> 8) & 0x00FF;
	tab[1] = convertedString & 0x00FF;

	/* BASE_UUID: 00000000-0000-1000-8000-00805F9B34FB */
	uint8_t bt_uuid[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
			0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };

	bt_uuid[2] = tab[0];
	bt_uuid[3] = tab[1];

	if (invert)
		invert_hex_UUID(bt_uuid, dest, swap_bytes);
	else
		memcpy(dest, bt_uuid, sizeof(bt_uuid));

	return TRUE;
}

/* source array should have form like:
 * 00000000-FFFF-0000-FFFF-000000000000 */
bool sscanf_UUID_128(char *src, uint8_t *dest, bool invert, bool swap_bytes)
{
	/* UUID's string length: 32 * hex digit + 4 * '-' */
	unsigned int i, j = 0, UUID_slen = 36;
	char clear_UUID[UUID_slen - 3];

	if (strlen(src) != UUID_slen)
		return FALSE;

	for (i = 0; i < strlen(src); i++) {
		if(!isxdigit(src[i]) && src[i] != '-')
			return FALSE;

		if (src[i] != '-') {
			clear_UUID[j] = src[i];
			++j;
		}
	}

	clear_UUID[UUID_slen - 4] = '\0';

	if (!string_to_hex(clear_UUID, dest))
		return FALSE;

	if (invert)
		invert_hex_UUID(dest, dest, swap_bytes);

	return TRUE;
}

void printf_UUID_128(uint8_t *src, bool invert, bool swap_bytes)
{
	unsigned int i, ulen = sizeof(bt_uuid_t);
	uint8_t tmp;

	BTT_LOG_S("UUID: ");

	/* inverting source array */
	if (invert)
		invert_hex_UUID(src, src, swap_bytes);

	for (i = 0; i < ulen; i++) {
		BTT_LOG_S("%.2X", src[i]);

		if (i == 3 || i == 5 || i == 7 || i== 9)
			BTT_LOG_S("-");

	}

	BTT_LOG_S("\n");
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
	int length = 0;
	char num[3] = {0,0,0};

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
