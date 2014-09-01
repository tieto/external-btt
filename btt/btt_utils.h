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

#ifdef BTT_UTILS_H
#error Included twice
#endif
#define BTT_UTILS_H

extern void print_commands(const struct command *commands,
		unsigned int cmds_num);
extern void run_generic(const struct command *commands, unsigned int cmds_num,
		void (*help)(int argc, char **argv), int argc, char **argv);
extern struct btt_message *btt_send_command(struct btt_message *msg);
extern struct btt_message *btt_send_ext_command(struct ext_btt_message *ext_cmd,
		char *data, int data_len);
extern void run_generic_extended(const struct extended_command *commands,
		unsigned int cmds_num, void (*help)(int argc, char **argv),
		int argc, char **argv);
extern void print_commands_extended(const struct extended_command*commands,
		unsigned int cmds_num);

struct list_element
{
	void *data;
	struct list_element *next;
};

void (*data_destroy)(void *);
bool (*equal)(void *, void *);
extern struct list_element *list_init(void);
extern bool list_contains(struct list_element *list, void *data,
		bool (*equal)(void *, void *));
extern struct list_element *list_append(struct list_element *list,void *data);
struct list_element *list_clear(struct list_element *list,
		void (*data_destroy)(void *));
extern bool sscanf_bdaddr(char *src, uint8_t *dest);
extern int string_to_hex(char *src, uint8_t *dest);
extern bool sscanf_UUID(char *src, uint8_t *dest);
extern void printf_UUID_128(uint8_t *src);

/* return FALSE if length of received structure is different
 * from expected length */
#define RECV(ptr, sock) (((recv((sock), (ptr), \
		sizeof(*(ptr)), 0)) != (sizeof(*(ptr)))) ? FALSE : TRUE)
