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
#define MAX_ARGC 20

extern void print_commands(const struct command *commands,
		unsigned int cmds_num);
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
extern void print_bdaddr(uint8_t *source);
extern bool sscanf_bdaddr(char *src, uint8_t *dest);
extern void byte_swap(uint8_t *src, uint8_t *dest);
extern void invert_hex_UUID(uint8_t *src, uint8_t *dest, bool swap_bytes);
extern int string_to_hex(char *src, uint8_t *dest);
extern bool sscanf_UUID(char *src, uint8_t *dest, bool invert,
		bool swap_bytes);
extern void printf_UUID_128(uint8_t *src, bool invert, bool swap_bytes);
extern bool sscanf_UUID_128(char *src, uint8_t *dest, bool invert,
		bool swap_bytes);
int get_hexlines_length(int i_arg, int argc, char **argv);
int hexlines_to_data(int i_arg, int argc, char **argv, unsigned char *data);
int connect_to_daemon_socket(void);

/* return FALSE if length of received structure is different
 * from expected length */
#define RECV(ptr, sock) (((recv((sock), (ptr), \
		sizeof(*(ptr)), 0)) != (sizeof(*(ptr)))) ? FALSE : TRUE)

#define FILL_HDR(str, comm) \
	{ \
		(((str).hdr.command) = (comm)); \
		(((str).hdr.length) = (sizeof((str)) - \
				sizeof(struct btt_message))); \
	}

#define FILL_HDR_P(ptr, comm) FILL_HDR((*ptr), comm)

#define FILL_MSG_P(p_data, ptr, comm) \
	{ \
		((ptr) = (typeof((ptr))) (p_data)); \
		FILL_HDR_P(ptr, comm); \
	}
