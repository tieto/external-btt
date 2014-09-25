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

#ifdef BTT_ADAPTER_H
#error Included twice.
#endif
#define BTT_ADAPTER_H

struct btt_msg_cmd_adapter_scan_mode {
	struct btt_message hdr;

	unsigned int mode;
};

struct btt_msg_cmd_adapter_pair {
	struct btt_message hdr;

	uint8_t addr[BD_ADDR_LEN];
};

struct btt_msg_cmd_ssp {
	struct btt_message hdr;

	unsigned int accept;
	uint8_t      addr[BD_ADDR_LEN];
	unsigned int passkey;
	int          variant;
};

struct btt_msg_cmd_pin {
	struct btt_message hdr;

	uint8_t pin_code[PIN_CODE_MAX_LEN];
	uint8_t addr[BD_ADDR_LEN];
	uint8_t pin_len;
	uint8_t accept;
};

struct btt_cb_adapter_pin_request {
	struct btt_message hdr;

	unsigned int cod;
	char         name[NAME_MAX_LEN];
	uint8_t      bd_addr[BD_ADDR_LEN];
};

struct btt_cb_adapter_bond_state_changed {
	struct btt_message hdr;

	bt_status_t     status;
	bt_bond_state_t state;
	uint8_t         bd_addr[BD_ADDR_LEN];
};

struct btt_cb_adapter_ssp_request {
	struct btt_message hdr;

	unsigned int cod;
	unsigned int variant;
	uint8_t      bd_addr[BD_ADDR_LEN];
	char         name[NAME_MAX_LEN];
	unsigned int passkey;
};

struct btt_cb_adapter_state {
	struct btt_message hdr;

	bool state;
};

struct btt_cb_adapter_scan_mode_changed {
	struct btt_message hdr;

	/* mode:
	 * 0 - NONE
	 * 1 - CONNECTABLE
	 * 2 - CONNECTABLE & DISCOVERABLE
	 */
	int mode;
};

struct btt_cb_adapter_name {
	struct btt_message hdr;

	char name[NAME_MAX_LEN];
};

struct btt_cb_adapter_addr {
	struct btt_message hdr;

	uint8_t bd_addr[BD_ADDR_LEN];
};

struct btt_cb_adapter_device_found {
	struct btt_message hdr;

	uint8_t bd_addr[BD_ADDR_LEN];
	char    name[NAME_MAX_LEN];
	int     cod;
};

struct btt_cb_adapter_discovery {
	struct btt_message hdr;

	bool state;
};

extern void handle_adapter_cb(const struct btt_message *btt_cb);
extern void run_adapter(int argc, char **argv);
extern const struct command *btt_adapter_commands;

