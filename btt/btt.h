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

#ifndef BTT_H
#define BTT_H

#define FALSE 0
#define TRUE  1

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <ctype.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>

/* NOTE: Required by Bluedroid, but this is part of Android, do not forget to
 *       copy them (and other) on other platform */
#include <hardware/bluetooth.h>

#define BTT_DIRECTORY_NAME     ".btt"
#define BTT_SOCKET_NAME        "btt.socket"
#define BTT_AGENT_SOCKET_NAME  "btt.agent"

#ifdef ANDROID
#define BTT_DIRECTORY "/data/"BTT_DIRECTORY_NAME
#else
#define BTT_DIRECTORY "/var/lock/"BTT_DIRECTORY_NAME
#endif

#ifdef ANDROID
#define BTT_LOG_E(args...) ALOGE(args)
#define BTT_LOG_W(args...) ALOGW(args)
#define BTT_LOG_I(args...) ALOGI(args)
#define BTT_LOG_D(args...) ALOGD(args)
#define BTT_LOG_V(args...) ALOGV(args)
#define BTT_LOG_S(args...) printf(args)
#else
#if DEVELOPMENT_VERSION == TRUE
#define BTT_LOG_E(args...) printf("E " args)
#define BTT_LOG_W(args...) printf("W " args)
#define BTT_LOG_I(args...) printf("I " args)
#define BTT_LOG_D(args...) printf("D " args)
#define BTT_LOG_V(args...) printf("V " args)
#else
#define BTT_LOG_E(args...)
#define BTT_LOG_W(args...)
#define BTT_LOG_I(args...)
#define BTT_LOG_D(args...)
#define BTT_LOG_V(args...)
#endif
#define BTT_LOG_S(args...) printf(args)
#endif

#define SOCK_PATH BTT_DIRECTORY"/"BTT_SOCKET_NAME
#define AGENT_SOCK_PATH BTT_DIRECTORY"/"BTT_AGENT_SOCKET_NAME
#define BTT_EXT_SOCKET_NAME        "btt_ext_daemon.socket"
#define BTT_EXT_DAEMON_DIRECTORY_NAME     "btt_ext_daemon"
#define SUB_CMD_DIVIDER '|'
#define BTT_EXT_DAEMON_DIRECTORY BTT_DIRECTORY"/"BTT_EXT_DAEMON_DIRECTORY_NAME
#define EXT_SOCK_PATH BTT_EXT_DAEMON_DIRECTORY"/"BTT_EXT_SOCKET_NAME
#define EXT_DAEMON "/system/bin/btt_ext_daemon"

#define VERSION_MAJOR    0
#define VERSION_MINOR    1
#define VERSION_RELEASE  0
#include "version_build.h"

#define MAX_CONF_NEG     3
#define PIN_CODE_MAX_LEN 16
#define BD_ADDR_LEN      6
#define UUID_LEN         16
#define NAME_MAX_LEN     256

struct command {
	char const *command;
	char const *description;
	void (*run)(int argc, char **argv);
};

struct extended_command {
	struct command comm;
	uint8_t argc_min;
	uint8_t argc_max;
};

struct btt_message {
	unsigned int command;
	unsigned int length;
};

struct l2cap_session_data {
	int      psm;
	int      cid;
	bool     omtu_set;
	uint16_t omtu;
	bool     imtu_set;
	uint16_t imtu;
	bool     conf_sent;
	bool     conf_rcvd;
	bool     connected;
	bool     listening;
	uint8_t  addr[BD_ADDR_LEN];
	int      omtu_neg;
	int      imtu_neg;
};

struct version {
	unsigned int major;
	unsigned int minor;
	unsigned int release;
	unsigned int build;
};

struct btt_msg_rsp_daemon_check {
	struct btt_message hdr;
	struct version     version;
};

enum btt_command {
	/* TODO: Sort and use explicit values - 0, 1, 2, etc. */
	BTT_STATUS_START = 1,
	BTT_RSP_OK,
	BTT_RSP_ERROR,
	BTT_RSP_ERROR_UNKNOWN_COMMAND,
	BTT_RSP_ERROR_NO_TEST_INTERFACE,
	BTT_RSP_ERROR_VERSION,
	BTT_STATUS_END,

	BTT_DAEMON_CMD_RSP_START = 100,
	BTT_CMD_DAEMON_CHECK,
	BTT_RSP_DAEMON_CHECK,
	BTT_CMD_DAEMON_STOP,
	BTT_DAEMON_END,
	BTT_DAEMON_CMD_RSP_END,

	BTT_ADAPTER_CMD_RSP_START =300,
	BTT_CMD_ADAPTER_UP,
	BTT_CMD_ADAPTER_DOWN,
	BTT_CMD_ADAPTER_NAME,
	BTT_CMD_ADAPTER_ADDRESS,
	BTT_CMD_ADAPTER_SCAN,
	BTT_CMD_ADAPTER_SCAN_MODE,
	BTT_CMD_ADAPTER_PAIR,
	BTT_CMD_ADAPTER_UNPAIR,
	BTT_ADAPTER_CMD_RSP_END,

	BTT_MISC_CMD_RSP_START = 900,
	BTT_RSP_AGENT_SSP_REPLY,
	BTT_RSP_AGENT_PIN_REPLY,
	BTT_MISC_CMD_RSP_END,

	BTT_GATT_CLIENT_CMD_RSP_START = 1100,
	BTT_CMD_GATT_CLIENT_REGISTER_CLIENT,
	BTT_CMD_GATT_CLIENT_UNREGISTER_CLIENT,
	BTT_CMD_GATT_CLIENT_SCAN,
	BTT_CMD_GATT_CLIENT_CONNECT,
	BTT_CMD_GATT_CLIENT_DISCONNECT,
	BTT_CMD_GATT_CLIENT_LISTEN,
	BTT_CMD_GATT_CLIENT_REFRESH,
	BTT_CMD_GATT_CLIENT_SEARCH_SERVICE,
	BTT_CMD_GATT_CLIENT_GET_INCLUDE_SERVICE,
	BTT_CMD_GATT_CLIENT_GET_CHARACTERISTIC,
	BTT_CMD_GATT_CLIENT_GET_DESCRIPTOR,
	BTT_CMD_GATT_CLIENT_READ_CHARACTERISTIC,
	BTT_CMD_GATT_CLIENT_WRITE_CHARACTERISTIC,
	BTT_CMD_GATT_CLIENT_READ_DESCRIPTOR,
	BTT_CMD_GATT_CLIENT_WRITE_DESCRIPTOR,
	BTT_CMD_GATT_CLIENT_EXECUTE_WRITE,
	BTT_CMD_GATT_CLIENT_REGISTER_FOR_NOTIFICATION,
	BTT_CMD_GATT_CLIENT_DEREGISTER_FOR_NOTIFICATION,
	BTT_CMD_GATT_CLIENT_READ_REMOTE_RSSI,
	BTT_CMD_GATT_CLIENT_GET_DEVICE_TYPE,
	BTT_CMD_GATT_CLIENT_SET_ADV_DATA,
	BTT_CMD_GATT_CLIENT_TEST_COMMAND,
	BTT_GATT_CLIENT_CMD_RSP_END,

	BTT_GATT_SERVER_CMD_RSP_START = 1300,
	BTT_GATT_SERVER_CMD_REGISTER_SERVER,
	BTT_GATT_SERVER_CMD_UNREGISTER_SERVER,
	BTT_GATT_SERVER_CMD_CONNECT,
	BTT_GATT_SERVER_CMD_DISCONNECT,
	BTT_GATT_SERVER_CMD_ADD_SERVICE,
	BTT_GATT_SERVER_CMD_ADD_INCLUDED_SERVICE,
	BTT_GATT_SERVER_CMD_ADD_CHARACTERISTIC,
	BTT_GATT_SERVER_CMD_ADD_DESCRIPTOR,
	BTT_GATT_SERVER_CMD_START_SERVICE,
	BTT_GATT_SERVER_CMD_STOP_SERVICE,
	BTT_GATT_SERVER_CMD_DELETE_SERVICE,
	BTT_GATT_SERVER_CMD_SEND_INDICATION,
	BTT_GATT_SERVER_CMD_SEND_RESPONSE,
	BTT_GATT_SERVER_CMD_RSP_END,

	BTT_COMMAND_END
};

enum btt_ext_command {
	BTT_EXT_COMMAND_START = 1,

	BTT_EXT_SDP_CMD,

	BTT_EXT_DEAMON_CMD,

	BTT_EXT_COMMAND_END

};

enum btt_ext_sdp_command {
	BTT_EXT_SDP_COMMAND_START = 1,

	BTT_EXT_SDP_DECODE_RECORDS_CMD,

	BTT_EXT_SDP_COMMAND_END
};

enum btt_ext_daemon_command {
	BTT_EXT_DAEMON_COMMAND_START = 1,

	BTT_EXT_DAEMON_STOP_CMD,

	BTT_EXT_DAEMON_COMMAND_END
};

/*The peer won't pay attention to the cmd,
   will only concern about the cmd_str.
   The cmd string should be followed this structure*/
struct ext_btt_message{
	int cmd;
	int sub_cmd;
	int data_len;
	char data[0];
};

struct ext_command_item {
	char const *cmd_str;
	char const *sub_cmd_str;
	int cmd;
	int sub_cmd;
};

static const struct ext_command_item ext_command_map[] = {
		{ "sdp", "decode_records", BTT_EXT_SDP_CMD, BTT_EXT_SDP_DECODE_RECORDS_CMD },
		{ "daemon", "stop", BTT_EXT_DEAMON_CMD, BTT_EXT_DAEMON_STOP_CMD }
};

#define TOTAL_EXT_CMDS_IN_MAP sizeof(ext_command_map)/sizeof(struct ext_command_item)

#ifndef WITHOUT_STACK
#include <sys/prctl.h>

#define LOG_TAG "btt"

#include <utils/Log.h>
#include <private/android_filesystem_config.h>
#else
#include <netinet/in.h>
#endif

struct btt_msg_cmd_adapter_scan_mode {
	struct btt_message hdr;

	unsigned int mode;
};

struct btt_msg_cmd_adapter_pair {
	struct btt_message hdr;

	uint8_t addr[BD_ADDR_LEN];
};

struct btt_msg_cmd_agent_ssp {
	struct btt_message hdr;

	unsigned int accept;
	uint8_t      addr[BD_ADDR_LEN];
	unsigned int passkey;
	int          variant;
};

struct btt_msg_cmd_agent_pin {
	struct btt_message hdr;

	uint8_t pin_code[PIN_CODE_MAX_LEN];
	uint8_t addr[BD_ADDR_LEN];
	uint8_t pin_len;
	uint8_t accept;
};

/* strings array for bt_status_t enum
 * if that enum change, this array also should */
static const char *bt_status_string[] = {
		"SUCCESS",
		"FAIL",
		"NOT READY",
		"NO MEMORY",
		"BUSY",
		"DONE",
		"UNSUPORTED",
		"INVALID PARAMETER",
		"UNHANDLED",
		"AUTHORISATION FAILURE",
		"REMOTE DEVICE DOWN"
};

extern struct btt_message *btt_send_command(struct btt_message *msg);
extern int get_hexlines_length(int i_arg, int argc, char **argv);
extern int hexlines_to_data(int i_arg, int argc, char **argv,
		unsigned char *data);
extern void print_bdaddr(uint8_t *source);

#endif
