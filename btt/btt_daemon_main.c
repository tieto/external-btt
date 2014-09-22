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
#include <signal.h>
#include <sys/capability.h>
#include <hardware/bt_gatt.h>

#include "btt_utils.h"

#include "btt_daemon_main.h"
#include "btt_daemon_adapter.h"
#include "btt_daemon_gatt_client.h"
#include "btt_daemon_gatt_server.h"
#include "btt_adapter.h"
#include "btt_gatt_client.h"

static btgatt_callbacks_t sGattCallbacks;
static pthread_t callback_thread;
static int socket_agent;
int socket_remote;

const bt_interface_t *bluetooth_if = NULL;
const btgatt_interface_t *gatt_if = NULL;
const btgatt_client_interface_t *gatt_client_if = NULL;
const btgatt_server_interface_t *gatt_server_if = NULL;

struct list_element *list = NULL;

static void run_daemon_help(int argc, char **argv);
static void run_daemon_start(int argc, char **argv) ;
static void run_daemon_stop(int argc, char **argv);
static void run_daemon_restart(int argc, char **argv);
static void run_daemon_status(int argc, char **argv);
static void run_daemon_generic(const struct command *commands,
		unsigned int number_of_commands,
		void (*help)(int argc, char **argv), int argc, char **argv);
static void btgatt_callbacks_init();

static struct command daemon_commands[] = {
		{"help",   "",            run_daemon_help},
		{"start",  "[nodetach]",  run_daemon_start},
		{"stop",   "",            run_daemon_stop},
		{"restart","[nodetach]",  run_daemon_restart},
		{"status", "",            run_daemon_status},
};

#define DAEMON_SUPPORTED_COMMANDS sizeof(daemon_commands)/sizeof(struct command)

void run_daemon(int argc, char **argv)
{
	run_daemon_generic(daemon_commands, DAEMON_SUPPORTED_COMMANDS,
			run_daemon_help, argc, argv);
}

static void run_daemon_help(int argc, char **argv)
{
	print_commands(daemon_commands, DAEMON_SUPPORTED_COMMANDS);
	exit(EXIT_SUCCESS);
}

void btt_daemon_check(void)
{
	struct btt_message msg;
	struct btt_msg_rsp_daemon_check *rsp;

	msg.command = BTT_CMD_DAEMON_CHECK;
	msg.length  = 0;

	rsp = (struct btt_msg_rsp_daemon_check *)btt_send_command(&msg);
	if (!rsp) {
		BTT_LOG_S("Error: daemon not run\n");
		exit(EXIT_FAILURE);
	}

	if (!(rsp->version.major   == VERSION_MAJOR &&
			rsp->version.minor   == VERSION_MINOR &&
			rsp->version.release == VERSION_RELEASE &&
			rsp->version.build   == VERSION_BUILD)) {
		BTT_LOG_S("Error: incompatible versions: client is: %u.%u.%u (%u), but daemon is: %u.%u.%u (%u)\n",
				VERSION_MAJOR,
				VERSION_MINOR,
				VERSION_RELEASE,
				VERSION_BUILD,
				rsp->version.major,
				rsp->version.minor,
				rsp->version.release,
				rsp->version.build);
		free(rsp);
		exit(EXIT_FAILURE);
	}

	free(rsp);
}

static void signal_int(int signum)
{
	BTT_LOG_S("Ending...\n");

	run_daemon_stop(0, NULL);
}

static int stop_listening_thread(struct btt_message *message)
{
	struct btt_message btt_msg;
	struct sockaddr_un server;
	int                server_socket;
	unsigned int       len;

	memset(&btt_msg, 0, sizeof(struct btt_message));
	errno = 0;

	if ((server_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, AGENT_SOCK_PATH);
	len = strlen(server.sun_path) + sizeof(server.sun_family);

	if (connect(server_socket, (struct sockaddr *)&server, len) == -1) {
		BTT_LOG_S("Can't connect - %s \n", strerror(errno));
		close(server_socket);
		return -1;
	}

	if (send(server_socket, (const char *)message,
			sizeof(struct btt_message) + message->length, 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
		close(server_socket);
		return -1;
	}

	len = recv(server_socket, &btt_msg, sizeof(struct btt_message), 0);

	close(server_socket);
	pthread_join(callback_thread, NULL);

	return 0;
}

static void *agent_socket_routine(void *arg)
{
	struct btt_message btt_message;
	struct sockaddr_un local;
	struct sockaddr    remote;
	socklen_t          len;
	int                socket_listening_server;

	errno = 0;

	if ((socket_listening_server = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return NULL;

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, AGENT_SOCK_PATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (bind(socket_listening_server, (struct sockaddr *)&local, len)) {
		BTT_LOG_E("DEEP SHIT %s\n", strerror(errno));
		close(socket_listening_server);
		pthread_exit(NULL);
	}

	if (listen(socket_listening_server, 5)) {
		BTT_LOG_E("HOLY SHIT\n");
		close(socket_listening_server);
		pthread_exit(NULL);
	}

	while (1) {
		socket_agent = accept(socket_listening_server, &remote, &len);

		len= recv(socket_agent, &btt_message,
				sizeof(struct btt_message), MSG_PEEK);

		if (len < (int) sizeof(struct btt_message))
			continue;

		switch (btt_message.command) {
		case BTT_CMD_DAEMON_STOP:
			btt_message.command = BTT_RSP_OK;
			btt_message.length = 0;

			if (send(socket_agent, (const char *)&btt_message,
					sizeof(struct btt_message), 0) == -1) {
				BTT_LOG_E("Failed to send response from listening thread, \n");
			}

			close(socket_agent);
			close(socket_listening_server);
			pthread_exit(NULL);
		case BTT_RSP_AGENT_PIN_REPLY: {
			struct btt_msg_cmd_agent_pin msg;

			recv(socket_agent, &msg, sizeof(msg), 0);

			bluetooth_if->pin_reply((bt_bdaddr_t const *)msg.addr,
					msg.accept, msg.pin_len,
					(bt_pin_code_t *)msg.pin_code);
			break;
		}
		case BTT_RSP_AGENT_SSP_REPLY: {
			struct btt_msg_cmd_agent_ssp msg;

			recv(socket_agent, &msg, sizeof(msg), 0);

			bluetooth_if->ssp_reply((bt_bdaddr_t const *)msg.addr,
					(bt_ssp_variant_t)msg.variant,
					msg.accept, msg.passkey);
			break;
		}
		default:
			break;
		}
	}

	return NULL;
}

#ifndef WITHOUT_STACK
/*
 * Be careful to close socket in the callback functions below.
 * Some of commands, like BTT_CMD_ADAPTER_UP, trigger calling
 * several callback fucntions in succession. You must make
 * sure that the socket is only be closed in the last callback
 * function which uses the socket to send message to client.
 */

static void btt_cb_adapter_state_changed(bt_state_t state)
{
	struct btt_cb_adapter_state btt_cb;

	BTT_LOG_I("Callback Adapter State Changed");

	btt_cb.hdr.type   = BTT_ADAPTER_STATE_CHANGED;
	btt_cb.hdr.length = sizeof(bool);

	if (state == BT_STATE_OFF)
		btt_cb.state = false;
	else
		btt_cb.state = true;

	turning_on_adapter = FALSE;

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_state), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
	close(socket_remote);
}

static void btt_cb_adapter_properties(bt_status_t status,
		int num_properties, bt_property_t *properties)
{
	int i = num_properties;

	while (i-- > 0) {
		switch (properties[i].type) {
		case BT_PROPERTY_BDNAME: {
			struct btt_cb_adapter_name btt_cb;

			BTT_LOG_I("Callback Adapter Name");

			btt_cb.hdr.type   = BTT_ADAPTER_NAME;
			btt_cb.hdr.length = properties[i].len;

			strncpy(btt_cb.name,
					(const char *)properties[i].val, properties[i].len);
			btt_cb.name[btt_cb.hdr.length + 1] = '\0';

			if (send(socket_remote, (const char *)&btt_cb,
					sizeof(struct btt_cb_adapter_name), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
			}
			if (turning_on_adapter == FALSE)
				close(socket_remote);
			break;
		}
		case BT_PROPERTY_BDADDR: {
			struct btt_cb_adapter_addr btt_cb;

			BTT_LOG_I("Callback Adapter Address");

			btt_cb.hdr.type   = BTT_ADAPTER_ADDRESS;
			btt_cb.hdr.length = properties[i].len;

			memcpy(btt_cb.bd_addr, properties[i].val, sizeof(bt_bdaddr_t));

			if (send(socket_remote, (const char *)&btt_cb,
					sizeof(struct btt_cb_adapter_addr), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
			}
			if (turning_on_adapter == FALSE)
				close(socket_remote);
			break;
		}
		case BT_PROPERTY_UUIDS:
		case BT_PROPERTY_CLASS_OF_DEVICE:
		case BT_PROPERTY_TYPE_OF_DEVICE:
		case BT_PROPERTY_SERVICE_RECORD:
			break;
		case BT_PROPERTY_ADAPTER_SCAN_MODE: {
			struct btt_cb_adapter_scan_mode_changed btt_cb;
			bt_scan_mode_t *scan_mode = (bt_scan_mode_t *)properties[i].val;

			BTT_LOG_I("Callback Adapter Scan Mode");

			btt_cb.hdr.type   = BTT_ADAPTER_SCAN_MODE_CHANGED;
			btt_cb.hdr.length = sizeof(unsigned int);

			switch (*scan_mode) {
			case BT_SCAN_MODE_NONE:
				btt_cb.mode = 0;
				break;
			case BT_SCAN_MODE_CONNECTABLE:
				btt_cb.mode = 1;
				break;
			case BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE:
				btt_cb.mode = 2;
				break;
			default:
				break;
			}

			if (send(socket_remote, (const char *)&btt_cb,
					sizeof(struct btt_cb_adapter_addr), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 3\n", __FUNCTION__);
			}
			if (turning_on_adapter == FALSE)
				close(socket_remote);
			break;
		}
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
		default :
			break;
		}
	}
}

static void btt_cb_remote_device_properties(bt_status_t status,
		bt_bdaddr_t *bd_addr, int num_properties,
		bt_property_t *properties)
{
	BTT_LOG_I("Callback Remote Device Properties");
}

static void btt_cb_device_found(int num_properties, bt_property_t *properties)
{
	int i = num_properties;
	struct btt_cb_adapter_device_found btt_cb;

	memset(&btt_cb, 0, sizeof(btt_cb));
	btt_cb.hdr.type   = BTT_ADAPTER_DEVICE_FOUND;
	btt_cb.hdr.length = sizeof(struct btt_cb_adapter_device_found) -
			sizeof(struct btt_cb_hdr);

	BTT_LOG_I("Callback Device Found Properties");

	while (i-- > 0) {
		switch (properties[i].type) {
		case BT_PROPERTY_BDNAME:
			strncpy(btt_cb.name, (const char *)properties[i].val,
					properties[i].len);
			btt_cb.name[properties[i].len] = '\0';
			break;
		case BT_PROPERTY_BDADDR:
			memcpy(btt_cb.bd_addr, properties[i].val, properties[i].len);
			break;
		case BT_PROPERTY_CLASS_OF_DEVICE:
		case BT_PROPERTY_TYPE_OF_DEVICE:
		case BT_PROPERTY_SERVICE_RECORD:
		default :
			break;
		}
	}

	BTT_LOG_E("%d\n", fcntl(socket_remote, F_GETFL));

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_device_found), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
	/* do NOT close(socket_remote) here,
	 * we will continue sending the found device info to client one by one
	 */
}

static void btt_cb_discovery_state_changed(bt_discovery_state_t state)
{
	struct btt_cb_adapter_discovery btt_cb;

	btt_cb.hdr.type   = BTT_ADAPTER_DISCOVERY;
	btt_cb.hdr.length = sizeof(bool);

	BTT_LOG_I("Callback Discovery State Changed");

	if (state == BT_DISCOVERY_STOPPED)
		btt_cb.state = false;
	else
		btt_cb.state = true;

	if (send(socket_remote, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_discovery), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}

	if (state == BT_DISCOVERY_STOPPED)
		close(socket_remote);
}

static void btt_cb_pin_request(bt_bdaddr_t *remote_bd_addr,
		bt_bdname_t *bd_name, uint32_t cod)
{
	struct btt_cb_adapter_pin_request btt_cb;

	BTT_LOG_I("Callback Pin Request");

	btt_cb.hdr.type   = BTT_ADAPTER_PIN_REQUEST;
	btt_cb.hdr.length = sizeof(struct btt_cb_adapter_pin_request) -
			sizeof(struct btt_cb_hdr);

	btt_cb.cod = cod;
	memcpy(btt_cb.bd_addr, remote_bd_addr->address, BD_ADDR_LEN);
	strcpy(btt_cb.name, (char *)bd_name->name);

	if (send(socket_agent, (const char *)&btt_cb,
			sizeof(struct btt_cb_adapter_pin_request), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}
}

static void btt_cb_ssp_request(bt_bdaddr_t *remote_bd_addr,
		bt_bdname_t *bd_name, uint32_t cod,
		bt_ssp_variant_t pairing_variant, uint32_t pass_key)
{
	struct btt_cb_adapter_ssp_request btt_cb;

	BTT_LOG_I("Callback SSP Request");

	btt_cb.hdr.type   = BTT_ADAPTER_SSP_REQUEST;
	btt_cb.hdr.length = sizeof(struct btt_cb_adapter_ssp_request) -
			sizeof(struct btt_message);
	btt_cb.cod     = cod;
	btt_cb.passkey = pass_key;

	memcpy(btt_cb.bd_addr, remote_bd_addr->address, BD_ADDR_LEN);

	strcpy(btt_cb.name, (char *)bd_name->name);

	btt_cb.variant = pairing_variant;

	if (TRUE == bonding_peer_dev) {
		if (send(socket_remote, (const char *)&btt_cb,
				sizeof(struct btt_cb_adapter_ssp_request), 0) == -1) {
			BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
		}
	} else {
		if (send(socket_agent, (const char *)&btt_cb,
				sizeof(struct btt_cb_adapter_ssp_request), 0) == -1) {
			BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
		}
	}
}

static void btt_cb_bond_state_changed(bt_status_t status,
		bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state)
{
	struct btt_cb_adapter_bond_state_changed btt_cb;

	BTT_LOG_I("Callback Bond State Changed");

	btt_cb.hdr.type = BTT_ADAPTER_BOND_STATE_CHANGED;
	btt_cb.status   = status;
	btt_cb.state    = state;
	memcpy(btt_cb.bd_addr, remote_bd_addr->address, BD_ADDR_LEN);

	if (TRUE == bonding_peer_dev) {
		if (send(socket_remote, (const char *)&btt_cb,
				sizeof(struct btt_cb_adapter_bond_state_changed), 0) == -1) {
			BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
		}
		if (BT_BOND_STATE_BONDED == state)
			bonding_peer_dev = FALSE;
	} else {
		if (send(socket_agent, (const char *)&btt_cb,
				sizeof(struct btt_cb_adapter_bond_state_changed), 0) == -1) {
			BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
		}
	}
}

static void btt_cb_acl_state_changed(bt_status_t status,
		bt_bdaddr_t *remote_bd_addr, bt_acl_state_t state)
{
	BTT_LOG_I("Callback ACL State Changed");
}

static void btt_cb_thread_event(bt_cb_thread_evt event)
{
	BTT_LOG_I("Callback Thread Event");
}

static void btt_cb_dut_mode_recv(uint16_t opcode, uint8_t *buf, uint8_t len)
{
	BTT_LOG_I("Callback Dut Mode Recv");
}

static void btt_cb_le_test_mode(bt_status_t status, uint16_t num_packets)
{
	BTT_LOG_I("Callback LE test mode");
}

static bt_callbacks_t sBluetoothCallbacks = {
		sizeof(sBluetoothCallbacks),
		btt_cb_adapter_state_changed,
		btt_cb_adapter_properties,
		btt_cb_remote_device_properties,
		btt_cb_device_found,
		btt_cb_discovery_state_changed,
		btt_cb_pin_request,
		btt_cb_ssp_request,
		btt_cb_bond_state_changed,
		btt_cb_acl_state_changed,
		btt_cb_thread_event,
		btt_cb_dut_mode_recv,
		btt_cb_le_test_mode
};

static void config_permissions(void)
{
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct cap;
	static gid_t groups[] = {
			AID_NET_BT,
			AID_INET,
			AID_NET_BT_ADMIN,
			AID_SYSTEM,
			AID_MISC,
			AID_SDCARD_RW,
			AID_NET_ADMIN,
			AID_VPN
	};

	BTT_LOG_D("Previous Info: pid %d, uid %d gid %d",
			getpid(), getuid(), getgid());

	header.pid = 0;

	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

	setuid(AID_BLUETOOTH);
	setgid(AID_BLUETOOTH);

	header.version = _LINUX_CAPABILITY_VERSION;

	cap.effective = cap.permitted = cap.inheritable =
			1 << CAP_NET_RAW |
			1 << CAP_NET_ADMIN |
			1 << CAP_NET_BIND_SERVICE |
			1 << CAP_SYS_RAWIO |
			1 << CAP_SYS_NICE |
			1 << CAP_SETGID;

	capset(&header, &cap);
	setgroups(sizeof(groups)/sizeof(groups[0]), groups);

	BTT_LOG_D("Info : pid %d, uid %d gid %d", getpid(), getuid(), getgid());
}
#endif

static int start_bluedroid_hal(void)
{
#ifndef WITHOUT_STACK
	int          err;
	int          status;
	hw_module_t *module;
	hw_device_t *device;

	config_permissions();

	err = hw_get_module(BT_HARDWARE_MODULE_ID, (hw_module_t const**)&module);
	if (err == 0) {
		err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
		if (err == 0) {
			bluetooth_device_t *bt_device;

			bt_device    = (bluetooth_device_t *)device;
			bluetooth_if = bt_device->get_bluetooth_interface();
		}
	}

	BTT_LOG_I("HAL library loaded (%s)", strerror(err));
	status = bluetooth_if->init(&sBluetoothCallbacks);
	gatt_if = bluetooth_if->get_profile_interface(BT_PROFILE_GATT_ID);

	if(gatt_if)
	{
		btgatt_callbacks_init();
		gatt_if->init(&sGattCallbacks);
		gatt_client_if = gatt_if->client;
		gatt_server_if = gatt_if->server;
	}

	BTT_LOG_I("HAL Status %i", status);
#endif
	return 0;
}

static void run_daemon_generic(const struct command *commands,
		unsigned int commands_num,
		void (*help)(int argc, char **argv), int argc, char **argv)
{
	unsigned int i_command;

	if (argc <= 1) {
		help(0, NULL);
	}

	for (i_command = 0; i_command < commands_num; i_command += 1) {
		if (strcmp(argv[1], commands[i_command].command) == 0) {
			if (!commands[i_command].run)
				BTT_LOG_S("Not implemented yet");
			else
				commands[i_command].run(argc - 1, argv + 1);
			break;
		}
	}
	if (i_command >= commands_num) {
		BTT_LOG_S("Unknown \"%s\" command: <%s>\n", argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}
}

void run_daemon_start(int argc, char **argv)
{
	int                 pid;
	int                 sid;
	int                 socket_server;
	struct sockaddr_un  local;
	struct sockaddr     remote;
	socklen_t           len;
	struct btt_message  btt_msg;
	struct btt_message *btt_rsp;
	int                 length;
	bool                nodetach = FALSE;

	if (argc > 2) {
		BTT_LOG_S("Error: Too many arguments\n");
		return;
	}

	if (argc == 2 && strcmp("nodetach", argv[1]) == 0) {
		nodetach = TRUE;
	} else if (argc == 2) {
		BTT_LOG_S("Error: Unknown argument <%s>\n", argv[1]);
		return;
	}

	btt_msg.command = BTT_CMD_DAEMON_CHECK;
	btt_msg.length  = 0;

	btt_rsp = btt_send_command(&btt_msg);
	if (btt_rsp) {
		BTT_LOG_S("Error: daemon seems to be run\n");
		free(btt_rsp);
		exit(EXIT_FAILURE);
	}

	BTT_LOG_S("Starting BTT daemon...\n");

	if (!nodetach) {
		pid = fork();
		if (pid < 0) {
			BTT_LOG_E("Starting BTT daemon: FAIL (1)\n");
			exit(EXIT_FAILURE);
		}

		if (pid > 0)
			exit(EXIT_SUCCESS);

		sid = setsid();
		if (sid < 0) {
			BTT_LOG_E("Starting BTT daemon: FAIL (2)\n");
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGINT, signal_int);

	umask(0);

	if ((chdir("/")) < 0) {
		BTT_LOG_E("Starting BTT daemon: FAIL (3)\n");
		exit(EXIT_FAILURE);
	}

	if (!nodetach) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/*start callback socket before, to receive hal callbacks*/
	pthread_create(&callback_thread, NULL, agent_socket_routine, NULL);

	socket_server = socket(AF_UNIX , SOCK_STREAM , 0);

	/* we won't catch SIGPIPE errors, we just ignore them
	 * so user can close socket every time
	 */
	signal(SIGPIPE, SIG_IGN);

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, SOCK_PATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (bind(socket_server, (struct sockaddr *)&local, len) == -1) {
		BTT_LOG_E("Starting BTT daemon: FAIL (4)\n");
		close(socket_server);
		exit(EXIT_FAILURE);
	}

	if (listen(socket_server, 5) == -1) {
		BTT_LOG_E("Starting BTT daemon: FAIL (5)\n");
		close(socket_server);
		exit(EXIT_FAILURE);
	}

	len = sizeof(struct sockaddr_un);

	if (start_bluedroid_hal()) {
		BTT_LOG_E("Starting BTT daemon: FAIL (6)\n");
		exit(EXIT_FAILURE);
	}

	BTT_LOG_I("Daemon successfully start at pid=%u\n", getpid());

	while (1) {
		BTT_LOG_D("Waiting for btt_message\n");
		socket_remote = accept(socket_server, &remote, &len);
		BTT_LOG_D("Receving btt_message\n");
		length        = recv(socket_remote, &btt_msg,
				sizeof(struct btt_message), MSG_PEEK);
		if (length < (int) sizeof(struct btt_message)) {
			BTT_LOG_E("Received invalid btt_message\n");
			close(socket_remote);
			continue;
		}

		BTT_LOG_D("RECEIVE command=%u length=%u\n",
				btt_msg.command, btt_msg.length);

		switch (btt_msg.command) {
		case BTT_CMD_DAEMON_CHECK: {
			struct btt_msg_rsp_daemon_check btt_rsp;

			FILL_HDR(btt_rsp, BTT_RSP_DAEMON_CHECK);

			btt_rsp.version.major   = VERSION_MAJOR;
			btt_rsp.version.minor   = VERSION_MINOR;
			btt_rsp.version.release = VERSION_RELEASE;
			btt_rsp.version.build   = VERSION_BUILD;

			recv(socket_remote, NULL, 0, 0);
			if (send(socket_remote, (const char *)&btt_rsp,
					sizeof(struct btt_msg_rsp_daemon_check), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
			}
			close(socket_remote);
			continue;
		}
		case BTT_CMD_DAEMON_STOP:
			if (stop_listening_thread(&btt_msg)) {
				BTT_LOG_E("error closing listening thread");
			}

			if (send(socket_remote, (const char *)&btt_msg,
					sizeof(struct btt_message), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
			}

			close(socket_remote);
			close(socket_server);
			exit(EXIT_SUCCESS);
		default:
			break;
		}

		/*start to handle different command here.*/
		if (btt_msg.command > BTT_ADAPTER_CMD_RSP_START &&
				btt_msg.command < BTT_ADAPTER_CMD_RSP_END) {
			handle_adapter_cmd(&btt_msg, socket_remote);
		} else if (btt_msg.command > BTT_GATT_CLIENT_CMD_RSP_START &&
				btt_msg.command < BTT_GATT_CLIENT_CMD_RSP_END) {
			list = list_clear(list, free);
			handle_gatt_client_cmd(&btt_msg, socket_remote);
		} else if (btt_msg.command > BTT_GATT_SERVER_CMD_RSP_START &&
				btt_msg.command < BTT_GATT_SERVER_CMD_RSP_END) {
			handle_gatt_server_cmd(&btt_msg, socket_remote);
		} else {
			BTT_LOG_W("Unknown command=%u with length=%u\n",
					btt_msg.command, btt_msg.length);
			btt_msg.command = BTT_RSP_ERROR_UNKNOWN_COMMAND;
			btt_msg.length  = 0;
			if (send(socket_remote, (const char *)&btt_msg,
					sizeof(struct btt_message), 0) == -1) {
				BTT_LOG_E("%s:System Socket Error 4\n", __FUNCTION__);
			}
			close(socket_remote);
			continue;
		}

		if (length > 0)
			recv(socket_remote, NULL, 0, 0);

		/*
		 * Do NOT close socket here.
		 * handle_l2cap_cmd(), handle_adapter_cmd() and handle_misc_cmd()
		 * call asynchronous methods to handle their commands. Their
		 * callback functions will use the socket and close it.
		 */
	}
}

void run_daemon_stop(int argc, char **argv)
{
	struct btt_message  btt_msg;
	struct btt_message *msg_rsp;
	struct ext_btt_message ext_cmd;

	if (argc > 1) {
		BTT_LOG_S("Error: Too many arguments\n");
		return;
	}

	btt_msg.command = BTT_CMD_DAEMON_STOP;
	btt_msg.length  = 0;
	msg_rsp = btt_send_command(&btt_msg);

	BTT_LOG_S("Status: %s\n", msg_rsp ? "stopped" : "error");

	ext_cmd.cmd     = BTT_EXT_DEAMON_CMD;
	ext_cmd.sub_cmd = BTT_EXT_DAEMON_STOP_CMD;
	btt_send_ext_command(&ext_cmd, NULL, 0);
	free(msg_rsp);

	/*free list*/
	list_clear(list, free);
}

void run_daemon_status(int argc, char **argv)
{
	int                server_socket;
	int                len;
	struct sockaddr_un server;
	struct btt_message btt_message;
	time_t             start_time;
	time_t             end_time;

	if (argc > 1) {
		BTT_LOG_S("Error: Too many arguments\n");
		return;
	}

	BTT_LOG_S("Status: ");

	if ((server_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		BTT_LOG_S("system socket error\n");
		exit(EXIT_FAILURE);
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCK_PATH);
	len = strlen(server.sun_path) + sizeof(server.sun_family);
	if (connect(server_socket, (struct sockaddr *)&server, len) == -1) {
		BTT_LOG_S("not run\n");
		close(server_socket);
		exit(EXIT_SUCCESS);
	}

	btt_message.command = BTT_CMD_DAEMON_CHECK;
	btt_message.length  = 0;

	if (send(server_socket, (const char *)&btt_message,
			sizeof(btt_message) + btt_message.length, 0) == -1) {
		BTT_LOG_S("run, but system socket error\n");
		close(server_socket);
		exit(EXIT_SUCCESS);
	}

	start_time = time(NULL);
	end_time   = 0;
	do {
		len = recv(server_socket, (char *) &btt_message,
				sizeof(btt_message), MSG_DONTWAIT);
		if (len== sizeof(btt_message))
			break;

		end_time = time(NULL);
	} while (end_time - start_time < 1);

	if (end_time - start_time >= 1) {
		BTT_LOG_S("run, but not responsible\n");
		exit(EXIT_SUCCESS);
	}

	close(server_socket);
	BTT_LOG_S("ok\n");
	exit(EXIT_SUCCESS);
}

void run_daemon_restart(int argc, char **argv)
{
	run_daemon_stop(argc, argv);
	run_daemon_start(argc, argv);
}

/*initialization sGattCallbacks structure*/
/*must be call before using this structure*/
static void btgatt_callbacks_init()
{
	sGattCallbacks.size = sizeof(sGattCallbacks);
	sGattCallbacks.client = getGattClientCallbacks();
	sGattCallbacks.server = getGattServerCallbacks();
}
