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
#include <sys/wait.h>
#include <hardware/bt_gatt.h>

#include "btt_utils.h"

#include "btt_daemon_main.h"
#include "btt_daemon_adapter.h"
#include "btt_daemon_gatt_client.h"
#include "btt_daemon_gatt_server.h"
#include "btt_adapter.h"
#include "btt_gatt_client.h"

static btgatt_callbacks_t sGattCallbacks;
int socket_remote;
extern int app_socket;

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
static void run_daemon_generic_extended(const struct extended_command *commands,
		unsigned int number_of_commands,
		void (*help)(int argc, char **argv), int argc, char **argv);
static void btgatt_callbacks_init();

static struct extended_command daemon_commands[] = {
		{{"help",   "",            run_daemon_help}, 1, 1},
		{{"start",  "[nodetach]",  run_daemon_start}, 1, 2},
		{{"stop",   "",            run_daemon_stop}, 1, 1},
		{{"restart","[nodetach]",  run_daemon_restart}, 1, 2}
};

#define DAEMON_SUPPORTED_COMMANDS sizeof(daemon_commands)/sizeof(struct extended_command)
#define OK "OK"
#define ER "ER"

void run_daemon(int argc, char **argv)
{
	run_daemon_generic_extended(daemon_commands, DAEMON_SUPPORTED_COMMANDS,
			run_daemon_help, argc, argv);
}

static void run_daemon_help(int argc, char **argv)
{
	print_commands_extended(daemon_commands, DAEMON_SUPPORTED_COMMANDS);
}

static void signal_int(int signum)
{
	BTT_LOG_S("Ending...\n");

	run_daemon_stop(0, NULL);
}

#ifndef WITHOUT_STACK

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
	status = bluetooth_if->init(getBluetoothCallbacks());
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

static void run_daemon_generic_extended(const struct extended_command *commands,
		unsigned int commands_num,
		void (*help)(int argc, char **argv), int argc, char **argv)
{
	unsigned int i_command;

	if (argc <= 1) {
		help(0, NULL);
		return;
	}

	for (i_command = 0; i_command < commands_num; i_command += 1) {
		if (strcmp(argv[1], commands[i_command].comm.command) == 0) {
			if (!commands[i_command].comm.run) {
				BTT_LOG_S("Not implemented yet");
			} else {
				if (argc - 1 > commands[i_command].argc_max) {
					BTT_LOG_S("Error: Too many arguments\n");
					return;
				} else if (argc - 1 < commands[i_command].argc_min) {
					BTT_LOG_S("Error: Too few arguments\n");
					return;
				}

				commands[i_command].comm.run(argc - 1, argv + 1);
			}

			break;
		}
	}
	if (i_command >= commands_num) {
		BTT_LOG_S("Unknown \"%s\" command: <%s>\n", argv[0], argv[1]);
		return;
	}
}

void run_daemon_start(int argc, char **argv)
{
	int pid;
	int sid;
	int socket_server;
	struct sockaddr_un local;
	struct sockaddr remote;
	socklen_t len;
	struct btt_message btt_msg;
	struct btt_message *btt_rsp;
	int length;
	bool nodetach = FALSE;
	char buff[256];
	int fd[2];
	char temp[3];

	if (argc == 2 && strcmp("nodetach", argv[1]) == 0) {
		nodetach = TRUE;
	} else if (argc == 2) {
		BTT_LOG_S("Error: Unknown argument <%s>\n", argv[1]);
		return;
	}

	btt_msg.command = BTT_CMD_DAEMON_CHECK;
	btt_msg.length  = 0;

	if (!nodetach) {

		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd) == -1) {
			BTT_LOG_S("Error: Can't pair diagnostic socket.\n");
					return;
		}

		pid = fork();

		if (pid < 0) {
			BTT_LOG_E("Starting BTT daemon: FAIL (1)\n");
			return;
		}

		if (pid > 0) {
			int stat;

			close(fd[0]);
			recv(fd[1], temp, 3, MSG_WAITALL);

			if (strncmp(temp, OK, 2)) {
				wait(&stat);
				BTT_LOG_S("Daemon start status: error.\n");
			} else {
				BTT_LOG_S("Daemon start status: success.\n");
			}

			close(fd[1]);
			errno = 0;
			return;
		}

		close(fd[1]);
		sid = setsid();

		if (sid < 0) {
			BTT_LOG_E("Starting BTT daemon: FAIL (2)\n");
			send(fd[0], ER, 3, 0);
			close(fd[0]);
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGINT, signal_int);

	umask(0);

	if ((chdir("/")) < 0) {
		BTT_LOG_E("Starting BTT daemon: FAIL (3)\n");
		send(fd[0], ER, 3, 0);
		close(fd[0]);
		exit(EXIT_FAILURE);
	}

	if (!nodetach) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	socket_server = socket(AF_UNIX , SOCK_STREAM , 0);

	/* we won't catch SIGPIPE errors, we just ignore them
	 * so user can close socket every time
	 */
	signal(SIGPIPE, SIG_IGN);

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, SOCK_PATH);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (bind(socket_server, (struct sockaddr *)&local, len) == -1) {
		BTT_LOG_E("Starting BTT daemon: FAIL (4)\n");
		close(socket_server);

		if (!nodetach) {
			send(fd[0], ER, 3, 0);
			close(fd[0]);
		}

		exit(EXIT_FAILURE);
	}

	if (listen(socket_server, 1) == -1) {
		BTT_LOG_E("Starting BTT daemon: FAIL (5)\n");
		close(socket_server);

		if (!nodetach) {
			send(fd[0], ER, 3, 0);
			close(fd[0]);
		}

		exit(EXIT_FAILURE);
	}

	len = sizeof(struct sockaddr_un);

	if (start_bluedroid_hal()) {
		BTT_LOG_E("Starting BTT daemon: FAIL (6)\n");

		if (!nodetach) {
			send(fd[0], ER, 3, 0);
			close(fd[0]);
		}

		exit(EXIT_FAILURE);
	}

	BTT_LOG_I("Daemon successfully start at pid=%u\n", getpid());


	if (!nodetach) {
		send(fd[0], OK, 3, 0);
		close(fd[0]);
	}

	while (1) {
		errno = 0;
		BTT_LOG_D("Waiting for btt_messages\n");
		socket_remote = accept(socket_server, &remote, &len);

		while (1) {
			BTT_LOG_D("Receving btt_message\n");

			length = (int) recv(socket_remote, &btt_msg,
					sizeof(struct btt_message), MSG_PEEK);
			send(socket_remote, NULL, 0, MSG_NOSIGNAL);

			if (errno == EPIPE)
				break;

			if (length <= 0) {
				BTT_LOG_E("Received invalid btt_message\n");
				break;
			}

			BTT_LOG_D("RECEIVE command=%u length=%i\n",
					btt_msg.command, length);

			if (btt_msg.command == BTT_CMD_DAEMON_STOP) {
				close(socket_remote);
				close(socket_server);
				exit(EXIT_SUCCESS);
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
				continue;
			}
		}
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
	struct btt_message btt_msg;
	int status = -1;

	btt_msg.command = BTT_CMD_DAEMON_STOP;
	btt_msg.length = 0;

	if (send(app_socket, (const char *)&btt_msg,
			sizeof(struct btt_message), 0) == -1) {
		BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
	}

	/*free list*/
	list_clear(list, free);
	wait(&status);
	unlink(SOCK_PATH);
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
