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

#include "btt.h"
#include "btt_adapter.h"
#include "btt_l2cap.h"
#include "btt_utils.h"

enum l2cap_reguest_type_t {
    BTT_REQ_CONNECT_AND_BE_SILENT,
    BTT_REQ_CONNECT_AND_DUMP,
    BTT_REQ_DISCONNECT,
    BTT_REQ_WRITE,
    BTT_REQ_LISTEN,
    BTT_REQ_PING,
};

struct btt_req_connect {
    uint8_t addr[BD_ADDR_LEN];
    int psm;
    int imtu;
    int omtu;
};

struct btt_req_ping {
    uint8_t addr[BD_ADDR_LEN];
};

struct btt_req_listen {
    int psm;
    int imtu;
    int omtu;
};

struct btt_req_write {
    int cid;
    int len;
    char *buffer;
};

static void run_l2cap_help(int argc, char **argv);
static void run_l2cap_connect(int argc, char **argv);
static void run_l2cap_connect_dump(int argc, char **argv);
static void run_l2cap_disconnect(int argc, char **argv);
static void run_l2cap_write(int argc, char **argv);
static void run_l2cap_listen(int argc, char **argv);
static void run_l2cap_ping(int argc, char **argv);

static const struct command l2cap_commands[] = {
    { "help",                   "",                                           run_l2cap_help             },
    { "connect",                "<BD_ADDR> <PSM> [imtu NUMBER [omtu NUMBER] | omtu NUMBER]", run_l2cap_connect          },
    { "connect_dump",           "<BD_ADDR> <PSM> [imtu NUMBER [omtu NUMBER] | omtu NUMBER]", run_l2cap_connect_dump     },
    { "disconnect",             "",                                           run_l2cap_disconnect       },
    { "write",                  "<TEXT>",                                     run_l2cap_write            },
    { "receive",                "NOT IMPLEMENTED YET <HANDLE> <print | print_all | check [HEXLINES...] | wait [HEXLINES...]>", NULL },
    { "listen",                 "<PSM> [imtu NUMBER [omtu NUMBER] | omtu NUMBER]",           run_l2cap_listen           },
    { "ping",                   "<BD_ADDR> [count NUMBER [delay NUMBER] | delay NUMBER]",    run_l2cap_ping             }
};

const struct command *btt_l2cap_commands = l2cap_commands;

#define L2CAP_SUPPORTED_COMMANDS sizeof(l2cap_commands)/sizeof(struct command)

#define L2CAP_CONN_ERR_LEN 32
static const char l2cap_conn_err[][L2CAP_CONN_ERR_LEN] = {
    {"L2CAP_CONN_PENDING"},           // 0  error:1
    {"L2CAP_CONN_NO_PSM"},            // 1  error:2
    {"L2CAP_CONN_SECURITY_BLOCK"},    // 2  error:3
    {"L2CAP_CONN_NO_RESOURCES"},      // 3  error:4
    {"L2CAP_CONN_BAD_CTLR_ID"},       // 4  error:5
    {"L2CAP_CONN_TIMEOUT"},           // 5  error:0xEEEE
    {"L2CAP_CONN_AMP_FAILED"},        // 6  error:254
    {"L2CAP_CONN_NO_LINK"},           // 7  error:255
    {"L2CAP_CONN_CANCEL"},            // 8  error:256
    {"L2CAP_GREAT_SUCCESS"},          // 9  error:0
    {"L2CAP_WTF"}                     // 10 error:others
};

void run_l2cap(int argc, char **argv) {
    run_generic(btt_l2cap_commands, L2CAP_SUPPORTED_COMMANDS,
                run_l2cap_help, argc, argv);
}

void run_l2cap_help(int argc, char **argv) {
    print_commands(btt_l2cap_commands, L2CAP_SUPPORTED_COMMANDS);
    exit(EXIT_SUCCESS);
}

static const char *get_connect_err(int err)
{
    if (err == 1)
        return l2cap_conn_err[0];
    else if (err == 2)
        return l2cap_conn_err[1];
    else if (err == 3)
        return l2cap_conn_err[2];
    else if (err == 4)
        return l2cap_conn_err[3];
    else if (err == 5)
        return l2cap_conn_err[4];
    else if (err == 0xEEEE)
        return l2cap_conn_err[5];
    else if (err == 254)
        return l2cap_conn_err[6];
    else if (err == 255)
        return l2cap_conn_err[7];
    else if (err == 256)
        return l2cap_conn_err[8];
    else if (err == 0)
        return l2cap_conn_err[9];
    else
        return l2cap_conn_err[10];
}

static void process_request(enum l2cap_reguest_type_t type, void *data)
{
    int server_sock, conn_state = 0;
    unsigned int len;
    struct timeval tv;
    struct sockaddr_un server;
    struct btt_l2cap_cb_hdr btt_cb;
    char *buffer;

    errno = 0;

    if ((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        return;

    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, SOCK_PATH);

    len = strlen(server.sun_path) + sizeof(server.sun_family);

    if (connect(server_sock, (struct sockaddr *)&server, len) == -1) {
        close(server_sock);
        return;
    }

    switch (type) {
    case BTT_REQ_CONNECT_AND_DUMP:
    case BTT_REQ_CONNECT_AND_BE_SILENT: {
        struct btt_msg_cmd_l2cap_connect cmd_conn;
        struct btt_req_connect *req_conn;

        tv.tv_sec  = 25;
        tv.tv_usec = 0;
        setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&tv, sizeof(struct timeval));

        req_conn = (struct btt_req_connect *)data;
        cmd_conn.hdr.command = BTT_L2CAP_CONNECT;
        cmd_conn.hdr.length  = sizeof(cmd_conn) - sizeof(struct btt_message);
        memcpy(cmd_conn.addr, req_conn->addr, sizeof(req_conn->addr));
        cmd_conn.imtu = req_conn->imtu;
        cmd_conn.omtu = req_conn->omtu;
        cmd_conn.psm  = req_conn->psm;

        if (send(server_sock, (const char *)&cmd_conn,
                 sizeof(struct btt_msg_cmd_l2cap_connect), 0) == -1) {
            close(server_sock);
            return;
        }
        break;
    }
    case BTT_REQ_DISCONNECT: {
        int cid;
        struct btt_msg_cmd_l2cap_disconnect cmd_disc;

        tv.tv_sec  = 5;
        tv.tv_usec = 0;
        setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO,
                   (char *)&tv, sizeof(struct timeval));

        cid = *(int *)data;
        cmd_disc.hdr.command = BTT_L2CAP_DISCONNECT;
        cmd_disc.hdr.length  = sizeof(cmd_disc) - sizeof(struct btt_message);
        cmd_disc.cid = cid;

        if (send(server_sock, (const char *)&cmd_disc,
                 sizeof(struct btt_msg_cmd_l2cap_disconnect), 0) == -1) {
            close(server_sock);
            return;
        }
        break;
    }
    case BTT_REQ_WRITE: {
        struct btt_msg_cmd_l2cap_write cmd_write;
        struct btt_req_write *req_write;

        tv.tv_sec  = 5;
        tv.tv_usec = 0;
        setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, 
                   (char *)&tv, sizeof(struct timeval));

        req_write = (struct btt_req_write *)data;
        cmd_write.hdr.command = BTT_L2CAP_WRITE;
        cmd_write.hdr.length  = req_write->len;
        cmd_write.cid = 0; /*daemon holds session cid*/

        if (send(server_sock, (const char *)&cmd_write,
                                  sizeof(cmd_write), 0) == -1) {
            close(server_sock);
            return;
        }

        if (req_write->len != 0) {
            if (send(server_sock, req_write->buffer, req_write->len, 0) == -1) {
                close(server_sock);
                return;
            }
        }
        break;
    }
    case BTT_REQ_LISTEN: {
        struct btt_msg_cmd_l2cap_listen cmd_listen;
        struct btt_req_listen *req_listen;

        req_listen = (struct btt_req_listen *)data;
        cmd_listen.hdr.command = BTT_L2CAP_LISTEN;
        cmd_listen.hdr.length  = sizeof(cmd_listen) - sizeof(struct btt_message);
        cmd_listen.psm  = req_listen->psm;
        cmd_listen.imtu = req_listen->imtu;
        cmd_listen.omtu = req_listen->omtu;

        if (send(server_sock, (const char *)&cmd_listen,
                                  sizeof(cmd_listen), 0) == -1) {
            close(server_sock);
            return;
        }
        break;
    }
    case BTT_REQ_PING: {
        struct btt_msg_cmd_l2cap_ping cmd_ping;
        struct btt_req_ping *req_ping;

        req_ping = (struct btt_req_ping *)data;
        cmd_ping.hdr.command = BTT_L2CAP_PING;
        cmd_ping.hdr.length  = sizeof(struct btt_msg_cmd_l2cap_ping) -
                               sizeof(struct btt_message);
        memcpy(cmd_ping.addr, req_ping->addr, sizeof(req_ping->addr));

        if (send(server_sock, (const char *)&cmd_ping,
                 sizeof(struct btt_msg_cmd_l2cap_ping), 0) == -1) {
            close(server_sock);
            return;
        }
        break;
    }
    default:
        break;
    }

    len = 0;

    while (1) {
        len = recv(server_sock, &btt_cb, sizeof(btt_cb), MSG_PEEK);

        if (len == 0 || errno) {
            BTT_LOG_S("Timeout\n");
            close(server_sock);
            return;
        }

        switch (btt_cb.type) {
        case BTT_L2CAP_CONNECTED: {
            struct btt_l2cap_cb_connected cb_cnt;

            len = recv(server_sock, &cb_cnt, sizeof(cb_cnt), 0);
            if (type == BTT_REQ_CONNECT_AND_BE_SILENT) {
                if (!cb_cnt.result) {
                    BTT_LOG_S("Connecting, cid is %d...\n", cb_cnt.cid);
                } else {
                  BTT_LOG_S("Connect failed, %s\n",
                            get_connect_err(cb_cnt.result));
                    close(server_sock);
                    return;
                }
            }
            conn_state |= CONNECTING_MASK;
            break;
        }
        case BTT_L2CAP_CONFIG: {
            struct btt_l2cap_cb_config cb_config;

            len = recv(server_sock, &cb_config, sizeof(cb_config), 0);
            if (cb_config.direction == 1)
                conn_state |= CONF_SENT_MASK;
            else
                conn_state |= CONF_RCVD_MASK;

            if (conn_state == CONNECTED_MASK) {
                BTT_LOG_S("Connected\n");
            }

            if (type == BTT_REQ_CONNECT_AND_BE_SILENT) {
                if (conn_state == CONNECTED_MASK) {
                    BTT_LOG_S("?????\n");
                    close(server_sock);
                    return;
                }
            }
            break;
        }
        case BTT_L2CAP_DISCONNECTED: {
            struct btt_l2cap_cb_disconnected cb_disc;

            len = recv(server_sock, &cb_disc, sizeof(cb_disc), 0);
            if (!cb_disc.result) {
                BTT_LOG_S("Disconnected\n");
            } else {
                BTT_LOG_S("Disconnected with status %d\n", cb_disc.result);
            }
            close(server_sock);
            return;
        }
        case BTT_L2CAP_TX_COMPLETE: {
            struct btt_l2cap_cb_tx_complete cb_tx_cmpl;

            len = recv(server_sock, &cb_tx_cmpl, sizeof(cb_tx_cmpl), 0);
            if (type == BTT_REQ_WRITE) {
                BTT_LOG_S("wrote\n");
                close(server_sock);
                return;
            }
            break;
        }
        case BTT_L2CAP_CONN_IND: {
            struct btt_l2cap_cb_conn_ind cb_conn_ind;

            len = recv(server_sock, &cb_conn_ind, sizeof(cb_conn_ind), 0);
            if (type == BTT_REQ_LISTEN) {
                BTT_LOG_S("Accepted connection from: ");
                print_bdaddr(cb_conn_ind.addr);
                BTT_LOG_S("\n");
            }
            break;
        }
        case BTT_L2CAP_RECV_DATA: {
            int line;
            unsigned int i;

            len = recv(server_sock, &btt_cb, sizeof(btt_cb), 0);
            BTT_LOG_S("Received data len:%d\n", btt_cb.length);

            buffer = malloc(btt_cb.length);
            if (NULL == buffer)
                break;

            len = recv(server_sock, &buffer, btt_cb.length, 0);

            line = 0;
            for (i = 0; i < btt_cb.length; i++) {
                if (!(i%16) && i != 0) {
                    BTT_LOG_S("\n%04d\t %02X", line++, buffer[i]);
                } else if (!(i%8)&& i != 0) {
                    BTT_LOG_S("  %02X", buffer[i]);
                } else if (i == 0) {
                    BTT_LOG_S("%04d \t %02X", line++ ,buffer[i]);
                } else {
                    BTT_LOG_S(" %02X", buffer[i]);
                }
            }
            BTT_LOG_S("\n");
            free(buffer);
            break;
        }
        case BTT_L2CAP_PING_RSP: {
            struct btt_l2cap_cb_ping_rsp cb_ping_rsp;

            len = recv(server_sock, &cb_ping_rsp, sizeof(cb_ping_rsp), 0);
            if (type == BTT_REQ_PING) {
                BTT_LOG_S("PING_RSP with result %d\n", cb_ping_rsp.result);
                close(server_sock);
                return;
            }
            break;
        }
        default:
            len = recv(server_sock, &btt_cb, sizeof(btt_cb), 0);
            buffer = malloc(btt_cb.length);
            if (NULL == buffer)
                break;
            len = recv(server_sock, &buffer, btt_cb.length, 0);
            free(buffer);
            break;
        }
    }
}

static void l2cap_connect(int argc, char **argv,
                          enum l2cap_reguest_type_t request)
{
    struct btt_req_connect req;

    if (argc < 3 || argc == 4 || argc == 6) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 7) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    sscanf(argv[1], "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            &req.addr[0], &req.addr[1], &req.addr[2],
            &req.addr[3], &req.addr[4], &req.addr[5]);

    req.psm  = strtoul(argv[2], NULL, 0);
    req.imtu = 0;
    req.omtu = 0;

    if (argc == 3) {
        process_request(request, &req);
        return;
    }

    if (!strcmp(argv[3], "imtu")) {
        req.imtu = strtoul(argv[4], NULL, 0);

        if (argc > 6 && !strcmp(argv[5], "omtu")) {
            req.omtu = strtoul(argv[6], NULL, 0);
        } else if (argc > 5) {
            BTT_LOG_S("Error: Unknown argument <%s>\n", argv[5]);
            return;
        }
    } else if (!strcmp(argv[3], "omtu")) {
        req.omtu = strtoul(argv[4], NULL, 0);
    } else {
        BTT_LOG_S("Error: Unknown argument <%s>\n", argv[3]);
        return;
    }

    process_request(request, &req);
}

static void run_l2cap_connect(int argc, char **argv)
{
    l2cap_connect(argc, argv, BTT_REQ_CONNECT_AND_BE_SILENT);
}

static void run_l2cap_connect_dump(int argc, char **argv)
{
    l2cap_connect(argc, argv, BTT_REQ_CONNECT_AND_DUMP);
}

static void run_l2cap_disconnect(int argc, char **argv)
{
    int cid = 0;

    if (argc > 1) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    process_request(BTT_REQ_DISCONNECT, &cid);
}

static void run_l2cap_write(int argc, char **argv)
{
    struct btt_req_write req;

    if (argc < 2) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    req.len    = strlen(argv[1]);
    req.buffer = argv[1];

    process_request(BTT_REQ_WRITE, &req);
}

static void run_l2cap_listen(int argc, char **argv)
{
    struct btt_req_listen req;

    if (argc < 2 || argc == 3 || argc == 5) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 6) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    req.psm = strtoul(argv[1], NULL, 0);

    if (!(req.psm % 2)) {
        BTT_LOG_S("Error: PSM must be odd number\n");
        return;
    }

    req.imtu = 0;
    req.omtu = 0;

    if (argc == 2) {
        process_request(BTT_REQ_LISTEN, &req);
        return;
    }

    if (!strcmp(argv[2], "imtu")) {
        req.imtu = strtoul(argv[3], NULL, 0);

        if (argc > 5 && !strcmp(argv[4], "omtu")) {
            req.omtu = strtoul(argv[5], NULL, 0);
        } else if (argc > 4) {
            BTT_LOG_S("Error: Unknown argument <%s>\n", argv[4]);
            return;
        }
    } else if (!strcmp(argv[2], "omtu")) {
        req.omtu = strtoul(argv[3], NULL, 0);
    } else {
        BTT_LOG_S("Error: Unknown argument <%s>\n", argv[2]);
        return;
    }

    process_request(BTT_REQ_LISTEN, &req);
}

static void run_l2cap_ping(int argc, char **argv)
{
    struct btt_req_ping req;
    int j;
    int count;
    int delay = 1000000;

    if (argc < 2 || argc == 3 || argc == 5) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    sscanf(argv[1], "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            &req.addr[0], &req.addr[1], &req.addr[2],
            &req.addr[3], &req.addr[4], &req.addr[5]);

    if (argc == 2) {
        process_request(BTT_REQ_PING, &req);
        return;
    }

    if (!strcmp(argv[2], "count")) {
        count = strtoul(argv[3], NULL, 0);

        if (argc > 5 && !strcmp(argv[4], "delay")) {
            delay = strtoul(argv[5], NULL, 0);
        } else if (argc > 4) {
            BTT_LOG_S("Error: Unknown argument <%s>\n", argv[4]);
            return;
        }
    } else if (!strcmp(argv[2], "delay")) {
        delay = strtoul(argv[3], NULL, 0);
    } else {
        BTT_LOG_S("Error: Unknown argument <%s>\n", argv[2]);
        return;
    }

    if (delay < 100000) {
        BTT_LOG_S("WARNING: stack may explode\n");
    }

    for (j = 0; j < count; j++) {
        process_request(BTT_REQ_PING, &req);
        usleep(delay);
    }
}

