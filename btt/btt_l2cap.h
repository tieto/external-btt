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

#ifdef BTT_L2CAP_H
    #error Included twice.
#endif
#define BTT_L2CAP_H

#define CONNECTING_MASK  0x0001
#define CONF_RCVD_MASK   0x0002
#define CONF_SENT_MASK   0x0004
#define CONNECTED_MASK   0x0007

enum btt_l2cap_cb_t {
    BTT_L2CAP_CONNECTED = BTT_ADAPTER_END,
    BTT_L2CAP_CONFIG,
    BTT_L2CAP_RECV_DATA,
    BTT_L2CAP_TX_COMPLETE,
    BTT_L2CAP_PING_RSP,
    BTT_L2CAP_DISCONNECTED,
    BTT_L2CAP_CONN_IND,
    BTT_L2CAP_STATUS,
    BTT_L2CAP_END
};

struct btt_l2cap_cb_hdr {
    enum btt_l2cap_cb_t type;
    unsigned int        length;
};

struct btt_l2cap_cb_connected {
    struct btt_l2cap_cb_hdr hdr;

    int result;
    int cid;
};

struct btt_l2cap_cb_disconnected {
    struct btt_l2cap_cb_hdr hdr;

    int result;
    int cid;
};

struct btt_l2cap_cb_config {
    struct btt_l2cap_cb_hdr hdr;

    int direction; /* sent = 1, rcvd = 2 */
};

struct btt_l2cap_cb_tx_complete {
    struct btt_l2cap_cb_hdr hdr;

    int result;
    int cid;
};

struct btt_l2cap_cb_data {
    struct btt_l2cap_cb_hdr hdr;

    void *data;
};

struct btt_l2cap_cb_status {
    struct btt_l2cap_cb_hdr hdr;

    int cid;
    int state;
    int psm;
};

struct btt_l2cap_cb_conn_ind {
    struct btt_l2cap_cb_hdr hdr;

    uint8_t addr[BD_ADDR_LEN];
    int     cid;
    int     psm;
    int     id;
};

struct btt_msg_cmd_l2cap_connect {
    struct btt_message hdr;

    int      psm;
    uint8_t  addr[BD_ADDR_LEN];
    uint16_t imtu;
    uint16_t omtu;
};

struct btt_msg_cmd_l2cap_ping {
    struct btt_message hdr;

    uint8_t addr[BD_ADDR_LEN];
};

struct btt_l2cap_cb_ping_rsp {
    struct btt_l2cap_cb_hdr hdr;

    int result;
};

struct btt_msg_cmd_l2cap_disconnect {
    struct btt_message hdr;

    uint16_t cid;
};

struct btt_msg_cmd_l2cap_write {
    struct btt_message hdr;

    uint16_t cid;
};

struct btt_msg_cmd_l2cap_listen {
    struct btt_message hdr;

    int      psm;
    uint16_t imtu;
    uint16_t omtu;
};

enum btt_l2cap_state {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING
};

struct btt_l2cap_session {
    enum btt_l2cap_state state;
    int                  psm;
};

extern void run_l2cap(int argc, char **argv);
extern const struct command *btt_l2cap_commands;

