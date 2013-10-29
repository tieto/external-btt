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

extern const test_interface_t *test_if;

static struct l2cap_session_data session_data;
static int socket_remote_l2cap;

static bool config_req(uint16_t cid, tl2cap_cfg_info_t *config)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->config_req(cid, config);
}

static bool config_rsp(uint16_t cid, tl2cap_cfg_info_t *config)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->config_rsp(cid, config);
}

static bool connect_rsp(bt_bdaddr_t *addr, uint8_t id,
        uint16_t lcid, uint16_t result, uint16_t status)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->connect_rsp(addr, id, lcid, result, status);
}

static uint16_t connect_req(uint16_t psm, bt_bdaddr_t *addr)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return -1;
    else
        return l2cap_if->connect_req(psm, addr);
}

static bool disconnect_req(uint16_t cid)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->disconnect_req(cid);
}

static bool disconnect_rsp(uint16_t cid)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->disconnect_rsp(cid);
}

static uint8_t write_data(uint16_t cid, uint32_t length, uint8_t *buf)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->write_data(cid, length, buf);
}

static void l2cap_echo(uint16_t result)
{
    struct btt_l2cap_cb_ping_rsp cb;

    cb.hdr.type   = BTT_L2CAP_PING_RSP;
    cb.hdr.length = sizeof(cb) - sizeof(struct btt_l2cap_cb_hdr);
    cb.result = result;

    if (send(socket_remote_l2cap, (const char *)&cb, sizeof(cb), 0) == -1) {
        BTT_LOG_E("%s:System Socket Error\n",__FUNCTION__);
    }
    close(socket_remote_l2cap);
}

static bool l2cap_ping(uint8_t *addr)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return false;
    else
        return l2cap_if->ping(addr, &l2cap_echo);
}

/*
 * Be careful to close socket in l2cap_callback().
 * Some of commands, like BTT_L2CAP_CONNECT, trigger several
 * callings of l2cap_callback() in succession. You can only
 * close the socket when the following calling of l2cap_callback()
 * will NOT use it.
 */
static void l2cap_callback(bt_l2cap_callback_t *callback_data)
{
    switch (callback_data->type) {
    case CONN_CFM_CB: {
        struct btt_l2cap_cb_connected cb;
        tl2cap_cfg_info_t cfg;
        bt_l2cap_int_t *data = (bt_l2cap_int_t *)callback_data->val;

        BTT_LOG_I("%s:CONN_CFM_CB", __FUNCTION__);

        cb.hdr.type   = BTT_L2CAP_CONNECTED;
        cb.hdr.length = sizeof(cb) - sizeof(struct btt_l2cap_cb_hdr);
        cb.result = data->result;
        cb.cid    = data->cid;
        session_data.omtu_neg = 0;
        session_data.imtu_neg = 0;

        if (send(socket_remote_l2cap, (const char *)&cb, sizeof(cb), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
        }

        session_data.cid = data->cid;
        if (!data->result) {
            session_data.connected = true;
            memset (&cfg, 0, sizeof(cfg));
            cfg.result = 0;

            if (session_data.imtu_set) {
                cfg.mtu_present = true;
                cfg.mtu = session_data.imtu;
            }
            session_data.imtu_neg++;
            config_req(session_data.cid, &cfg);
        } else {
            close(socket_remote_l2cap);
        }
        break;
    }
    case CONF_IND_CB: {
        struct btt_l2cap_cb_config cb;
        tl2cap_cfg_info_t cfg;
        bt_l2cap_cfg_t *recv_cfg = (bt_l2cap_cfg_t *)callback_data->val;

        BTT_LOG_I("%s:CONF_IND_CB", __FUNCTION__);

        session_data.conf_rcvd = true;
        memset (&cfg, 0, sizeof(cfg));

        if (session_data.omtu_set && session_data.omtu > recv_cfg->cfg->mtu) {
            if (session_data.omtu_neg >= MAX_CONF_NEG) {
                disconnect_req(session_data.cid);
                return;
            }

            cfg.result      = 1;
            cfg.mtu_present = true;
            cfg.mtu         = session_data.omtu;
            config_rsp(session_data.cid, &cfg);
            session_data.omtu_neg++;
        } else {
            cfg.result = 0;
            if (recv_cfg->cfg->mtu_present) {
                cfg.mtu_present   = true;
                cfg.mtu           = recv_cfg->cfg->mtu;
                session_data.omtu = recv_cfg->cfg->mtu;
            } else {
                cfg.mtu_present   = true;
                session_data.omtu = 672;
                cfg.mtu           = session_data.omtu;
            }

            config_rsp(session_data.cid, &cfg);
            cb.hdr.type   = BTT_L2CAP_CONFIG;
            cb.hdr.length = sizeof(int);
            cb.direction  = 2;

            if (send(socket_remote_l2cap, (const char *)&cb,
                                              sizeof(cb), 0) == -1) {
                BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
            }
        }
        break;
    }
    case CONF_CFM_CB: {
        struct btt_l2cap_cb_config cb;
        tl2cap_cfg_info_t cfg;
        bt_l2cap_cfg_t *recv_cfg = (bt_l2cap_cfg_t *)callback_data->val;

        BTT_LOG_I("%s:CONF_CFM_CB", __FUNCTION__);

        if (session_data.imtu_set && session_data.imtu > recv_cfg->cfg->mtu) {
            if (session_data.omtu_neg >= MAX_CONF_NEG) {
                disconnect_req(session_data.cid);
                return;
           }

            /*TODO send status message to inform we won't connect*/
            memset (&cfg, 0, sizeof(cfg));
            cfg.result      = 0;
            cfg.mtu_present = true;
            cfg.mtu         = session_data.imtu;
            session_data.imtu_neg++;
        } else {
            session_data.conf_sent = true;
            cb.hdr.type   = BTT_L2CAP_CONFIG;
            cb.hdr.length = sizeof(int);
            cb.direction  = 1;

            if (send(socket_remote_l2cap, (const char *)&cb,
                                              sizeof(cb), 0) == -1) {
                BTT_LOG_E("%s:System Socket Error 3\n", __FUNCTION__);
            }
            close(socket_remote_l2cap);
        }
        break;
    }
    case DATA_IND_CB: {
        bt_l2cap_data_t *data;
        uint8_t *buf;
        struct btt_l2cap_cb_hdr msg;

        BTT_LOG_I("%s:DATA_IND_CB", __FUNCTION__);

        data = (bt_l2cap_data_t *)callback_data->val;
        buf  = (uint8_t *)malloc(data->buf->len);
        memcpy(buf, data->buf + 2, data->buf->len);
        msg.type   = BTT_L2CAP_RECV_DATA;
        msg.length = data->buf->len;

        if (send(socket_remote_l2cap, (const char *)&msg,
                                          sizeof(msg), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 4\n", __FUNCTION__);
        }

        if (send(socket_remote_l2cap, (const char *)buf,
                                      data->buf->len, 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 5\n", __FUNCTION__);
        }

        free(buf);
        break;
    }
    case CONN_IND_CB: {
        struct btt_l2cap_cb_conn_ind cb;
        tl2cap_cfg_info_t cfg;
        bt_l2cap_conn_ind_t *data;

        BTT_LOG_I("%s:CONN_IND_CB", __FUNCTION__);

        data = (bt_l2cap_conn_ind_t *)callback_data->val;
        session_data.omtu_neg = 0;
        session_data.imtu_neg = 0;

        if (session_data.listening) {
            session_data.cid = data->cid;
            connect_rsp(data->addr, data->id,
            data->cid, 0, 0);
        }

        cb.hdr.type   = BTT_L2CAP_CONN_IND;
        cb.hdr.length = sizeof(cb) - sizeof(struct btt_l2cap_cb_hdr);

        cb.psm = data->psm;
        cb.cid = data->cid;
        cb.id  = data->id;
        memcpy(cb.addr, data->addr, sizeof(bt_bdaddr_t));

        session_data.connected = true;
        session_data.cid       = data->cid;
        memset (&cfg, 0, sizeof(cfg));
        cfg.result = 0;

        if (session_data.imtu_set) {
            cfg.mtu_present = true;
            cfg.mtu         = session_data.imtu;
        }
        session_data.imtu_neg++;
        config_req(session_data.cid, &cfg);

        if (send(socket_remote_l2cap, (const char *)&cb, sizeof(cb), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 6\n", __FUNCTION__);
        }
        break;
    }
    case TX_COMPLETE_CB: {
        struct btt_l2cap_cb_tx_complete cb;
        bt_l2cap_int_t *data = (bt_l2cap_int_t *)callback_data->val;

        BTT_LOG_I("%s:TX_COMPLETE_CB", __FUNCTION__);

        cb.hdr.type   = BTT_L2CAP_TX_COMPLETE;
        cb.hdr.length = sizeof(int) * 2;
        cb.cid    = data->cid;
        cb.result = data->result;

        if (send(socket_remote_l2cap, (const char *)&cb, sizeof(cb), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 7\n", __FUNCTION__);
        }
        break;
    }
    case DISC_CFM_CB: {
        struct btt_l2cap_cb_disconnected cb;
        bt_l2cap_int_t *data = (bt_l2cap_int_t *)callback_data->val;

        BTT_LOG_I("%s:DISC_CFM_CB", __FUNCTION__);

        cb.hdr.type   = BTT_L2CAP_DISCONNECTED;
        cb.hdr.length = sizeof(int) * 2;
        cb.result = data->result;
        cb.cid    = data->cid;

        session_data.omtu_set  = false;
        session_data.imtu_set  = false;
        session_data.connected = false;

        if (send(socket_remote_l2cap, (const char *)&cb, sizeof(cb), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 8\n", __FUNCTION__);
        }
        break;
    }
    case DISC_IND_CB: {
        struct btt_l2cap_cb_disconnected cb;
        bt_l2cap_bool_cb_t *data = (bt_l2cap_bool_cb_t *)callback_data->val;

        BTT_LOG_I("%s:DISC_IND_CB", __FUNCTION__);

        disconnect_rsp(data->cid);

        cb.hdr.type   = BTT_L2CAP_DISCONNECTED;
        cb.hdr.length = sizeof(int) * 2;
        cb.result = data->result;
        cb.cid    = data->cid;

        session_data.omtu_set  = false;
        session_data.imtu_set  = false;
        session_data.connected = false;

        if (send(socket_remote_l2cap, (const char *)&cb, sizeof(cb), 0) == -1) {
           BTT_LOG_E("%s: System Socket Error 9\n", __FUNCTION__);
        }
        break;
    }
    default:
        break;
    }
}

static int register_psm(int psm)
{
    const btl2cap_interface_t *l2cap_if =
          (const btl2cap_interface_t *)test_if->get_test_interface(TEST_L2CAP);

    if (l2cap_if == NULL)
        return -1;
    else
        return l2cap_if->register_psm(psm, &l2cap_callback);
}

void handle_l2cap_cmd(const struct btt_message* btt_msg_l2cap,
                      const int socket_remote)
{
    socket_remote_l2cap = socket_remote;

    switch (btt_msg_l2cap->command) {
    case BTT_L2CAP_CONNECT: {
        struct btt_msg_cmd_l2cap_connect msg;

        recv(socket_remote_l2cap, &msg, sizeof(msg), 0);
        session_data.psm = register_psm(msg.psm);

        if (msg.imtu > 0) {
            session_data.imtu     = msg.imtu;
            session_data.imtu_set = true;
        }
        if (msg.omtu >0) {
            session_data.omtu     = msg.omtu;
            session_data.omtu_set = true;
        }

        session_data.cid =
            connect_req(session_data.psm, (bt_bdaddr_t *)msg.addr);
        break;
    }
    case BTT_L2CAP_DISCONNECT: {
        struct btt_msg_cmd_l2cap_disconnect msg;

        recv(socket_remote_l2cap, &msg, sizeof(msg), 0);

        if (session_data.cid == 0)
            break;

        disconnect_req(session_data.cid);
        break;
    }
    case BTT_L2CAP_WRITE: {
        struct btt_msg_cmd_l2cap_write msg;
        char *buffer;

        recv(socket_remote_l2cap, &msg, sizeof(msg), 0);

        buffer = malloc(msg.hdr.length);
        if (NULL == buffer)
            break;
        memset(buffer, 0, msg.hdr.length);

        if (msg.hdr.length != 0) {
            recv(socket_remote_l2cap, buffer, msg.hdr.length, 0);
        } else {
            write_data(session_data.cid, session_data.omtu, (uint8_t *)buffer);
            free(buffer);
            break;
        }

        if (session_data.cid == 0) {
           free(buffer);
           break;
        }

        write_data(session_data.cid, msg.hdr.length, (uint8_t *)buffer);
        free(buffer);
        break;
    }
    case BTT_L2CAP_LISTEN: {
        struct btt_msg_cmd_l2cap_listen msg;

        recv(socket_remote_l2cap, &msg, sizeof(msg), 0);

        if (msg.imtu > 0) {
           session_data.imtu     = msg.imtu;
           session_data.imtu_set = true;
        }
        if (msg.omtu > 0) {
           session_data.omtu     = msg.omtu;
           session_data.omtu_set = true;
        }

        session_data.psm       = register_psm(msg.psm);
        session_data.listening = true;
        break;
    }
    case BTT_L2CAP_PING: {
        struct btt_msg_cmd_l2cap_ping msg;

        recv(socket_remote_l2cap, &msg, sizeof(msg), 0);

        l2cap_ping(msg.addr);
        break;
    }
    default:
        break;
    }
}

