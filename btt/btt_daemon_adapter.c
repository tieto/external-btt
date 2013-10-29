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

extern const bt_interface_t *bluetooth_if;

bool turning_on_adapter = FALSE;
bool bonding_peer_dev   = FALSE;

void handle_adapter_cmd(const struct btt_message *btt_msg,
                        const int socket_remote)
{
    switch (btt_msg->command) {
    case BTT_CMD_ADAPTER_UP:
    /* TODO: detect status of adapter and fix reply*/
        if (bluetooth_if->enable() == BT_STATUS_SUCCESS)
            turning_on_adapter = TRUE;
        break;
    case BTT_CMD_ADAPTER_DOWN:
        bluetooth_if->disable();
        break;
    case BTT_CMD_ADAPTER_NAME:
        bluetooth_if->get_adapter_property(BT_PROPERTY_BDNAME);
        break;
    case BTT_CMD_ADAPTER_ADDRESS:
        bluetooth_if->get_adapter_property(BT_PROPERTY_BDADDR);
        break;
    case BTT_CMD_ADAPTER_SCAN:
        bluetooth_if->start_discovery();
        break;
    case BTT_CMD_ADAPTER_SCAN_MODE: {
        struct btt_msg_cmd_adapter_scan_mode msg;
        bt_property_t  prop;
        bt_scan_mode_t scan_mode;

        prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE;
        prop.len  = sizeof(bt_scan_mode_t);

        recv(socket_remote, &msg, sizeof(msg), 0);

        if (msg.mode == 0)
            scan_mode = BT_SCAN_MODE_NONE;
        else if (msg.mode == 1)
            scan_mode = BT_SCAN_MODE_CONNECTABLE;
        else if (msg.mode == 2)
            scan_mode = BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
        else
            scan_mode = BT_SCAN_MODE_NONE;

        prop.val = &scan_mode;

        bluetooth_if->set_adapter_property(&prop);
        break;
    }
    case BTT_CMD_ADAPTER_PAIR: {
        struct btt_msg_cmd_adapter_pair msg;

        recv(socket_remote, &msg, sizeof(msg), 0);

        if (bluetooth_if->create_bond((bt_bdaddr_t *)msg.addr) ==
                BT_STATUS_SUCCESS)
            bonding_peer_dev = TRUE;
        break;
    }
    case BTT_CMD_ADAPTER_UNPAIR: {
        struct btt_msg_cmd_adapter_pair msg;

        recv(socket_remote, &msg, sizeof(msg), 0);

        bluetooth_if->remove_bond((bt_bdaddr_t *)msg.addr);
        break;
    }
    default:
        break;
    }
}

