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

extern const bt_interface_t   *bluetooth_if;
extern const test_interface_t *test_if;

static int socket_remote_misc;

void handle_misc_cmd(const struct btt_message* btt_msg_misc,
                     const int socket_remote)
{
    int length;

    socket_remote_misc = socket_remote;

    switch (btt_msg_misc->command) {
    case BTT_RSP_AGENT_SSP_REPLY: {
        struct btt_msg_cmd_agent_ssp msg;

        recv(socket_remote_misc, &msg, sizeof(msg), 0);
        BTT_LOG_D("passkey:%d in %s\n", msg.passkey, __FUNCTION__);
        bluetooth_if->ssp_reply((bt_bdaddr_t *)msg.addr,
            (bt_ssp_variant_t) msg.variant, msg.accept, msg.passkey);
        break;
    }
    case BTT_CMD_TESTER_DUMP: {
        struct btt_msg_cmd_tester_dump btt_msg;
        struct btt_message             btt_rsp;
        const tester_test_interface_t *tester;
        int result;

        recv(socket_remote_misc, &btt_msg,
             sizeof(struct btt_message) + btt_msg_misc->length, 0);
        length = 0;
        tester =
            (const tester_test_interface_t *)test_if->get_test_interface(TEST_TESTER);
        result = tester->dump(btt_msg.type, btt_msg.name);
        btt_rsp.command =  result ? BTT_RSP_ERROR : BTT_RSP_OK;
        btt_rsp.length  = 0;
        if (send(socket_remote_misc, (const char *)&btt_rsp,
                              sizeof(struct btt_message), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error\n", __FUNCTION__);
        }
        break;
    }
    default:
            break;
    }
}

