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

extern const test_interface_t *test_if;

static int socket_remote_sdp;

static unsigned int sdp_get_number_of_records(void)
{
    unsigned int records;

    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    records = test->get_number_of_records();

    BTT_LOG_I("Number of records: %i\n", records);

    return records;
}

static unsigned int sdp_get_max_number_of_records(void)
{
    unsigned int records;

    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    records = test->get_max_number_of_records();

    BTT_LOG_I("Max number of records: %i\n", records);

    return records;
}

static unsigned int sdp_create_record(void)
{
    unsigned int handle;

    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    handle = test->create_record();

    BTT_LOG_I("Create record: 0x%x\n", handle);

    return handle;
}

static unsigned int sdp_delete_record(unsigned int handle)
{
    unsigned int result;
    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    result = test->delete_record(handle);

    BTT_LOG_I("Delete record 0x%x - %s \n", handle, result ? "ok" : "error");

    return result;
}

static unsigned int sdp_connect(unsigned char bd_addr[BD_ADDR_LEN])
{
    unsigned int handle;
    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    handle = test->connect(bd_addr);

    BTT_LOG_I("SDP Connect %02x:%02x:%02x:%02x:%02x:%02x with handle=%x \n",
            bd_addr[0], bd_addr[1], bd_addr[2],
            bd_addr[3], bd_addr[4], bd_addr[5], handle);

    return handle;
}

static unsigned int sdp_disconnect(unsigned int handle)
{
    unsigned int result;
    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    result = test->disconnect(handle);

    return result;
}

static unsigned int sdp_send(unsigned int handle, unsigned int length,
                             unsigned char *data)
{
    unsigned int result;
    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    result = test->send(handle, length, data);

    return result;
}

static char *sdp_get_records(void)
{
    const sdp_test_interface_t *test =
        (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

    return (char *) test->get_records();
}

void handle_sdp_cmd(struct btt_message * btt_msg_sdp, const int socket_remote)
{
    int length;

    socket_remote_sdp = socket_remote;

    switch (btt_msg_sdp->command) {
    case BTT_CMD_SDP_GET_NUMBER_OF_RECORDS: {
        struct btt_msg_rsp_sdp_get_records_num btt_msg;

        btt_msg.records     = sdp_get_number_of_records();
        btt_msg.max_records = sdp_get_max_number_of_records();
        btt_msg.hdr.command = BTT_RSP_SDP_GET_NUMBER_OF_RECORDS;
        btt_msg.hdr.length  = sizeof(struct btt_msg_rsp_sdp_get_records_num) -
                              sizeof(struct btt_message);
        if (send(socket_remote_sdp, (const char *)&btt_msg,
                 sizeof(struct btt_msg_rsp_sdp_get_records_num), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 1\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_CREATE_RECORD: {
        struct btt_msg_rsp_sdp_create_record btt_msg;
        unsigned int handle;

        handle = sdp_create_record();
        if (!handle) {
            btt_msg_sdp->command = BTT_RSP_ERROR;
            btt_msg_sdp->length  = 0;
            if (send(socket_remote_sdp, (const char *)btt_msg_sdp,
                                    sizeof(struct btt_message), 0) == -1) {
                BTT_LOG_E("%s:System Socket Error 2\n", __FUNCTION__);
            }
            break;
        }

        btt_msg.handle = handle;
        btt_msg.hdr.command = BTT_RSP_SDP_CREATE_RECORD;
        btt_msg.hdr.length  = sizeof(struct btt_msg_rsp_sdp_create_record) -
                              sizeof(struct btt_message);
        if (send(socket_remote_sdp, (const char *)&btt_msg,
                 sizeof(struct btt_msg_rsp_sdp_create_record), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 3\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_DELETE_RECORD: {
        struct btt_msg_cmd_sdp_delete_record btt_msg;
        struct btt_message                   btt_rsp;
        unsigned int result;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_msg_cmd_sdp_delete_record), 0);
        length = 0;
        result = sdp_delete_record(btt_msg.handle);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                             sizeof(struct btt_message), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 4\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_CONNECT: {
        struct btt_msg_cmd_sdp_connect btt_msg;
        struct btt_message             btt_rsp;
        unsigned int result;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_msg_cmd_sdp_connect), 0);
        length = 0;
        result = sdp_connect(btt_msg.bd_addr);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                             sizeof(struct btt_message), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 5\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_DISCONNECT: {
        struct btt_msg_cmd_sdp_disconnect btt_msg;
        struct btt_message                btt_rsp;
        unsigned int result;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_msg_cmd_sdp_disconnect), 0);
        length = 0;
        result = sdp_disconnect(btt_msg.handle);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                             sizeof(struct btt_message), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 6\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_SEND: {
        struct btt_msg_cmd_sdp_send *btt_msg;
        struct btt_message           btt_rsp;
        unsigned int result;

        btt_msg =
            (struct btt_msg_cmd_sdp_send *)malloc(sizeof(struct btt_message) +
                                                  btt_msg_sdp->length);

        recv(socket_remote_sdp, btt_msg,
             sizeof(struct btt_message) + btt_msg_sdp->length, 0);
        length = 0;
        result = sdp_send(btt_msg->handle, btt_msg->length, btt_msg->data);

        free(btt_msg);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                             sizeof(struct btt_message), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 7\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_PRINT_RECORDS: {
        struct btt_msg_rsp_sdp_get_records *btt_rsp;
        struct sdp_test_records            *records;

        records = (struct sdp_test_records *)sdp_get_records();

        btt_rsp = (struct btt_msg_rsp_sdp_get_records *)malloc(
                  sizeof(struct btt_msg_rsp_sdp_get_records) + records->size);

        btt_rsp->hdr.command = BTT_RSP_SDP_PRINT_RECORDS;
        btt_rsp->hdr.length  = sizeof(struct btt_msg_rsp_sdp_get_records) -
                               sizeof(struct btt_message) + records->size;
        memcpy(btt_rsp->records, records, records->size);

        if (send(socket_remote_sdp, (const char *)btt_rsp,
                 sizeof(struct btt_message) + btt_rsp->hdr.length, 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 8\n", __FUNCTION__);
        }

        free(btt_rsp);
        break;
    }
    case BTT_CMD_SDP_PRINT_REMOTE_RECORDS: {
        struct btt_msg_cmd_sdp_print_remote_records btt_msg;
        struct btt_msg_rsp_sdp_get_records         *btt_rsp;
        struct sdp_test_records                    *records;
        const sdp_test_interface_t                 *test;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_message) + btt_msg_sdp->length, 0);
        test =
            (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

        records = (struct sdp_test_records *)test->get_remote_records(
                   btt_msg.bd_addr, btt_msg.type, btt_msg.data);
        btt_rsp = (struct btt_msg_rsp_sdp_get_records *)malloc(
                   sizeof(struct btt_msg_rsp_sdp_get_records) + records->size);

        btt_rsp->hdr.command = BTT_RSP_SDP_PRINT_RECORDS;
        btt_rsp->hdr.length  = sizeof(struct btt_msg_rsp_sdp_get_records) -
                               sizeof(struct btt_message) + records->size;
        memcpy(btt_rsp->records, records, records->size);
        if (send(socket_remote_sdp, (const char *)btt_rsp,
                 sizeof(struct btt_message) + btt_rsp->hdr.length, 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 9\n", __FUNCTION__);
        }

        free(btt_rsp);
        break;
    }
    case BTT_CMD_SDP_ADD_RFCOMM_RECORD: {
        struct btt_msg_cmd_sdp_add_rfcomm_record btt_msg;
        struct btt_message                       btt_rsp;
        unsigned int                             result;
        const sdp_test_interface_t              *test;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_message) + btt_msg_sdp->length, 0);
        length = 0;

        test =
            (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

        result = test->add_rfcomm_record(btt_msg.name,
                                         btt_msg.uuid,
                                         btt_msg.channel);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                 sizeof(struct btt_message) + btt_rsp.length, 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 10\n", __FUNCTION__);
        }
        break;
    }
        case BTT_CMD_SDP_ADD_ATTRIBUTE: {
        struct btt_msg_cmd_sdp_add_attribute *btt_msg;
        struct btt_message                    btt_rsp;
        unsigned int                          result;
        const sdp_test_interface_t           *test;

        btt_msg = (struct btt_msg_cmd_sdp_add_attribute *)malloc(
                      sizeof(struct btt_message) + btt_msg_sdp->length);
        recv(socket_remote_sdp, btt_msg,
             sizeof(struct btt_message) +btt_msg_sdp->length, 0);
        length = 0;

        test =
            (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

        result = test->add_attribute(btt_msg->handle,
                                     btt_msg->attribute_id,
                                     btt_msg->type,
                                     btt_msg->length,
                                     btt_msg->data);
        free(btt_msg);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                 sizeof(struct btt_message) + btt_rsp.length, 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 11\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_DELETE_ATTRIBUTE:{
        struct btt_msg_cmd_sdp_delete_attribute btt_msg;
        struct btt_message                      btt_rsp;
        unsigned int                            result;
        const sdp_test_interface_t             *test;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_message) + btt_msg_sdp->length, 0);
        length = 0;

        test =
            (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

        result = test->delete_attribute(btt_msg.handle,
                                        btt_msg.attribute_id);

        btt_rsp.command = result ? BTT_RSP_OK : BTT_RSP_ERROR;
        btt_rsp.length  = 0;
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                 sizeof(struct btt_message) + btt_rsp.length, 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 12\n", __FUNCTION__);
        }
        break;
    }
    case BTT_CMD_SDP_TRACE_LEVEL: {
        struct btt_msg_cmd_sdp_trace_level btt_msg;
        struct btt_msg_rsp_sdp_trace_level btt_rsp;
        unsigned int                       level;
        const sdp_test_interface_t        *test;

        recv(socket_remote_sdp, &btt_msg,
             sizeof(struct btt_message) + btt_msg_sdp->length, 0);
        length = 0;

        test =
            (const sdp_test_interface_t *)test_if->get_test_interface(TEST_SDP);

        level = test->trace_level(btt_msg.level);
        btt_rsp.level = level;

        btt_rsp.hdr.command = (btt_msg.level == 0xFF) ?
                              BTT_RSP_SDP_TRACE_LEVEL : BTT_RSP_OK;
        btt_rsp.hdr.length  = sizeof(struct btt_msg_rsp_sdp_trace_level) -
                              sizeof(struct btt_message);
        if (send(socket_remote_sdp, (const char *)&btt_rsp,
                 sizeof(struct btt_msg_rsp_sdp_trace_level), 0) == -1) {
            BTT_LOG_E("%s:System Socket Error 13\n", __FUNCTION__);
        }
        break;
    }
    default:
        break;
    }
}

