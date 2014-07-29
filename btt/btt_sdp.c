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

#include <dlfcn.h>
#include <errno.h>

#include "btt.h"
#include "btt_sdp.h"
#include "btt_utils.h"

static void run_sdp_help(int argc, char **argv);
static void run_sdp_get_number_of_records(int argc, char **argv);
static void run_sdp_create_record(int argc, char **argv);
static void run_sdp_delete_record(int argc, char **argv);
static void run_sdp_print_records(int argc, char **argv);
static void run_sdp_print_remote_records(int argc, char **argv);
static void run_sdp_add_attribute(int argc, char **argv);
static void run_sdp_delete_attribute(int argc, char **argv);
static void run_sdp_add_rfcomm_record(int argc, char **argv);
static void run_sdp_trace_level(int argc, char **argv);
static void run_sdp_connect(int argc, char **argv);
static void run_sdp_disconnect(int argc, char **argv);
static void run_sdp_send(int argc, char **argv);

static const struct command sdp_commands[] = {
    { "help",                   "",                       run_sdp_help                  },
    { "get_number_of_records",  "",                       run_sdp_get_number_of_records },
    { "create_record",          "",                       run_sdp_create_record         },
    { "delete_record",          "<RECORD_HANDLE | all>",  run_sdp_delete_record         },
    { "print_records",          "",                       run_sdp_print_records         },
    { "print_remote_records",   "NOT FULLY IMPLEMENTED YET <BD_ADDR> [public | all | record_handle <RECORD_HANDLE> | uuid <UUID16>]", run_sdp_print_remote_records },
    { "add_attribute",          "<RECORD_HANDLE> <ATTRIBUTE_ID> <TYPE_NAME={NIL | INT | UUID | TEXT | BOOLEAN | SEQUENCE | ALTERNATIVE | URL} | TYPE> <HEXLINES...>", run_sdp_add_attribute },
    { "delete_attribute",       "<RECORD_HANDLE> <ATTRIBUTE_ID>", run_sdp_delete_attribute },
    { "add_rfcomm_record",      "<NAME> <UUID_NAME={PBAP | OPP | SPP} | UUID128_HEXLINE> <channel>",       run_sdp_add_rfcomm_record },
    { "trace_level",            "[LEVEL: 0-6]",           run_sdp_trace_level           },
    { "connect",                "<BD_ADDR>",              run_sdp_connect               },
    { "disconnect",             "<HANDLE>",               run_sdp_disconnect            },
    { "send",                   "<HANDLE> <HEXLINES...>", run_sdp_send                  },
    { "receive",                "NOT IMPLEMENTED YET <HANDLE> <print | print_all | check [HEXLINES...] | wait [HEXLINES...]>", NULL },
};

#define SDP_SUPPORTED_COMMANDS sizeof(sdp_commands)/sizeof(struct command)

void run_sdp_help(int argc, char **argv)
{
    print_commands(sdp_commands, SDP_SUPPORTED_COMMANDS);
    exit(EXIT_SUCCESS);
}

void run_sdp(int argc, char **argv)
{
    run_generic(sdp_commands, SDP_SUPPORTED_COMMANDS, run_sdp_help, argc, argv);
}

static void run_sdp_get_number_of_records(int argc, char **argv)
{
    struct btt_message btt_msg;
    struct btt_msg_rsp_sdp_get_records_num *btt_rsp;

    if (argc != 1) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    btt_msg.command = BTT_CMD_SDP_GET_NUMBER_OF_RECORDS;
    btt_msg.length  = 0;

    btt_rsp =
        (struct btt_msg_rsp_sdp_get_records_num *)btt_send_command(&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    BTT_LOG_S("Records %u/%u\n", btt_rsp->records, btt_rsp->max_records);

    free(btt_rsp);
}

static void run_sdp_create_record(int argc, char **argv)
{
    struct btt_message btt_msg;
    struct btt_msg_rsp_sdp_create_record *btt_rsp;

    if (argc != 1) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    btt_msg.command = BTT_CMD_SDP_CREATE_RECORD;
    btt_msg.length  = 0;

    btt_rsp =
        (struct btt_msg_rsp_sdp_create_record *)btt_send_command(&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    if (btt_rsp->hdr.command == BTT_RSP_ERROR) {
        BTT_LOG_S("Error: Cannot crete new record - there is maximum number of records.\n");
        return;
    }

    BTT_LOG_S("Record handle 0x%x\n", btt_rsp->handle);

    free(btt_rsp);
}

static void run_sdp_delete_record(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_delete_record btt_msg;
    struct btt_message *btt_rsp;

    if (argc <= 1) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    btt_msg.hdr.command = BTT_CMD_SDP_DELETE_RECORD;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_delete_record) -
                          sizeof(struct btt_message);

    if (strcmp("all", argv[1]) == 0)
        btt_msg.handle = 0;
    else
        btt_msg.handle = strtoul(argv[1], NULL, 0);

    btt_rsp = btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    if (btt_rsp->command == BTT_RSP_ERROR) {
        BTT_LOG_S("Error: Cannot delete record 0x%x\n", btt_msg.handle);
        return;
    }

    if (strcmp("all", argv[1]) == 0) {
        BTT_LOG_S("All records deleted\n");
    } else {
        BTT_LOG_S("Record handle 0x%x deleted\n", btt_msg.handle);
    }

    free(btt_rsp);
}

static void run_sdp_connect(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_connect btt_msg;
    struct btt_message *btt_rsp;

    if (argc <= 1) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    memset(&btt_msg, 0, sizeof(struct btt_msg_cmd_sdp_connect));
    btt_msg.hdr.command = BTT_CMD_SDP_CONNECT;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_connect) -
                          sizeof(struct btt_message);

    sscanf(argv[1], "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            &btt_msg.bd_addr[0], &btt_msg.bd_addr[1], &btt_msg.bd_addr[2],
            &btt_msg.bd_addr[3], &btt_msg.bd_addr[4], &btt_msg.bd_addr[5]);

    btt_rsp = btt_send_command((struct btt_message *) &btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    if (btt_rsp->command == BTT_RSP_ERROR) {
        BTT_LOG_S("Error: Cannot connect to %s\n", argv[1]);
        return;
    }

    BTT_LOG_S("SDP Connected to %s with handle %u\n", argv[1], 0);

    free(btt_rsp);
}

static void run_sdp_disconnect(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_disconnect btt_msg;
    struct btt_message *btt_rsp;

    if (argc <= 1) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    btt_msg.hdr.command = BTT_CMD_SDP_DISCONNECT;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_disconnect) -
                          sizeof(struct btt_message);

    btt_msg.handle = strtoul(argv[1], NULL, 0);

    btt_rsp = btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    if (btt_rsp->command == BTT_RSP_ERROR) {
        BTT_LOG_S("Error: Cannot disconnect on handle %s\n", argv[1]);
        return;
    }

    BTT_LOG_S("SDP Disconnected on handle %s\n", argv[1]);

    free(btt_rsp);
}

static void run_sdp_send(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_send *btt_msg;
    struct btt_message *btt_rsp;
    int length;

    if (argc <= 2) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    length = get_hexlines_length(2, argc, argv);
    if (length < 0) return;

    btt_msg = (struct btt_msg_cmd_sdp_send *)malloc(
                  sizeof(struct btt_msg_cmd_sdp_send) + length);

    btt_msg->hdr.command = BTT_CMD_SDP_SEND;
    btt_msg->hdr.length  = sizeof(struct btt_msg_cmd_sdp_send) -
                           sizeof(struct btt_message) + length;
    btt_msg->length = length;
    btt_msg->handle = strtoul(argv[1], NULL, 0);

    length = hexlines_to_data(2, argc, argv, btt_msg->data);
    if (length < 0) {
        free(btt_msg);
        return;
    }

    btt_rsp = btt_send_command((struct btt_message *)btt_msg);
    free(btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    if (btt_rsp->command == BTT_RSP_ERROR) {
        BTT_LOG_S("Error: Cannot send data on handle %s\n", argv[1]);
        free(btt_rsp);
        return;
    }

    BTT_LOG_S("SDP data send on handle %s\n", argv[1]);

    free(btt_rsp);
}

static void sdp_print_records(struct btt_msg_rsp_sdp_get_records *btt_rsp,
                              int verbose)
{
    bool use_generic = FALSE;
    struct ext_btt_message ext_cmd;
    
    ext_cmd.cmd     = BTT_EXT_SDP_CMD;
    ext_cmd.sub_cmd = BTT_EXT_SDP_DECODE_RECORDS_CMD;
    btt_send_ext_command(&ext_cmd, (char*)btt_rsp,
                         btt_rsp->hdr.length + sizeof(struct btt_message));

#ifndef WITHOUT_STACK
    if (use_generic) {
        struct sdp_test_record_attribute *attr;
        unsigned int i_record;
        unsigned int i_attr;
        unsigned int i_data;
        char *service_name;
        char *attr_value;

        for (i_record = 0;
             i_record < btt_rsp->records->records_num;
             i_record += 1) {
            /* main uuid search */
            service_name = "";
            for (i_attr = 0;
                 i_attr < btt_rsp->records->record[i_record].attributes_num;
                 i_attr += 1) {
                attr =
                    (struct sdp_test_record_attribute *)((char *)btt_rsp->records +
                    btt_rsp->records->record[i_record].attribute_offset);

                if (attr[i_attr].id == 0x0100)
                    service_name = (((char *) btt_rsp->records) +
                                   attr[i_attr].value_offset);
            }

            BTT_LOG_S("Record: %u/%u\n\tService name: \"%s\"\n", i_record + 1,
                      btt_rsp->records->records_num, service_name);

            for (i_attr = 0;
                 i_attr < btt_rsp->records->record[i_record].attributes_num;
                 i_attr += 1) {
                attr =
                    (struct sdp_test_record_attribute *)((char *)btt_rsp->records +
                    btt_rsp->records->record[i_record].attribute_offset);

                BTT_LOG_S("\t    Attribute %u/%u, ID: 0x%04x, Type: %u, Length: %3u",
                          i_attr + 1,
                          btt_rsp->records->record[i_record].attributes_num,
                          attr[i_attr].id,
                          attr[i_attr].type,
                          attr[i_attr].size);

                BTT_LOG_S(": ");
                attr_value = ((char *)btt_rsp->records) +
                             attr[i_attr].value_offset;
                for (i_data = 0;
                     i_data < attr[i_attr].size;
                     i_data += 1) {
                    BTT_LOG_S("%02x", attr_value[i_data]);
                }
                BTT_LOG_S("\n");
            }
        }
    }
#else
    if (use_generic) {
        BTT_LOG_S("Not supported for generic print without stack");
    } else {
        BTT_LOG_S("Not supported without stack");
    }
#endif
}

static void run_sdp_print_remote_records(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_print_remote_records  btt_msg;
    struct btt_msg_rsp_sdp_get_records          *btt_rsp;
    int verbose;

/* TODO: [public | all | record_handle <RECORD_HANDLE> | uuid <UUID16>] */
    if (argc <= 2) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    memset(&btt_msg, 0, sizeof(struct btt_msg_cmd_sdp_print_remote_records));

    sscanf(argv[1], "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            &btt_msg.bd_addr[0], &btt_msg.bd_addr[1], &btt_msg.bd_addr[2],
            &btt_msg.bd_addr[3], &btt_msg.bd_addr[4], &btt_msg.bd_addr[5]);

    if (strcmp(argv[2], "public") == 0) {
        btt_msg.type = PRINT_RECORDS_PUBLIC;
    } else if (strcmp(argv[2], "all") == 0) {
        btt_msg.type = PRINT_RECORDS_ALL;
    } else if (strcmp(argv[2], "record_handle") == 0) {
        btt_msg.type = PRINT_RECORDS_RECORD_HANDLE;

        if (argc < 4) {
            BTT_LOG_S("Error: Too few arguments\n");
            return;
        }

        btt_msg.data.record_handle = (uint32_t)strtoul(argv[3], NULL, 0);

        argc -= 1;
        argv += 1;
    } else if (strcmp(argv[2], "uuid") == 0) {
        btt_msg.type = PRINT_RECORDS_UUID;

        if (argc < 4) {
            BTT_LOG_S("Error: Too few arguments\n");
            return;
        }

        btt_msg.data.uuid = (uint16_t)strtoul(argv[3], NULL, 0);

        argc -= 1;
        argv += 1;
    } else {
        BTT_LOG_S("Unknown subcommand <%s>\n", argv[2]);
        return;
    }

    argc -= 2;
    argv += 2;

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    if (argc == 2) {
        if (strcmp(argv[1], "verbose") == 0) {
            verbose = TRUE;
        } else {
            BTT_LOG_S("Error: Unknown last argument\n");
            return;
        }
    }

    btt_msg.hdr.command = BTT_CMD_SDP_PRINT_REMOTE_RECORDS;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_print_remote_records) -
                          sizeof(struct btt_message);

    btt_rsp =
        (struct btt_msg_rsp_sdp_get_records *)btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    sdp_print_records(btt_rsp, verbose);
    free(btt_rsp);
}

static void run_sdp_print_records(int argc, char **argv)
{
    struct btt_message btt_msg;
    struct btt_msg_rsp_sdp_get_records *btt_rsp;
    int verbose;

    btt_msg.command = BTT_CMD_SDP_PRINT_RECORDS;
    btt_msg.length  = 0;

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    verbose = (argc == 2 && strcmp(argv[1], "verbose") == 0);

    btt_rsp =
        (struct btt_msg_rsp_sdp_get_records *)btt_send_command(&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    }

    sdp_print_records(btt_rsp, verbose);

    free(btt_rsp);
}

static void run_sdp_add_attribute(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_add_attribute *btt_msg;
    struct btt_message                   *btt_rsp;
    char num[3] = {0,0,0};
    unsigned int i = 0;
    int          i_arg;
    unsigned int i_char;
    unsigned int arg_length;
    int          type = -1;
    char const  *types[] = {
                            "NIL",
                            "UINT",
                            "INT",
                            "UUID",
                            "TEXT",
                            "BOOLEAN",
                            "SEQUENCE",
                            "ALTERNATIVE",
                            "URL"};

    if (argc <= 4) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    for (i_arg = 4; i_arg < argc; i_arg += 1) {
        arg_length = strlen(argv[i_arg]);
        for (i_char = 0; i_char < arg_length - 1; i_char += 2) {
            i += 1;
        }
    }

    btt_msg = (struct btt_msg_cmd_sdp_add_attribute *)malloc(
                  sizeof(struct btt_msg_cmd_sdp_add_attribute) + i);
    memset(btt_msg, 0, sizeof(struct btt_msg_cmd_sdp_add_attribute) + i);

    btt_msg->hdr.command = BTT_CMD_SDP_ADD_ATTRIBUTE;
    btt_msg->hdr.length  = sizeof(struct btt_msg_cmd_sdp_add_attribute) -
                           sizeof(struct btt_message) + i;
    btt_msg->length = i;
    btt_msg->handle = strtoul(argv[1], NULL, 0);
    btt_msg->attribute_id = strtoul(argv[2], NULL, 0);


    for (i = 0; i < sizeof(types)/sizeof(char *); i += 1) {
        if (strcmp(types[i], argv[3]) == 0)
            type = i;
    }

    if (type == -1)
        btt_msg->type = strtoul(argv[3], NULL, 0);
    else
        btt_msg->type = type;

    i = 0;
    for (i_arg = 4; i_arg < argc; i_arg += 1) {
        arg_length = strlen(argv[i_arg]);

        for (i_char = 0; i_char < arg_length - 1; i_char += 2) {
            num[0] = argv[i_arg][i_char];
            num[1] = argv[i_arg][i_char + 1];
            btt_msg->data[i] = (unsigned char)strtoul(num, NULL, 16);
            i += 1;
        }
    }

    btt_rsp =
        (struct btt_message *)btt_send_command((struct btt_message *)btt_msg);
    free(btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    } else {
        if (btt_rsp->command == BTT_RSP_OK) {
            BTT_LOG_S("Ok\n");
        } else {
            BTT_LOG_S("Error\n");
        }

        free(btt_rsp);
    }
}

static void run_sdp_delete_attribute(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_delete_attribute btt_msg;
    struct btt_message *btt_rsp;

    if (argc <= 2) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 3) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    btt_msg.handle       = strtoul(argv[1], NULL, 0);
    btt_msg.attribute_id = strtoul(argv[2], NULL, 0);

    btt_msg.hdr.command = BTT_CMD_SDP_DELETE_ATTRIBUTE;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_delete_attribute) -
                          sizeof(struct btt_message);

    btt_rsp =
        (struct btt_message *)btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    } else {
        if (btt_rsp->command == BTT_RSP_OK) {
            BTT_LOG_S("Ok\n");
        } else {
            BTT_LOG_S("Error\n");
        }

        free(btt_rsp);
    }
}

static void run_sdp_add_rfcomm_record(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_add_rfcomm_record btt_msg;
    struct btt_message *btt_rsp;

    static const uint8_t pbap_uuid[UUID_LEN] = { 0x00, 0x00, 0x11, 0x2F, 0x00, 0x00, 0x10, 0x00,
                          0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };
    static const uint8_t opp_uuid[UUID_LEN] = { 0x00, 0x00, 0x11, 0x05, 0x00, 0x00, 0x10, 0x00,
                          0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };
    static const uint8_t spp_uuid[UUID_LEN] = { 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00,
                          0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB };
    char                 num[3] = {0,0,0};
    unsigned int         length;

    if (argc <= 3) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    if (argc > 4) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    memset(&btt_msg, 0, sizeof(struct btt_msg_cmd_sdp_add_rfcomm_record));

    length = strlen(argv[1]);
    if (length > NAME_MAX_LEN) {
        length = NAME_MAX_LEN;
        BTT_LOG_S("Warning: Name length should be max %d bytes. Truncated.\n",
                  NAME_MAX_LEN);
    }

    strncpy(btt_msg.name, argv[1], length);

    if (strcmp(argv[2], "PBAP") == 0) {
        memcpy(btt_msg.uuid, pbap_uuid, UUID_LEN);
    } else if (strcmp(argv[2], "OPP") == 0) {
        memcpy(btt_msg.uuid, opp_uuid, UUID_LEN);
    } else if (strcmp(argv[2], "SPP") == 0) {
        memcpy(btt_msg.uuid, spp_uuid, UUID_LEN);
    } else {
        unsigned int i_char;

        /* Hexline UUID */
        memset(btt_msg.uuid, 0, UUID_LEN);

        length = strlen(argv[2]);
        if (length > UUID_LEN<<1) {
            BTT_LOG_S("Warning: UUID length should be max %d bytes. Truncated.\n",
                      UUID_LEN);
            length = UUID_LEN<<1;
        }
        for (i_char = 0; i_char < length; i_char += 2) {
            num[0] = argv[2][i_char];
            num[1] = argv[2][i_char + 1];
            btt_msg.uuid[i_char>>1] = strtoul(num, NULL, UUID_LEN);
        }
    }

    btt_msg.channel = (uint8_t)strtoul(argv[3], NULL, 0);

    btt_msg.hdr.command = BTT_CMD_SDP_ADD_RFCOMM_RECORD;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_add_rfcomm_record) -
                          sizeof(struct btt_message);

    btt_rsp =
        (struct btt_message *)btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    } else {
        if (btt_rsp->command == BTT_RSP_OK) {
            BTT_LOG_S("Ok\n");
        } else {
            BTT_LOG_S("Error\n");
        }

        free(btt_rsp);
    }
}

static void run_sdp_trace_level(int argc, char **argv)
{
    struct btt_msg_cmd_sdp_trace_level  btt_msg;
    struct btt_msg_rsp_sdp_trace_level *btt_rsp;

    if (argc > 2) {
        BTT_LOG_S("Error: Too many arguments\n");
        return;
    }

    btt_msg.hdr.command = BTT_CMD_SDP_TRACE_LEVEL;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_sdp_trace_level) -
                          sizeof(struct btt_message);
    if (argc == 1)
        btt_msg.level = 0xff;
    else
        btt_msg.level = strtoul(argv[1], NULL, 0);

    btt_rsp =
        (struct btt_msg_rsp_sdp_trace_level *)btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
        return;
    } else {
        if (btt_rsp->hdr.command == BTT_RSP_OK) {
            BTT_LOG_S("Ok\n");
        } else if (btt_rsp->hdr.command == BTT_RSP_SDP_TRACE_LEVEL) {
            BTT_LOG_S("%u\n", btt_rsp->level);
        } else {
            BTT_LOG_S("Error\n");
        }
    }

    free(btt_rsp);
}

