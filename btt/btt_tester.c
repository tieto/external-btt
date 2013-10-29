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
#include "btt_tester.h"
#include "btt_utils.h"

static void run_tester_help(int argc, char **argv);
static void run_tester_dump(int argc, char **argv);

static const struct command tester_commands[] = {
    { "help",                   "",                       run_tester_help     },
    { "dump",  "<stop | FILE <NAME> | SOCKET <NAME>>",    run_tester_dump     },
};

#define TESTER_SUPPORTED_COMMANDS sizeof(tester_commands)/sizeof(struct command)

void run_tester(int argc, char **argv)
{
    run_generic(tester_commands, TESTER_SUPPORTED_COMMANDS,
                run_tester_help, argc, argv);
}

static void run_tester_help(int argc, char **argv)
{
    print_commands(tester_commands, TESTER_SUPPORTED_COMMANDS);
    exit(EXIT_SUCCESS);
}

static void run_tester_dump(int argc, char **argv)
{
    struct btt_msg_cmd_tester_dump btt_msg;
    struct btt_message            *btt_rsp;

    if (argc <= 1) {
        BTT_LOG_S("Error: Too few arguments\n");
        return;
    }

    memset(&btt_msg, 0, sizeof(struct btt_msg_cmd_tester_dump));

    btt_msg.hdr.command = BTT_CMD_TESTER_DUMP;
    btt_msg.hdr.length  = sizeof(struct btt_msg_cmd_tester_dump) -
                          sizeof(struct btt_message);
    btt_msg.name[0] = '\0';

    if (strcmp("stop", argv[1]) == 0) {
        btt_msg.type = DUMP_TYPE_STOP;
    } else if (argc > 2) {
        if (strcmp("FILE", argv[1]) == 0)
            btt_msg.type = DUMP_TYPE_FILE;
        else if (strcmp("SOCKET", argv[1]) == 0)
            btt_msg.type = DUMP_TYPE_SOCKET;

        if (argc <= 2) {
            BTT_LOG_S("Error: Too few arguments\n");
            return;
        }

        if (strlen(argv[2]) > NAME_MAX_LEN) {
            BTT_LOG_S("Error: Filename is longer than %d\n", NAME_MAX_LEN);
            return;
        }

        strcpy(btt_msg.name, argv[2]);
    } else {
        BTT_LOG_S("Error: Unknown subcommand: <%s>\n", argv[1]);
        return;
    }

    btt_rsp =
        (struct btt_message *)btt_send_command((struct btt_message *)&btt_msg);
    if (!btt_rsp) {
        BTT_LOG_S("Error: no reply\n");
    } else {
        if (btt_rsp->command == BTT_RSP_OK) {
            BTT_LOG_S("Ok\n");
        } else {
            BTT_LOG_S("Error\n");
        }

        free(btt_rsp);
    }
}

