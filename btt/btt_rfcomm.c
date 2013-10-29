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
#include "btt_rfcomm.h"
#include "btt_utils.h"

static void run_rfcomm_help(int argc, char **argv);

static const struct command rfcomm_commands[] = {
    { "help",                   "",                       run_rfcomm_help     },
    { "connect",                "NOT IMPLEMENTED YET <BD_ADDR>",              NULL    },
    { "send",                   "NOT IMPLEMENTED YET <HANDLE> <HEXLINES...>", NULL       },
    { "receive",                "NOT IMPLEMENTED YET <HANDLE> <print | print_all | check [HEXLINES...] | wait [HEXLINES...]>", NULL },
    { "disconnect",             "NOT IMPLEMENTED YET <HANDLE>",               NULL },
};

#define RFCOMM_SUPPORTED_COMMANDS sizeof(rfcomm_commands)/sizeof(struct command)

void run_rfcomm(int argc, char **argv)
{
    run_generic(rfcomm_commands, RFCOMM_SUPPORTED_COMMANDS,
                run_rfcomm_help, argc, argv);
}

void run_rfcomm_help(int argc, char **argv)
{
    print_commands(rfcomm_commands, RFCOMM_SUPPORTED_COMMANDS);
    exit(EXIT_SUCCESS);
}

