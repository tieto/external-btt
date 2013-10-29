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

#ifdef BTT_DAEMON_ADAPTER_H
    #error Included twince
#endif
#define BTT_DAEMON_ADAPTER_H

extern bool turning_on_adapter;
extern bool bonding_peer_dev;

extern void handle_adapter_cmd(const struct btt_message *btt_msg_adapter,
                               const int socket_remote);

