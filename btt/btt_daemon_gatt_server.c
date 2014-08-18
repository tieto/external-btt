/*
 * Copyright 2014 Tieto Corporation
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
#include "btt_daemon_gatt_server.h"

#include <hardware/bt_gatt.h>

void handle_gatt_server_cmd(const struct btt_message *btt_msg,
		const int socket_remote)
{
	switch (btt_msg->command)
	default: break;
}

/*************************************************************/
/* Gatt server: callbacks, necessary functions and structure */
/*************************************************************/

static btgatt_server_callbacks_t sGattServerCallbacks = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
};

btgatt_server_callbacks_t *getGattServerCallbacks(void)
{
	return &sGattServerCallbacks;
}
