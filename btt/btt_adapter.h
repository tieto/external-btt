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

#ifdef BTT_ADAPTER_H
    #error Included twice.
#endif
#define BTT_ADAPTER_H

enum btt_cb_t {
    /* ssp request callback type
     * struct btt_cb_adapter_ssp_request
     */
    BTT_ADAPTER_SSP_REQUEST = BTT_DAEMON_END + 1,
    /* device fount callback type
     * struct btt_cb_adapter_device_found
     */
    BTT_ADAPTER_DEVICE_FOUND,
    /* discovery state callback
     * struct btt_cb_adapter_discovery
     */
    BTT_ADAPTER_DISCOVERY,
    /* adapter address callback
     * struct btt_cb_adapter_addr
     */
    BTT_ADAPTER_ADDRESS,
    /* callback thread will send this
     * message to agent when adapter state changed
     * struct btt_cb_adapter_state
     */
    BTT_ADAPTER_STATE_CHANGED,
    /* cb thread will send it when scan mode changed
     * struct btt_cb_adapter_scan_mode
     */
    BTT_ADAPTER_SCAN_MODE_CHANGED,
    /* cb thread will send it when name requested
     * struct btt_cb_adapter_name
     */
    BTT_ADAPTER_NAME,
    /* pin request callback type
     * struct btt_cb_adapter_pin_request
     */
    BTT_ADAPTER_PIN_REQUEST,
    /* bond state changed callback type
     * struct btt_cb_adapter_bond_state_changed
     */
    BTT_ADAPTER_BOND_STATE_CHANGED,
    /* END OF ADAPTER MSG*/
    BTT_ADAPTER_END
};

struct btt_cb_hdr {
    enum btt_cb_t type;
    unsigned int  length;
};

struct btt_cb_adapter_pin_request {
    struct btt_cb_hdr hdr;

    unsigned int cod;
    char         name[NAME_MAX_LEN];
    uint8_t      bd_addr[BD_ADDR_LEN];
};

struct btt_cb_adapter_bond_state_changed {
    struct btt_cb_hdr hdr;

    bt_status_t     status;
    bt_bond_state_t state;
    uint8_t         bd_addr[BD_ADDR_LEN];
};

struct btt_cb_adapter_ssp_request {
    struct btt_cb_hdr hdr;

    unsigned int cod;
    unsigned int variant;
    uint8_t      bd_addr[BD_ADDR_LEN];
    char         name[NAME_MAX_LEN];
    unsigned int passkey;
};

struct btt_cb_adapter_state {
    struct btt_cb_hdr hdr;

    bool state;
};

struct btt_cb_adapter_scan_mode_changed {
    struct btt_cb_hdr hdr;

    /* mode:
     * 0 - NONE
     * 1 - CONNECTABLE
     * 2 - CONNECTABLE & DISCOVERABLE
     */
    int mode;
};

struct btt_cb_adapter_name {
    struct btt_cb_hdr hdr;

    char name[NAME_MAX_LEN];
};

struct btt_cb_adapter_addr {
    struct btt_cb_hdr hdr;

    uint8_t bd_addr[BD_ADDR_LEN];
};

struct btt_cb_adapter_device_found {
    struct btt_cb_hdr hdr;

    uint8_t bd_addr[BD_ADDR_LEN];
    char    name[NAME_MAX_LEN];
    int     cod;
};

struct btt_cb_adapter_discovery {
    struct btt_cb_hdr hdr;

    bool state;
};

extern void run_adapter(int argc, char **argv);
extern const struct command *btt_adapter_commands;

