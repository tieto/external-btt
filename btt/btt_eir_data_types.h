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

/*EIR and Advertising Data Type constant defines*/

#ifndef EIR_DATA_TYPES_H
#define EIR_DATA_TYPES_H

#define FLAGS 0x01
#define INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS 0x02
#define COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS 0x03
#define INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS 0x04
#define COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS 0x05
#define INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS 0x06
#define COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS 0x07
#define SHORTENED_LOCAL_NAME 0x08
#define COMPLETE_LOCAL_NAME 0x09
#define TX_POWER_LEVEL 0x0A
#define CLASS_OF_DEVICE 0x0D
#define SIMPLE_PAIRING_HASH_C 0x0E
#define SIMPLE_PAIRING_HASH_C_192 0x0E
#define SIMPLE_PAIRING_RANDOMIZER_R 0x0F
#define SIMPLE_PAIRING_RANDOMIZER_R_192 0x0F
#define DEVICE_ID 0x10
#define SECURITY_MANAGER_TK_VALUE 0x10
#define SECURITY_MANAGER_OUT_OF_BAND_FLAGS 0x11
#define SLAVE_CONNECTION_INTERVAL_RANGE 0x12
#define LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS 0x14
#define LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS 0x1F
#define LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS 0x15
#define SERVICE_DATA 0x16
#define SERVICE_DATA_16_BIT_UUID 0x16
#define SERVICE_DATA_32_BIT_UUID 0x20
#define SERVICE_DATA_128_BIT_UUID 0x21
#define PUBLIC_TARGET_ADDRESS 0x17
#define RANDOM_TARGET_ADDRESS 0x18
#define APPEARANCE 0x19
#define ADVERTISING_INTERVAL 0x1A
#define LE_BLUETOOTH_DEVICE_ADDRESS 0x1B
#define LE_ROLE 0x1C
#define SIMPLE_PAIRING_HASH_C_256 0x1D
#define SIMPLE_PAIRING_RANDOMIZER_R_256 0x1E
#define _3D_INFORMATION_DATA 0x3D
#define MANUFACTURER_SPECIFIC_DATA 0xFF

#endif
