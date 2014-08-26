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

#ifndef BTT_APPEARANCE_TYPE_H
#define BTT_APPEARANCE_TYPE_H

struct appearance {
	uint16_t key;
	char const *value;
};

static const struct appearance appearances_array[] = {
		{ 0, "Unknown"},
		{ 64, "Generic Phone"},
		{ 128, "Generic Computer"},
		{ 192, "Generic Watch"},
		{ 193, "Watch: Sports Watch"},
		{ 256, "Generic Clock"},
		{ 320, "Generic Display"},
		{ 384, "Generic Remote Control"},
		{ 448, "Generic Eye-glasses"},
		{ 512, "Generic Tag"},
		{ 576, "Generic Keyring"},
		{ 640, "Generic Media Player"},
		{ 704, "Generic Barcode Scanner"},
		{ 768, "Generic Thermometer"},
		{ 769, "Thermometer: Ear"},
		{ 832, "Generic Heart rate Sensor"},
		{ 833, "Heart Rate Sensor: Heart Rate Belt"},
		{ 896, "Generic Blood Pressure"},
		{ 897, "Blood Pressure: Arm"},
		{ 898, "Blood Pressure: Wrist"},
		{ 960, "Human Interface Device (HID)"},
		{ 961, "Keyboard"},
		{ 962, "Mouse"},
		{ 963, "Joystick"},
		{ 964, "Gamepad"},
		{ 965, "Digitizer"},
		{ 966, "Card Reader"},
		{ 967, "Digital Pen"},
		{ 968, "Barcode Scanner"},
		{ 1024, "Generic Glucose Meter"},
		{ 1088, "Generic: Running Walking Sensor"},
		{ 1089, "Running Walking Sensor: In-Shoe"},
		{ 1090, "Running Walking Sensor: On-Shoe"},
		{ 1091, "Running Walking Sensor: On-Hip"},
		{ 1152, "Generic: Cycling"},
		{ 1153, "Cycling: Cycling Computer"},
		{ 1154, "Cycling: Speed Sensor"},
		{ 1155, "Cycling: Cadence Sensor"},
		{ 1156, "Cycling: Power Sensor"},
		{ 1157, "Cycling: Speed and Cadence Sensor"},
		{ 3136, "Generic: Pulse Oximeter"},
		{ 3137, "Fingertip"},
		{ 3138, "Wrist Worn"},
		{ 3200, "Generic: Weight Scale"},
		{ 5184, "Generic: Outdoor Sports Activity"},
		{ 5185, "Location Display Device"},
		{ 5186, "Location and Navigation Display Device"},
		{ 5187, "Location Pod"},
		{ 5188, "Location and Navigation Pod"}
};

#endif
