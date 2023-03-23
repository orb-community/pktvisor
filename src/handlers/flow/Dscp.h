/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <unordered_map>
namespace visor::handler::flow {

static std::unordered_map<uint8_t, std::string> DscpNames({
    {0, "CS0"},
    {8, "CS1"},
    {16, "CS2"},
    {24, "CS3"},
    {32, "CS4"},
    {40, "CS5"},
    {48, "CS6"},
    {56, "CS7"},
    {10, "AF11"},
    {12, "AF12"},
    {14, "AF13"},
    {18, "AF21"},
    {20, "AF22"},
    {22, "AF23"},
    {26, "AF31"},
    {28, "AF32"},
    {30, "AF33"},
    {34, "AF41"},
    {36, "AF42"},
    {38, "AF43"},
    {46, "EF"},
    {43, "VOICE-ADMIT"},
});

static std::unordered_map<std::string, uint8_t> DscpNumbers({
    {"CS0", 0},
    {"CS1", 8},
    {"CS2", 16},
    {"CS3", 24},
    {"CS4", 32},
    {"CS5", 40},
    {"CS6", 48},
    {"CS7", 56},
    {"AF11", 10},
    {"AF12", 12},
    {"AF13", 14},
    {"AF21", 18},
    {"AF22", 20},
    {"AF23", 22},
    {"AF31", 26},
    {"AF32", 28},
    {"AF33", 30},
    {"AF41", 34},
    {"AF42", 36},
    {"AF43", 38},
    {"EF", 46},
    {"VOICE-ADMIT", 43},
});
}