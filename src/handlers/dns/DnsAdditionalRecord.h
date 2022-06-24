/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "DnsResource.h"

namespace visor::handler::dns {

static constexpr size_t IPV6_BYTE_SIZE = 16;

enum OptEnum {
    CSUBNET = 8,
    COOKIE = 10,
};

// IANA Address Family Numbers
enum FamilyAddressEnum {
    RESERVED = 0,
    IPV4 = 1,
    IPV6 = 2,
};

struct __attribute__((__packed__)) DnsAdditionalOptCommon {
    uint16_t option_code;
    uint16_t option_length;
};

struct DnsAdditionalEcs {
    DnsAdditionalOptCommon common;
    uint16_t family;
    uint8_t source_netmask;
    uint8_t scope_netmask;
    std::string client_subnet;
};

static std::unique_ptr<DnsAdditionalEcs> parse_additional_records_ecs(DnsResource *additional)
{

    if (!additional || additional->getDnsType() != DnsType::DNS_TYPE_OPT || additional->getDataLength() == 0) {
        return nullptr;
    }

    size_t data_length = additional->getDataLength();
    size_t size = 0;
    std::unique_ptr<uint8_t[]> array(new uint8_t[data_length]);
    additional->getData()->toByteArr(array.get(), size, nullptr);

    // data should contain at least the standard fields size
    if (size != data_length || size < 9) {
        return nullptr;
    }

    // rfc6891
    uint8_t *iterator = array.get();
    std::unique_ptr<DnsAdditionalEcs> ecs = std::make_unique<DnsAdditionalEcs>();
    ecs->common.option_code = be16toh(static_cast<uint16_t>(iterator[1] << 8) | iterator[0]);
    if (ecs->common.option_code != OptEnum::CSUBNET) {
        return nullptr;
    }

    // rfc7871 - Option Format
    ecs->common.option_length = be16toh(static_cast<uint16_t>(iterator[3] << 8) | iterator[2]);
    ecs->family = be16toh(static_cast<uint16_t>(iterator[5] << 8) | iterator[4]);
    ecs->source_netmask = iterator[6];
    ecs->scope_netmask = iterator[7];
    size_t offset = 8;

    if (ecs->family == FamilyAddressEnum::IPV4) {
        char addrBuffer[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &iterator[offset], addrBuffer, sizeof(addrBuffer)) != NULL)
            ecs->client_subnet = addrBuffer;
    } else if (ecs->family == FamilyAddressEnum::IPV6) {
        char addrBuffer[INET6_ADDRSTRLEN];
        std::array<uint8_t, IPV6_BYTE_SIZE> ipv6 = {};
        for (auto i = offset; i < size; i++) {
            ipv6[i - offset] = iterator[i];
        }
        if (inet_ntop(AF_INET6, &ipv6, addrBuffer, sizeof(addrBuffer)) != NULL)
            ecs->client_subnet = addrBuffer;
    }

    return ecs;
}
} // namespace visor