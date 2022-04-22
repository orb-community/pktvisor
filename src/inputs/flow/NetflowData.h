/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "EndianPortable.h"
#include <netflow.h>
#include <vector>

namespace visor::input::flow {

struct NFSample {
    /* the raw pdu */
    uint8_t *raw_sample;
    uint32_t raw_sample_len;

    /* common header */
    uint16_t version;
    uint16_t nflows;

    /* most common header */
    uint32_t uptime_ms;
    uint32_t time_sec;
    uint32_t time_nanosec;
    uint32_t flow_sequence;
    uint32_t package_sequence;
    uint32_t source_id;

    struct __attribute__((__packed__)) Flows {
        uint32_t src_ip, dst_ip, gateway_ip;
        uint16_t if_index_in, if_index_out;
        uint32_t flow_packets, flow_octets;
        uint32_t flow_start, flow_finish;
        uint16_t src_port, dst_port;
        uint8_t protocol, tos, tcp_flags;
    } f;
    std::vector<Flows> flows;
};

static bool process_netflow_v1(NFSample *sample)
{
    struct NF1_HEADER *nf1_hdr = reinterpret_cast<struct NF1_HEADER *>(sample->raw_sample);
    struct NF1_FLOW *nf1_flow;
    size_t offset;

    if (sample->raw_sample_len < sizeof(*nf1_hdr)) {
        return false;
    }
    sample->nflows = be16toh(nf1_hdr->c.flows);
    if (sample->nflows == 0 || sample->nflows > NF1_MAXFLOWS || sample->raw_sample_len != NF1_PACKET_SIZE(sample->nflows)) {
        return false;
    }

    sample->uptime_ms = nf1_hdr->uptime_ms;
    sample->time_sec = nf1_hdr->time_sec;
    sample->time_nanosec = nf1_hdr->time_nanosec;

    for (uint16_t flow = 0; flow < sample->nflows; flow++) {
        offset = NF1_PACKET_SIZE(flow);
        nf1_flow = (struct NF1_FLOW *)(sample->raw_sample + offset);
        NFSample::Flows flow_sample;

        flow_sample.tcp_flags = nf1_flow->tcp_flags;
        flow_sample.protocol = nf1_flow->protocol;
        flow_sample.tos = nf1_flow->tos;

        flow_sample.src_ip = nf1_flow->src_ip;
        flow_sample.dst_ip = nf1_flow->dest_ip;
        flow_sample.gateway_ip = nf1_flow->nexthop_ip;

        flow_sample.src_port = nf1_flow->src_port;
        flow_sample.dst_port = nf1_flow->dest_port;

        flow_sample.flow_start = nf1_flow->flow_start;
        flow_sample.flow_finish = nf1_flow->flow_finish;

        flow_sample.if_index_in = htobe32(be16toh(nf1_flow->if_index_in));
        flow_sample.if_index_out = htobe32(be16toh(nf1_flow->if_index_out));
        flow_sample.flow_octets = be32toh(nf1_flow->flow_octets);
        flow_sample.flow_packets = be32toh(nf1_flow->flow_packets);

        sample->flows.push_back(flow_sample);
    }

    return true;
}

static bool process_netflow_v5(NFSample *sample)
{
    struct NF5_HEADER *nf5_hdr = reinterpret_cast<struct NF5_HEADER *>(sample->raw_sample);
    struct NF5_FLOW *nf5_flow;
    size_t offset;

    if (sample->raw_sample_len < sizeof(*nf5_hdr)) {
        return false;
    }
    sample->nflows = be16toh(nf5_hdr->c.flows);
    if (sample->nflows == 0 || sample->nflows > NF5_MAXFLOWS || sample->raw_sample_len != NF5_PACKET_SIZE(sample->nflows)) {
        return false;
    }

    sample->uptime_ms = nf5_hdr->uptime_ms;
    sample->time_sec = nf5_hdr->time_sec;
    sample->time_nanosec = nf5_hdr->time_nanosec;
    sample->flow_sequence = nf5_hdr->flow_sequence;

    for (uint16_t flow = 0; flow < sample->nflows; flow++) {
        offset = NF5_PACKET_SIZE(flow);
        nf5_flow = reinterpret_cast<struct NF5_FLOW *>(sample->raw_sample + offset);
        NFSample::Flows flow_sample;

        flow_sample.tcp_flags = nf5_flow->tcp_flags;
        flow_sample.protocol = nf5_flow->protocol;
        flow_sample.tos = nf5_flow->tos;

        flow_sample.src_ip = nf5_flow->src_ip;
        flow_sample.dst_ip = nf5_flow->dest_ip;
        flow_sample.gateway_ip = nf5_flow->nexthop_ip;

        flow_sample.src_port = nf5_flow->src_port;
        flow_sample.dst_port = nf5_flow->dest_port;

        flow_sample.flow_start = nf5_flow->flow_start;
        flow_sample.flow_finish = nf5_flow->flow_finish;

        flow_sample.if_index_in = htobe32(be16toh(nf5_flow->if_index_in));
        flow_sample.if_index_out = htobe32(be16toh(nf5_flow->if_index_out));
        flow_sample.flow_octets = be32toh(nf5_flow->flow_octets);
        flow_sample.flow_packets = be32toh(nf5_flow->flow_packets);

        sample->flows.push_back(flow_sample);
    }

    return true;
}

static bool process_netflow_v7(NFSample *sample)
{
    struct NF7_HEADER *nf7_hdr = reinterpret_cast<struct NF7_HEADER *>(sample->raw_sample);
    struct NF7_FLOW *nf7_flow;
    size_t offset;

    if (sample->raw_sample_len < sizeof(*nf7_hdr)) {
        return false;
    }
    sample->nflows = be16toh(nf7_hdr->c.flows);
    if (sample->nflows == 0 || sample->nflows > NF7_MAXFLOWS || sample->raw_sample_len != NF7_PACKET_SIZE(sample->nflows)) {
        return false;
    }

    sample->uptime_ms = nf7_hdr->uptime_ms;
    sample->time_sec = nf7_hdr->time_sec;
    sample->time_nanosec = nf7_hdr->time_nanosec;
    sample->flow_sequence = nf7_hdr->flow_sequence;

    for (uint16_t flow = 0; flow < sample->nflows; flow++) {
        offset = NF7_PACKET_SIZE(flow);
        nf7_flow = reinterpret_cast<struct NF7_FLOW *>(sample->raw_sample + offset);
        NFSample::Flows flow_sample;

        flow_sample.tcp_flags = nf7_flow->tcp_flags;
        flow_sample.protocol = nf7_flow->protocol;
        flow_sample.tos = nf7_flow->tos;

        flow_sample.src_ip = nf7_flow->src_ip;
        flow_sample.dst_ip = nf7_flow->dest_ip;
        flow_sample.gateway_ip = nf7_flow->nexthop_ip;

        flow_sample.src_port = nf7_flow->src_port;
        flow_sample.dst_port = nf7_flow->dest_port;

        flow_sample.flow_start = nf7_flow->flow_start;
        flow_sample.flow_finish = nf7_flow->flow_finish;

        flow_sample.if_index_in = htobe32(be16toh(nf7_flow->if_index_in));
        flow_sample.if_index_out = htobe32(be16toh(nf7_flow->if_index_out));
        flow_sample.flow_octets = be32toh(nf7_flow->flow_octets);
        flow_sample.flow_packets = be32toh(nf7_flow->flow_packets);

        sample->flows.push_back(flow_sample);
    }

    return true;
}

static bool process_netflow_v9_template(u_int8_t *pkt, size_t len, u_int32_t source_id, std::vector<peer_nf9_template> *templates)
{
    struct NF9_FLOWSET_HEADER_COMMON *template_header;
    struct NF9_TEMPLATE_FLOWSET_HEADER *tmplh;
    struct NF9_TEMPLATE_FLOWSET_RECORD *tmplr;
    uint32_t i, count, offset, template_id, total_size;
    peer_nf9_template nf9_template;

    template_header = (struct NF9_FLOWSET_HEADER_COMMON *)pkt;
    if (len < sizeof(*template_header)) {
        return false;
    }

    if (be16toh(template_header->flowset_id) != NF9_TEMPLATE_FLOWSET_ID) {
        return false;
    }

    for (offset = sizeof(*template_header); offset < len;) {
        tmplh = reinterpret_cast<struct NF9_TEMPLATE_FLOWSET_HEADER *>(pkt + offset);

        template_id = be16toh(tmplh->template_id);
        count = be16toh(tmplh->count);
        offset += sizeof(*tmplh);

        total_size = 0;
        std::vector<peer_nf9_record> template_recs;
        for (i = 0; i < count; i++) {
            if (offset >= len) {
                break;
            }

            uint32_t rec_length = be16toh(tmplr->length);

            tmplr = (struct NF9_TEMPLATE_FLOWSET_RECORD *)(pkt + offset);
            peer_nf9_record recs(be16toh(tmplr->type), rec_length);
            offset += sizeof(*tmplr);

            total_size += rec_length;
        }
        nf9_template.template_id = template_id;
        nf9_template.template_id = source_id;
        nf9_template.num_records = count;
        nf9_template.records = template_recs;
        nf9_template.num_records = i;
        nf9_template.total_len += total_size;

        templates->push_back(nf9_template);
    }

    return true;
}

static inline void be_copy(uint8_t *data, uint8_t *target, uint32_t target_length, uint32_t rec_length)
{
    if (target_length < rec_length) {
        return;
    }
    memcpy(target + (target_length - rec_length), data, rec_length);
}

static int nf9_rec_to_flow(NFSample::Flows *flow, struct peer_nf9_record *rec, uint8_t *data)
{
    /* XXX: use a table-based interpreter */
    switch (rec->type) {

#define V9_FIELD(v9_field, target, target_length)                                    \
    case v9_field:                                                                   \
        be_copy(data, reinterpret_cast<uint8_t *>(target), target_length, rec->len); \
        break

        V9_FIELD(NF9_IN_BYTES, &flow->flow_octets, sizeof(flow->flow_octets));
        V9_FIELD(NF9_IN_PACKETS, &flow->flow_packets, sizeof(flow->flow_octets));
        V9_FIELD(NF9_IN_PROTOCOL, &flow->protocol, sizeof(flow->protocol));
        V9_FIELD(NF9_SRC_TOS, &flow->tos, sizeof(flow->tos));
        V9_FIELD(NF9_TCP_FLAGS, &flow->tcp_flags, sizeof(flow->tcp_flags));
        V9_FIELD(NF9_L4_SRC_PORT, &flow->src_port, sizeof(flow->src_port));
        // V9_FIELD(NF9_SRC_MASK, &flow->src_mask, sizeof(flow->src_mask));
        V9_FIELD(NF9_INPUT_SNMP, &flow->if_index_in, sizeof(flow->if_index_in));
        V9_FIELD(NF9_L4_DST_PORT, &flow->dst_port, sizeof(flow->dst_port));
        // V9_FIELD(NF9_DST_MASK, &flow->dst_mask, sizeof(flow->dst_mask));
        V9_FIELD(NF9_OUTPUT_SNMP, &flow->if_index_out, sizeof(flow->if_index_out));
        // V9_FIELD(NF9_SRC_AS, AS_INFO, asinf.src_as);
        // V9_FIELD(NF9_DST_AS, AS_INFO, asinf.dst_as);
        V9_FIELD(NF9_LAST_SWITCHED, &flow->flow_finish, sizeof(flow->flow_finish));
        V9_FIELD(NF9_FIRST_SWITCHED, &flow->flow_start, sizeof(flow->flow_start));
        // V9_FIELD(NF9_IPV6_SRC_MASK, AS_INFO, asinf.src_mask);
        // V9_FIELD(NF9_IPV6_DST_MASK, AS_INFO, asinf.dst_mask);
        // V9_FIELD(NF9_ENGINE_TYPE, FLOW_ENGINE_INFO, finf.engine_type);
        // V9_FIELD(NF9_ENGINE_ID, FLOW_ENGINE_INFO, finf.engine_id);
        V9_FIELD(NF9_IPV4_SRC_ADDR, &flow->src_ip, sizeof(flow->src_ip));
        V9_FIELD(NF9_IPV6_SRC_ADDR, &flow->src_ip, sizeof(flow->src_ip));
        V9_FIELD(NF9_IPV4_DST_ADDR, &flow->dst_ip, sizeof(flow->dst_ip));
        V9_FIELD(NF9_IPV6_DST_ADDR, &flow->dst_ip, sizeof(flow->dst_ip));
        V9_FIELD(NF9_IPV4_NEXT_HOP, &flow->gateway_ip, sizeof(flow->gateway_ip));
        V9_FIELD(NF9_IPV6_NEXT_HOP, &flow->gateway_ip, sizeof(flow->gateway_ip));

#undef V9_FIELD
    }
    return (0);
}

static bool process_netflow_v9_data(std::vector<NFSample::Flows> *flows, uint8_t *pkt, size_t len, uint32_t source_id, struct NF9_HEADER *nf9_hdr, uint32_t *num_flows, std::vector<peer_nf9_template> *templates)
{
    struct peer_nf9_template *templates1;
    struct NF9_DATA_FLOWSET_HEADER *dath;
    uint16_t flowset_id, i, offset, num_flowsets;

    if (templates->empty()) {
        return false;
    }

    *num_flows = 0;

    dath = (struct NF9_DATA_FLOWSET_HEADER *)pkt;
    if (len < sizeof(*dath)) {
        return false;
    }

    flowset_id = be16toh(dath->c.flowset_id);

    auto nf9_template = templates->rbegin();
    for (auto it = templates->rbegin(); it != templates->rend(); ++it) {
        if (it->template_id == flowset_id && it->source_id == source_id) {
            nf9_template = it;
            break;
        }
    }

    if (nf9_template == templates->rbegin()) {
        return true;
    }

    if (nf9_template->records.empty()) {
        return false;
    }

    offset = sizeof(*dath);
    num_flowsets = (len - offset) / nf9_template->total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        return false;
    }

    for (i = 0; i < num_flowsets; i++) {
        uint32_t offset_recs = 0;
        NFSample::Flows flow;
        for (i = 0; i < nf9_template->num_records; i++) {
            nf9_rec_to_flow(&flow, &nf9_template->records[i], pkt + offset);
            offset_recs += nf9_template->records[i].len;
        }
        flows->push_back(flow);
        offset += nf9_template->total_len;
    }

    *num_flows = i;

    return true;
}

static bool process_netflow_v9(NFSample *sample)
{
    struct NF9_HEADER *nf9_hdr = reinterpret_cast<struct NF9_HEADER *>(sample->raw_sample);

    if (sample->raw_sample_len < sizeof(*nf9_hdr)) {
        return false;
    }
    struct NF9_FLOWSET_HEADER_COMMON *flowset;
    uint32_t i, flowset_id, flowset_len, flowset_flows;
    uint32_t offset, total_flows;

    sample->uptime_ms = nf9_hdr->uptime_ms;
    sample->time_sec = nf9_hdr->time_sec;
    sample->package_sequence = nf9_hdr->package_sequence;
    sample->source_id = be32toh(nf9_hdr->source_id);

    offset = sizeof(*nf9_hdr);
    total_flows = 0;

    std::vector<peer_nf9_template> templates;
    std::vector<NFSample::Flows> flows;
    for (i = 0;; i++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= sample->raw_sample_len) {
            break;
        }

        flowset = reinterpret_cast<struct NF9_FLOWSET_HEADER_COMMON *>(sample->raw_sample + offset);
        flowset_id = be16toh(flowset->flowset_id);
        flowset_len = be16toh(flowset->length);

        /* Make sure we don't run off the end of the flow */
        if (offset + flowset_len > sample->raw_sample_len) {
            break;
        }

        switch (flowset_id) {
        case NF9_TEMPLATE_FLOWSET_ID:
            if (!process_netflow_v9_template(sample->raw_sample + offset, flowset_len, sample->source_id, &templates)) {
                return false;
            }
            break;
        case NF9_OPTIONS_FLOWSET_ID:
            /* XXX: implement this (maybe) */
            break;
        default:
            if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                /* XXX ratelimit */
                break;
            }
            if (!process_netflow_v9_data(&flows, sample->raw_sample + offset, flowset_len, sample->source_id, nf9_hdr, &flowset_flows, &templates)) {
                return false;
            }
            total_flows += flowset_flows;
            break;
        }
        offset += flowset_len;
        if (offset == sample->raw_sample_len)
            break;
        /* XXX check header->count against what we got */
    }

    sample->flows = flows;

    if (total_flows > 0) {
        return true;
    }
    return false;
}

static bool process_netflow_v10(NFSample *sample)
{
    return false;
}

static bool process_netflow_packet(NFSample *sample)
{
    struct NF_HEADER_COMMON *hdr = reinterpret_cast<struct NF_HEADER_COMMON *>(sample->raw_sample);
    sample->version = be16toh(hdr->version);

    std::cerr << sample->version << '\n';

    switch (sample->version) {
    case 1:
        return process_netflow_v1(sample);
    case 5:
        return process_netflow_v5(sample);
    case 7:
        return process_netflow_v7(sample);
    case 9:
        return process_netflow_v9(sample);
    case 10:
        return process_netflow_v10(sample);
    default:
        return false;
    }
}
}