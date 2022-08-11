/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "DhcpLayer.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <limits>
#include <string>

namespace visor::handler::dhcp {

using namespace visor::input::pcap;

class DhcpMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter DISCOVER;
        Counter OFFER;
        Counter REQUEST;
        Counter ACK;
        Counter total;
        Counter filtered;

        counters()
            : DISCOVER("dhcp", {"wire_packets", "discover"}, "Total DHCP packets with message type DISCOVER")
            , OFFER("dhcp", {"wire_packets", "offer"}, "Total DHCP packets with message type OFFER")
            , REQUEST("dhcp", {"wire_packets", "request"}, "Total DHCP packets with message type REQUEST")
            , ACK("dhcp", {"wire_packets", "ack"}, "Total DHCP packets with message type ACK")
            , total("dhcp", {"wire_packets", "total"}, "Total DHCP wire packets seen that match the configured filter(s)")
            , filtered("dhcp", {"wire_packets", "filtered"}, "Total DHCP wire packets seen that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;

public:
    DhcpMetricsBucket()
    {
        set_event_rate_info("dhcp", {"rates", "total"}, "Rate of all DHCP wire packets (combined ingress and egress) per second");
        set_num_events_info("dhcp", {"wire_packets", "events"}, "Total DHCP wire packets events");
        set_num_sample_info("dhcp", {"wire_packets", "deep_samples"}, "Total DHCP wire packets that were sampled for deep inspection");
    }

    // get a copy of the counters
    counters counters() const
    {
        std::shared_lock lock(_mutex);
        return _counters;
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t) override
    {
    }

    void process_filtered();
    void process_dhcp_layer(bool deep, pcpp::DhcpLayer *payload, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t src_port, uint16_t dst_port);
};

class DhcpMetricsManager final : public visor::AbstractMetricsManager<DhcpMetricsBucket>
{
public:
    DhcpMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DhcpMetricsBucket>(window_config)
    {
    }

    void process_filtered(timespec stamp);
    void process_dhcp_layer(pcpp::DhcpLayer *payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t src_port, uint16_t dst_port, timespec stamp);
};

class DhcpStreamHandler final : public visor::StreamMetricsHandler<DhcpMetricsManager>
{

    PcapInputEventProxy *_pcap_proxy;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _heartbeat_connection;

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);

    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    bool _filtering(pcpp::DhcpLayer *payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t src_port, uint16_t dst_port, timespec stamp);

public:
    DhcpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~DhcpStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "dhcp";
    }

    size_t consumer_count() const override
    {
        return 0;
    }

    void start() override;
    void stop() override;
};

}
