/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "DhcpLayer.h"
#include "PcapInputStream.h"
#include "RequestAckManager.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <limits>
#include <string>

namespace visor::handler::dhcp {

using namespace visor::input::pcap;

static constexpr const char *DHCP_SCHEMA{"dhcp"};

class DhcpMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    TopN<std::string> _dhcp_clients;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter DISCOVER;
        Counter OFFER;
        Counter REQUEST;
        Counter ACK;
        Counter total;
        Counter filtered;

        counters()
            : DISCOVER(DHCP_SCHEMA, {"wire_packets", "discover"}, "Total DHCP packets with message type DISCOVER")
            , OFFER(DHCP_SCHEMA, {"wire_packets", "offer"}, "Total DHCP packets with message type OFFER")
            , REQUEST(DHCP_SCHEMA, {"wire_packets", "request"}, "Total DHCP packets with message type REQUEST")
            , ACK(DHCP_SCHEMA, {"wire_packets", "ack"}, "Total DHCP packets with message type ACK")
            , total(DHCP_SCHEMA, {"wire_packets", "total"}, "Total DHCP wire packets matching the configured filter(s)")
            , filtered(DHCP_SCHEMA, {"wire_packets", "filtered"}, "Total DHCP wire packets seen that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;
    Rate _rate_total;

public:
    DhcpMetricsBucket()
        : _dhcp_clients(DHCP_SCHEMA, "client", {"top_clients"}, "Top DHCP clients")
        , _rate_total(DHCP_SCHEMA, {"rates", "total"}, "Rate of all DHCP wire packets (combined ingress and egress) in packets per second")
    {
        set_event_rate_info(DHCP_SCHEMA, {"rates", "events"}, "Rate of all DHCP wire packets before filtering per second");
        set_num_events_info(DHCP_SCHEMA, {"wire_packets", "events"}, "Total DHCP wire packets events");
        set_num_sample_info(DHCP_SCHEMA, {"wire_packets", "deep_samples"}, "Total DHCP wire packets that were sampled for deep inspection");
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
    void update_topn_metrics(size_t, uint64_t) override
    {
    }

    void on_set_read_only() override
    {
        // stop rate collection
        _rate_total.cancel();
    }

    void process_filtered();
    void process_dhcp_layer(bool deep, pcpp::DhcpLayer *payload);
    void new_dhcp_transaction(bool deep, pcpp::DhcpLayer *payload, DhcpTransaction &xact);
};

class DhcpMetricsManager final : public visor::AbstractMetricsManager<DhcpMetricsBucket>
{
    RequestAckManager _request_ack_manager;

public:
    DhcpMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DhcpMetricsBucket>(window_config)
    {
    }

    void on_period_shift(timespec stamp, [[maybe_unused]] const DhcpMetricsBucket *maybe_expiring_bucket) override
    {
        // Dhcp transaction support
        _request_ack_manager.purge_old_transactions(stamp);
    }

    void process_filtered(timespec stamp);
    void process_dhcp_layer(pcpp::DhcpLayer *payload, PacketDirection dir, uint32_t flowkey, timespec stamp);
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

    bool _filtering(pcpp::DhcpLayer *payload, PacketDirection dir, timespec stamp);

public:
    DhcpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~DhcpStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return DHCP_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
