/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PcapStreamHandler.h"
#include "GeoDB.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#pragma GCC diagnostic pop
#include <arpa/inet.h>
#include <cpc_union.hpp>

namespace visor::handler::pcap {

PcapStreamHandler::PcapStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, uint deepSampleRate)
    : visor::StreamMetricsHandler<PcapMetricsManager>(name, periods, deepSampleRate)
    , _stream(stream)
{
    assert(stream);
}

void PcapStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    _start_tstamp_connection = _stream->start_tstamp_signal.connect(&PcapStreamHandler::set_start_tstamp, this);
    _end_tstamp_connection = _stream->end_tstamp_signal.connect(&PcapStreamHandler::set_end_tstamp, this);

    _pcap_tcp_reassembly_errors_connection = _stream->tcp_reassembly_error_signal.connect(&PcapStreamHandler::process_pcap_tcp_reassembly_error, this);
    _pcap_stats_connection = _stream->pcap_stats_signal.connect(&PcapStreamHandler::process_pcap_stats, this);

    _running = true;
}

void PcapStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    _start_tstamp_connection.disconnect();
    _end_tstamp_connection.disconnect();
    _pcap_tcp_reassembly_errors_connection.disconnect();

    _running = false;
}

PcapStreamHandler::~PcapStreamHandler()
{
}

// callback from input module
void PcapStreamHandler::process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp)
{
    _metrics->process_pcap_tcp_reassembly_error(payload, dir, l3, stamp);
}
void PcapStreamHandler::process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats)
{
    _metrics->process_pcap_stats(stats);
}

void PcapStreamHandler::window_json(json &j, uint64_t period, bool merged)
{
    if (merged) {
        _metrics->window_merged_json(j, schema_key(), period);
    } else {
        _metrics->window_single_json(j, schema_key(), period);
    }
}
void PcapStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void PcapStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}
void PcapStreamHandler::info_json(json &j) const
{
    _common_info_json(j);
}
void PcapStreamHandler::window_prometheus(std::stringstream &out)
{
    if (_metrics->current_periods() > 1) {
        _metrics->window_single_prometheus(out, 1);
    } else {
        _metrics->window_single_prometheus(out, 0);
    }
}

void PcapMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const PcapMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.pcap_TCP_reassembly_errors += other._counters.pcap_TCP_reassembly_errors;
    _counters.pcap_os_drop += other._counters.pcap_os_drop;
    _counters.pcap_if_drop += other._counters.pcap_if_drop;
}

void PcapMetricsBucket::to_prometheus(std::stringstream &out) const
{
    std::shared_lock r_lock(_mutex);

    _counters.pcap_TCP_reassembly_errors.to_prometheus(out);
    _counters.pcap_os_drop.to_prometheus(out);
    _counters.pcap_if_drop.to_prometheus(out);
}

void PcapMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    _counters.pcap_TCP_reassembly_errors.to_json(j);
    _counters.pcap_os_drop.to_json(j);
    _counters.pcap_if_drop.to_json(j);
}

void PcapMetricsBucket::process_pcap_tcp_reassembly_error([[maybe_unused]] bool deep, [[maybe_unused]] pcpp::Packet &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3)
{
    std::unique_lock lock(_mutex);
    ++_counters.pcap_TCP_reassembly_errors;
}
void PcapMetricsBucket::process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats)
{
    std::unique_lock lock(_mutex);

    // pcap keeps monotonic counters, so at the start of every new bucket we have to record
    // the current pcap value and then keep track of differences.
    if (_counters.pcap_last_os_drop == std::numeric_limits<uint64_t>::max() || _counters.pcap_last_if_drop == std::numeric_limits<uint64_t>::max()) {
        _counters.pcap_last_os_drop = stats.packetsDrop;
        _counters.pcap_last_if_drop = stats.packetsDropByInterface;
        return;
    }
    if (stats.packetsDrop > _counters.pcap_last_os_drop) {
        _counters.pcap_os_drop += stats.packetsDrop - _counters.pcap_last_os_drop;
        _counters.pcap_last_os_drop = stats.packetsDrop;
    }
    if (stats.packetsDropByInterface > _counters.pcap_last_if_drop) {
        _counters.pcap_if_drop += stats.packetsDropByInterface - _counters.pcap_last_if_drop;
        _counters.pcap_last_if_drop = stats.packetsDropByInterface;
    }
}

// the general metrics manager entry point
void PcapMetricsManager::process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, [[maybe_unused]] timespec stamp)
{
    // process in the "live" bucket
    live_bucket()->process_pcap_tcp_reassembly_error(_deep_sampling_now, payload, dir, l3);
}
void PcapMetricsManager::process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats)
{
    // process in the "live" bucket
    live_bucket()->process_pcap_stats(stats);
}

}