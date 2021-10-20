/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DhcpStreamHandler.h"

namespace visor::handler::dhcp {

DhcpStreamHandler::DhcpStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config)
    : visor::StreamMetricsHandler<DhcpMetricsManager>(name, window_config)
{
    assert(stream);
    // figure out which input stream we have
    _pcap_stream = dynamic_cast<PcapInputStream *>(stream);
    if (!_pcap_stream) {
        throw StreamHandlerException(fmt::format("DhcpStreamHandler: unsupported input stream {}", stream->name()));
    }
}

void DhcpStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    _start_tstamp_connection = _pcap_stream->start_tstamp_signal.connect(&DhcpStreamHandler::set_start_tstamp, this);
    _end_tstamp_connection = _pcap_stream->end_tstamp_signal.connect(&DhcpStreamHandler::set_end_tstamp, this);

    _dhcp_tcp_reassembly_errors_connection = _pcap_stream->tcp_reassembly_error_signal.connect(&DhcpStreamHandler::process_dhcp_tcp_reassembly_error, this);
    _dhcp_stats_connection = _pcap_stream->dhcp_stats_signal.connect(&DhcpStreamHandler::process_dhcp_stats, this);

    _running = true;
}

void DhcpStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    _start_tstamp_connection.disconnect();
    _end_tstamp_connection.disconnect();
    _dhcp_tcp_reassembly_errors_connection.disconnect();

    _running = false;
}

// callback from input module
void DhcpStreamHandler::process_dhcp_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp)
{
    _metrics->process_dhcp_tcp_reassembly_error(payload, dir, l3, stamp);
}
void DhcpStreamHandler::process_dhcp_stats(const pcpp::IDhcpDevice::DhcpStats &stats)
{
    _metrics->process_dhcp_stats(stats);
}
void DhcpStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void DhcpStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void DhcpMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DhcpMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.dhcp_TCP_reassembly_errors += other._counters.dhcp_TCP_reassembly_errors;
    _counters.dhcp_os_drop += other._counters.dhcp_os_drop;
    _counters.dhcp_if_drop += other._counters.dhcp_if_drop;
}

void DhcpMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    _counters.dhcp_TCP_reassembly_errors.to_prometheus(out, add_labels);
    _counters.dhcp_os_drop.to_prometheus(out, add_labels);
    _counters.dhcp_if_drop.to_prometheus(out, add_labels);
}

void DhcpMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    _counters.dhcp_TCP_reassembly_errors.to_json(j);
    _counters.dhcp_os_drop.to_json(j);
    _counters.dhcp_if_drop.to_json(j);
}

void DhcpMetricsBucket::process_dhcp_tcp_reassembly_error([[maybe_unused]] bool deep, [[maybe_unused]] pcpp::Packet &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3)
{
    std::unique_lock lock(_mutex);
    ++_counters.dhcp_TCP_reassembly_errors;
}
void DhcpMetricsBucket::process_dhcp_stats(const pcpp::IDhcpDevice::DhcpStats &stats)
{
    std::unique_lock lock(_mutex);

    // dhcp keeps monotonic counters, so at the start of every new bucket we have to record
    // the current dhcp value and then keep track of differences.
    if (_counters.dhcp_last_os_drop == std::numeric_limits<uint64_t>::max() || _counters.dhcp_last_if_drop == std::numeric_limits<uint64_t>::max()) {
        _counters.dhcp_last_os_drop = stats.packetsDrop;
        _counters.dhcp_last_if_drop = stats.packetsDropByInterface;
        return;
    }
    if (stats.packetsDrop > _counters.dhcp_last_os_drop) {
        _counters.dhcp_os_drop += stats.packetsDrop - _counters.dhcp_last_os_drop;
        _counters.dhcp_last_os_drop = stats.packetsDrop;
    }
    if (stats.packetsDropByInterface > _counters.dhcp_last_if_drop) {
        _counters.dhcp_if_drop += stats.packetsDropByInterface - _counters.dhcp_last_if_drop;
        _counters.dhcp_last_if_drop = stats.packetsDropByInterface;
    }
}

// the general metrics manager entry point
void DhcpMetricsManager::process_dhcp_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, [[maybe_unused]] timespec stamp)
{
    // process in the "live" bucket
    live_bucket()->process_dhcp_tcp_reassembly_error(_deep_sampling_now, payload, dir, l3);
}
void DhcpMetricsManager::process_dhcp_stats(const pcpp::IDhcpDevice::DhcpStats &stats)
{
    // process in the "live" bucket
    live_bucket()->process_dhcp_stats(stats);
}

}