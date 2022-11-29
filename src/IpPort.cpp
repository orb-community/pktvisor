#include "IpPort.h"

namespace visor::network {

std::ostream &operator<<(std::ostream &os, const IpPort &p)
{
    os << std::to_string(p.port);
    return os;
}

std::map<const uint16_t, PortData> IpPort::ports_tcp_list;
std::map<const uint16_t, PortData> IpPort::ports_udp_list;

void IpPort::set_csv_iana_ports(std::string path)
{
    io::CSVReader<3> in(path);
    in.read_header(io::ignore_extra_column, "Service Name", "Port Number", "Transport Protocol");
    std::string service, ports, protocol;
    for (;;) {
        try {
            while (in.read_row(service, ports, protocol)) {
                if (service.empty() || ports.empty() || !(protocol == "tcp" || protocol == "udp")) {
                    continue;
                }
                auto delimiter = ports.find('-');
                if (delimiter != ports.npos) {
                    auto first_value = static_cast<uint16_t>(std::stoul(ports.substr(0, delimiter)));
                    auto last_value = static_cast<uint16_t>(std::stoul(ports.substr(delimiter + 1)));
                    if (protocol == "tcp") {
                        ports_tcp_list[last_value] = {service, first_value};
                    } else if (protocol == "udp") {
                        ports_udp_list[last_value] = {service, first_value};
                    }
                } else {
                    auto value = static_cast<uint16_t>(std::stoul(ports));
                    if (protocol == "tcp") {
                        ports_tcp_list[value] = {service, value};
                    } else if (protocol == "udp") {
                        ports_udp_list[value] = {service, value};
                    }
                }
            }
            break;
        } catch ([[maybe_unused]] std::exception &e) {
            in.next_line();
            continue;
        }
    }
}

std::string IpPort::get_service() const
{
    // dynamic range
    if (port >= BEGIN_DYNAMIC_PORT && port <= END_DYNAMIC_PORT) {
        return std::string("dynamic-client");
    }
    std::map<const uint16_t, PortData>::iterator it;
    if (proto == Protocol::TCP) {
        it = ports_tcp_list.lower_bound(port);
        if (it == ports_tcp_list.end()) {
            return std::to_string(port);
        }
    } else if (proto == Protocol::UDP) {
        it = ports_udp_list.lower_bound(port);
        if (it == ports_udp_list.end()) {
            return std::to_string(port);
        }
    }
    if ((it->first == port) || (port >= it->second.lower_bound)) {
        return it->second.name;
    }
    return std::to_string(port);
}
}
