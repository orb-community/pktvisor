#include "IpPort.h"

namespace visor::network {

std::ostream &operator<<(std::ostream &os, const IpPort &p)
{
    os << std::to_string(p.port);
    return os;
}

std::string IpPort::get_service() const
{
#ifdef _WIN32
    return std::to_string(port);
#elif defined(__APPLE__) || defined(__linux__)
    struct servent *serv{nullptr};
    if (proto == Protocol::TCP) {
        serv = getservbyport(htons(port), "tcp");
    } else if (proto == Protocol::UDP) {
        serv = getservbyport(htons(port), "udp");
    } else {
        serv = getservbyport(htons(port), nullptr);
    }
    if (serv) {
        return std::string(serv->s_name);
    }
    return std::to_string(port);
#endif
}

}