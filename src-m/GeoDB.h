#pragma once

#include <maxminddb.h>
#include <singleton/Singleton.hpp>
#include <string>

namespace pktvisor {

class MaxmindDB
{
public:
    ~MaxmindDB();

    void enable(const std::string &database_filename);
    bool is_enabled()
    {
        return _enabled;
    }

    /*
     * These routines accept both IPv4 and IPv6
     */
    std::string getGeoLocString(const char *ip_address) const;
    std::string getGeoLocString(const struct sockaddr *sa) const;

    std::string getASNString(const char *ip_address) const;
    std::string getASNString(const struct sockaddr *sa) const;

private:
    mutable MMDB_s _mmdb;
    bool _enabled = false;

    std::string _getGeoLocString(MMDB_lookup_result_s *lookup) const;
    std::string _getASNString(MMDB_lookup_result_s *lookup) const;
};

extern lib::Singleton<MaxmindDB> GeoIP;
extern lib::Singleton<MaxmindDB> GeoASN;

}
