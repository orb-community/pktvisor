#pragma once

#include <maxminddb.h>
#include <string>

namespace pktvisor {

class GeoDB
{
public:
    explicit GeoDB(const std::string &database_filename);
    ~GeoDB();

    std::string getGeoLocString(const char *ip_address) const;
    std::string getGeoLocString(const in_addr* ip_address) const;
    std::string getGeoLocString(const in6_addr* ip_address) const;

    std::string getASNString(const char *ip_address) const;
    std::string getASNString(const in_addr* in_addr) const;
    std::string getASNString(const in6_addr* in_addr) const;

private:
    MMDB_s mmdb;

    std::string _getGeoLocString(MMDB_lookup_result_s* lookup) const;
    std::string _getASNString(MMDB_lookup_result_s* lookup) const;

};

}
