#pragma once

#include <maxminddb.h>
#include <string>

namespace pktvisor {

class GeoDB
{
public:
    explicit GeoDB(const std::string &database_filename);
    ~GeoDB();

    std::string getGeoLocString(const char *ip_address);
    std::string getGeoLocString(const in_addr* ip_address);
    std::string getGeoLocString(const in6_addr* ip_address);

    std::string getASNString(const char *ip_address);
    std::string getASNString(const in_addr* in_addr);
    std::string getASNString(const in6_addr* in_addr);

private:
    MMDB_s mmdb;

    std::string _getGeoLocString(MMDB_lookup_result_s* lookup);
    std::string _getASNString(MMDB_lookup_result_s* lookup);

};

}
