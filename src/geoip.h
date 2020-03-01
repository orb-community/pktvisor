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
    std::string getASNString(const char *ip_address);

private:
    MMDB_s mmdb;

};

}
