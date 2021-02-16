#pragma once

#include <maxminddb.h>
#include <string>

namespace vizer::geo {

class MaxmindDB
{
public:
    ~MaxmindDB();

    void enable(const std::string &database_filename);
    bool enabled() const
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

MaxmindDB &GeoIP();
MaxmindDB &GeoASN();
bool enabled();

}
