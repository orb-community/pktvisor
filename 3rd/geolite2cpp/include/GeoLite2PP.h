#pragma once

#include <maxminddb.h>
#include <string>

namespace GeoLite2PP {

class DB final
{
public:
    DB(const std::string &database_filename);
    ~DB(void);

    void get_geoinfo(const char *ip_address, uint16_t &country,
                                     uint16_t &prov, uint16_t &isp, uint16_t &city);

    std::string getGeoCountry(const char *ip_address);

private:
    /* Internal handle to the database. */
    MMDB_s mmdb;

    std::string str_;

    /* Look up an IP address.  This returns a raw @p MMDB_lookup_result_s structure. */
    MMDB_lookup_result_s lookup_raw(const char *ip_address);

    /* Return a @p std::map of many of the key fields available when looking up an address. */
    std::string &get_field(const char *ip_address, const char **v);
    void get_field(const char *ip_address);

    /* Get a specific field, or an empty string if the field does not exist. */
    std::string &get_field(MMDB_lookup_result_s *lookup, const char **v);
    void get_field(MMDB_lookup_result_s *lookup);

    uint16_t city_;
    uint16_t country_;
    uint16_t isp_;
    uint16_t prov_;
};

}

