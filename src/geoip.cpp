#include "geoip.h"

namespace pktvisor {

GeoDB::GeoDB(const std::string &database_filename)
{
    auto status = MMDB_open(database_filename.c_str(), MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS) {
        std::string msg = "Failed to open MMDB database \"" + database_filename + "\": " + MMDB_strerror(status);
        throw std::runtime_error(msg);
    }
}

GeoDB::~GeoDB()
{
    MMDB_close(&mmdb);
}

std::string GeoDB::getGeoLocString(const char *ip_address)
{

    int gai_error, mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_string(&mmdb, ip_address, &gai_error, &mmdb_error);
    if (!lookup.found_entry) {
        return "Unknown";
    }

    std::string geoString;

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup.entry, &result, "continent", "code", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geoString.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup.entry, &result, "country", "names", "en", NULL);
        if (!result.has_data) {
            MMDB_get_value(&lookup.entry, &result, "country", "iso_code", NULL);
        }

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geoString.push_back('/');
            geoString.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup.entry, &result, "subdivisions", "0", "iso_code", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geoString.push_back('/');
            geoString.append(std::string(result.utf8_string, result.data_size));
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup.entry, &result, "city", "names", "en", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geoString.push_back('/');
            geoString.append(std::string(result.utf8_string, result.data_size));
        }
    }

    return geoString;
}

std::string GeoDB::getASNString(const char *ip_address)
{

    int gai_error, mmdb_error;

    MMDB_lookup_result_s lookup = MMDB_lookup_string(&mmdb, ip_address, &gai_error, &mmdb_error);
    if (!lookup.found_entry) {
        return "Unknown";
    }

    std::string geoString;

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup.entry, &result, "autonomous_system_number", NULL);

        if (result.has_data) {
            switch (result.type) {
            case MMDB_DATA_TYPE_UINT16:
                geoString.append(std::to_string(result.uint16));
                break;
            case MMDB_DATA_TYPE_INT32:
                geoString.append(std::to_string(result.int32));
                break;
            case MMDB_DATA_TYPE_UINT32:
                geoString.append(std::to_string(result.uint32));
                break;
            case MMDB_DATA_TYPE_UINT64:
                geoString.append(std::to_string(result.uint64));
                break;
            case MMDB_DATA_TYPE_UTF8_STRING:
                geoString.append(std::string(result.utf8_string, result.data_size));
                break;
            }
        }
    }

    {
        MMDB_entry_data_s result;
        MMDB_get_value(&lookup.entry, &result, "autonomous_system_organization", NULL);

        if (result.has_data && result.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geoString.push_back('/');
            geoString.append(std::string(result.utf8_string, result.data_size));
        }
    }

    return geoString;
}

}
