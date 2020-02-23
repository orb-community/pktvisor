#ifndef GEOLITE2PP_INCLUDE_GEOLITE2PP_ERROR_H_
#define GEOLITE2PP_INCLUDE_GEOLITE2PP_ERROR_H_

#pragma once

#include <string>
#include <system_error>
#include <maxminddb.h>

namespace GeoLite2PP {

/// Errors defined in maxminddb.h, converted to C++ enums.
enum class MMDBStatus {
  success                    = MMDB_SUCCESS,                                ///<= 0
  file_open                  = MMDB_FILE_OPEN_ERROR,                        ///<= 1
  corrupt_search_tree        = MMDB_CORRUPT_SEARCH_TREE_ERROR,              ///<= 2
  invalid_metadata           = MMDB_INVALID_METADATA_ERROR,                 ///<= 3
  io                         = MMDB_IO_ERROR,                               ///<= 4
  out_of_memory              = MMDB_OUT_OF_MEMORY_ERROR,                    ///<= 5
  unknown_db_format          = MMDB_UNKNOWN_DATABASE_FORMAT_ERROR,          ///<= 6
  invalid_data               = MMDB_INVALID_DATA_ERROR,                     ///<= 7
  invalid_lookup_path        = MMDB_INVALID_LOOKUP_PATH_ERROR,              ///<= 8
  lookup_path_does_not_match = MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR,  ///<= 9
  invalid_node_number        = MMDB_INVALID_NODE_NUMBER_ERROR,              ///<= 10
  ipv6_lookup_in_ipv4_db     = MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR      ///<= 11
};

/* Error class used to return libmaxminddb error codes and messages when C++ exceptions are thrown. */
class ErrorCategory : public std::error_category {
 public:
  /// Returns a unique name.
  virtual const char *name(void) const noexcept;

  /// Convert a MaxMindDB error/status code into a readable text string message.
  virtual std::string message(int code) const;
};

/// All error category objects should actually be references to the exact same object, which is provided by this function.
const ErrorCategory &get_error_category(void) noexcept;

/// Associate an error value with the category.
std::error_code make_error_code(MMDBStatus s);

/// Associate an error_condition with the category.
std::error_condition make_error_condition(MMDBStatus s);

}

namespace std {

/// Make sure that MMDBStatus enums can be converted to error codes.
template<>
struct is_error_code_enum<GeoLite2PP::MMDBStatus> : public true_type {};

}

#endif // GEOLITE2PP_INCLUDE_GEOLITE2PP_ERROR_H_
