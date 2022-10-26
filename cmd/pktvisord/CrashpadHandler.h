#pragma once

#define NOMINMAX

#include "visor_config.h"

#ifndef CRASHPAD_NOT_SUPPORTED
#include <client/crash_report_database.h>
#include <client/crashpad_client.h>
#include <client/settings.h>

namespace crashpad {

static bool start_crashpad_handler(base::FilePath::StringType token, base::FilePath::StringType url, base::FilePath::StringType handler_path)
{
    std::map<std::string, std::string> annotations;
    std::vector<std::string> arguments;
    CrashpadClient client;
    bool rc;

    annotations["format"] = "minidump";
    annotations["product"] = "pktvisor";
    annotations["database"] = "pktvisor";
    annotations["version"] = VISOR_VERSION_NUM;
    annotations["token"] = token;
    base::FilePath::StringType db_path("crashpad");
    arguments.push_back("--no-rate-limit");

    base::FilePath db(db_path);
    base::FilePath handler(handler_path);

    std::unique_ptr<CrashReportDatabase> database = crashpad::CrashReportDatabase::Initialize(db);

    if (database == nullptr || database->GetSettings() == NULL)
        return false;

    /* Enable automated uploads. */
    database->GetSettings()->SetUploadsEnabled(true);

    rc = client.StartHandler(handler, db, db, url, annotations, arguments, true, false);
    if (rc == false) {
        return false;
    }
    return true;
}
}
#else
namespace base {
namespace FilePath {
typedef std::string StringType;
}
}

namespace crashpad {
static bool start_crashpad_handler([[maybe_unused]] base::FilePath::StringType token, [[maybe_unused]] base::FilePath::StringType url, [[maybe_unused]] base::FilePath::StringType handler_path)
{
    return false;
}
}
#endif