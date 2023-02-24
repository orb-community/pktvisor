/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <fstream>
#include <vector>

#ifdef _WIN32
#elif __APPLE__
#elif __linux__
#include <unistd.h>
#endif

namespace visor {

class ThreadMonitor
{
#ifdef _WIN32
#elif __APPLE__
#elif __linux__
    static constexpr size_t PROC_STAT_POS_UTIME = 13;
    static constexpr size_t PROC_STAT_POS_STIME = 14;
    uint64_t _last_system_time = 0;
    uint64_t _last_thread_time = 0;
#endif
public:
    ThreadMonitor() = default;
    ~ThreadMonitor() = default;

    inline double cpu_percentage()
    {
#ifdef _WIN32
        return 0;
#elif __APPLE__
        return 0;
#elif __linux__
        uint64_t stat;

        std::ifstream system_stat("/proc/stat");
        std::string line;
        std::getline(system_stat, line);
        std::stringstream cpu_times(line.erase(0, 5));
        uint64_t system_total_time = 0;
        while (cpu_times >> stat) {
            system_total_time += stat;
        }
        system_total_time = system_total_time / sysconf(_SC_NPROCESSORS_ONLN);

        std::vector<std::string> stats;
        std::ifstream thread_stat("/proc/thread-self/stat");
        std::string stat_str;
        while (thread_stat >> stat_str) {
            stats.push_back(stat_str);
            if (stats.size() > PROC_STAT_POS_STIME)
                break;
        }

        if (stats.size() <= PROC_STAT_POS_STIME) {
            return 0.0;
        }

        uint64_t thread_total_time = std::stoull(stats[PROC_STAT_POS_UTIME]) + std::stoull(stats[PROC_STAT_POS_STIME]);

        uint64_t current_thread_time = thread_total_time - _last_thread_time;
        _last_thread_time = thread_total_time;
        double current_period_time = system_total_time - _last_system_time;
        _last_system_time = system_total_time;

        double cpu_usage = (current_thread_time / current_period_time) * 100.0;
        if (cpu_usage < 0.0) {
            cpu_usage = 0.0;
        }
        return cpu_usage;
#else
        return 0;
#endif
    }

    inline uint64_t memory_usage()
    {
#ifdef _WIN32
        return 0;
#elif __APPLE__
        return 0;
#elif __linux__
        uint64_t memory;
        std::string token;
        std::ifstream file("/proc/thread-self/status");
        while (file >> token) {
            if (token == "VmRSS:") {
                if (file >> memory) {
                    return memory * 1024;
                } else {
                    return 0;
                }
            }
            // Ignore the rest of the line
            file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        return 0; // Nothing found
#else
        return 0;
#endif
    }
};
}
