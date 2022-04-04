/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <fstream>
#include <vector>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif __APPLE__
#elif __linux__
#include <unistd.h>
#endif

namespace visor {

class ThreadMonitor
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif __APPLE__
#elif __linux__
    std::vector<uint64_t> _last_cpus_time;
    uint64_t _last_thread_time = 0;
#endif
public:
    ThreadMonitor() = default;
    ~ThreadMonitor() = default;

    inline double cpu_percentage()
    {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        return 0;
#elif __APPLE__
        return 0;
#elif __linux__
        uint64_t stat;

        std::ifstream system_stat("/proc/stat");
        std::string line;
        std::getline(system_stat, line); // remove first line
        std::vector<uint64_t> current_cpus_time;
        for (uint8_t i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); ++i) {
            std::getline(system_stat, line);
            std::stringstream cpu_times(line.erase(0, 5));
            uint64_t cpu_total_time = 0;
            while (cpu_times >> stat) {
                cpu_total_time += stat;
            }
            current_cpus_time.push_back(cpu_total_time);
        }

        std::vector<uint64_t> stats;
        std::ifstream thread_stat("/proc/thread-self/stat");
        thread_stat.ignore(' ');
        while (thread_stat >> stat) {
            stats.push_back(stat);
        }
        uint64_t thread_total_time = (stats[8] + stats[9]);
        uint64_t cpu_number = stats[33];

        uint64_t current_thread_time = thread_total_time - _last_thread_time;
        _last_thread_time = thread_total_time;
        double current_period_time = current_cpus_time[cpu_number];
        if (!_last_cpus_time.empty()) {
            current_period_time -= _last_cpus_time[cpu_number];
        }
        _last_cpus_time = current_cpus_time;

        double cpu_usage = (current_thread_time / current_period_time) * 100.0;
        if (cpu_usage < 0.0) {
            cpu_usage = 0.0;
        }
        return cpu_usage;
#endif
    }

    inline uint64_t memory_usage()
    {
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
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
#endif
    }
};
}
