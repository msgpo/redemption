#pragma once

#include <time.h>
#include <stdio.h>
#include <sys/resource.h>

template <typename TFile,
          int (*GET_PID)(),
          int (*GET_RUSAGE)(int, struct rusage *)>
class PerfLogFileWriter
{
public :
    void write(const char *record_tmp_path, time_t now, time_t tv_sec)
    {
        if (_perf_last_info_collect_time + tv_sec > now)
        {
            return;
        }
        if (!_perf_last_info_collect_time)
        {
            write_field_names(record_tmp_path, now, tv_sec);
        }
        write_fields_values(now, tv_sec);
    }

    time_t get_perf_last_info_collect_time() const noexcept
    {
        return _perf_last_info_collect_time;
    }

private :
    time_t _perf_last_info_collect_time = 3;
    pid_t _perf_pid = GET_PID();
    TFile _perf_file = nullptr;

    void write_field_names(const char *record_tmp_path,
                           time_t now,
                           time_t tv_sec)
    {
        assert(!_perf_file);

        _perf_last_info_collect_time = now - tv_sec;

        struct tm tm;

        localtime_r(&_perf_last_info_collect_time, &tm);

        char filename[2048];
            
        snprintf(filename,
                 sizeof(filename),
                 "%s/rdpproxy,%04d%02d%02d-%02d%02d%02d,%d.perf",
                 record_tmp_path,
                 tm.tm_year + 1900,
                 tm.tm_mon + 1,
                 tm.tm_mday,
                 tm.tm_hour,
                 tm.tm_min,
                 tm.tm_sec,
                 _perf_pid);

        _perf_file = File(filename, "w");
        _perf_file.write(cstr_array_view("time_t;"
                                         "ru_utime.tv_sec;ru_utime.tv_usec;ru_stime.tv_sec;ru_stime.tv_usec;"
                                         "ru_maxrss;ru_ixrss;ru_idrss;ru_isrss;ru_minflt;ru_majflt;ru_nswap;"
                                         "ru_inblock;ru_oublock;ru_msgsnd;ru_msgrcv;ru_nsignals;ru_nvcsw;ru_nivcsw\n"));
    }

    void write_fields_values(time_t now, time_t tv_sec)
    {
        struct rusage resource_usage;

        GET_RUSAGE(RUSAGE_SELF, &resource_usage);

        do
        {
            _perf_last_info_collect_time += tv_sec;

            struct tm result;

            localtime_r(&_perf_last_info_collect_time, &result);

            ::fprintf(_perf_file.get(),
                      "%lu;"
                      "%lu;%lu;%lu;%lu;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld;%ld\n",
                      static_cast<unsigned long>(now),
                      static_cast<unsigned long>(resource_usage.ru_utime.tv_sec), /* user CPU time used */
                      static_cast<unsigned long>(resource_usage.ru_utime.tv_usec),
                      static_cast<unsigned long>(resource_usage.ru_stime.tv_sec), /* system CPU time used */
                      static_cast<unsigned long>(resource_usage.ru_stime.tv_usec),
                      resource_usage.ru_maxrss, /* maximum resident set size */
                      resource_usage.ru_ixrss, /* integral shared memory size */
                      resource_usage.ru_idrss, /* integral unshared data size */
                      resource_usage.ru_isrss, /* integral unshared stack size */
                      resource_usage.ru_minflt, /* page reclaims (soft page faults) */
                      resource_usage.ru_majflt, /* page faults (hard page faults)   */
                      resource_usage.ru_nswap, /* swaps */
                      resource_usage.ru_inblock, /* block input operations */
                      resource_usage.ru_oublock, /* block output operations */
                      resource_usage.ru_msgsnd, /* IPC messages sent */
                      resource_usage.ru_msgrcv, /* IPC messages received */
                      resource_usage.ru_nsignals, /* signals received */
                      resource_usage.ru_nvcsw, /* voluntary context switches */
                      resource_usage.ru_nivcsw /* involuntary context switches */);
            _perf_file.flush();
        }
        while (_perf_last_info_collect_time + tv_sec <= now);
    }
};
