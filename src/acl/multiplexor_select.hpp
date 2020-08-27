#pragma once

#include <sys/time.h>

class MultiplexorSelect
{
public :
    MultiplexorSelect(timeval timeout);
    int monitor_fds(timeval now);
    void set_timeout(timeval next_timeout) noexcept;
    const timeval& get_timeout() const noexcept;
    bool is_set_for_writing(int fd) const;
    bool is_set_for_reading(int fd) const;
    void set_read_sck(int sck);
    void set_write_sck(int sck);

private :
    unsigned max = 0;
    fd_set rfds;
    fd_set wfds;
    timeval timeout;
    bool want_write = false;
};
