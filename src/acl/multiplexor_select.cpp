#include <chrono>
#include <sys/select.h>

#include "utils/difftimeval.hpp"
#include "utils/select.hpp"

#include "multiplexor_select.hpp"

MultiplexorSelect::MultiplexorSelect(timeval timeout) :
    timeout(timeout)
{
    io_fd_zero(this->rfds);
    io_fd_zero(this->wfds);
}

int MultiplexorSelect::monitor_fds(timeval now)
{    
    timeval timeoutastv = {0,0};
    const timeval & ultimatum = this->timeout;
    const timeval & starttime = now;
    
    if (ultimatum > starttime) {
        timeoutastv = to_timeval(std::chrono::seconds(ultimatum.tv_sec)
                                 - std::chrono::seconds(starttime.tv_sec)
                                 + std::chrono::microseconds(ultimatum.tv_usec)
                                 - std::chrono::microseconds(starttime.tv_usec));
    }

    return ::select(this->max + 1,
                    &this->rfds,
                    this->want_write ? &this->wfds : nullptr,
                    nullptr,
                    &timeoutastv);
}

void MultiplexorSelect::set_timeout(timeval next_timeout) noexcept
{
    this->timeout = next_timeout;
}

const timeval& MultiplexorSelect::get_timeout() const noexcept
{
    return this->timeout;
}

bool MultiplexorSelect::is_set_for_writing(int fd) const
{
    return io_fd_isset(fd, this->wfds);
}

bool MultiplexorSelect::is_set_for_reading(int fd) const
{
    return io_fd_isset(fd, this->rfds);
}

void MultiplexorSelect::set_read_sck(int sck)
{
    this->max = prepare_fds(sck, this->max, this->rfds);
}

void MultiplexorSelect::set_write_sck(int sck)
{    
    if (!this->want_write) {
        this->want_write = true;
        io_fd_zero(this->wfds);
    }
    this->max = prepare_fds(sck, this->max, this->wfds);
}
