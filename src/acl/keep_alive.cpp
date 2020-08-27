#include "keep_alive.hpp"

KeepAlive::KeepAlive(std::chrono::seconds grace_delay_) :
    grace_delay(grace_delay_.count()),
    timeout(0),
    renew_time(0),
    wait_answer(false),
    connected(false)
{ }

bool KeepAlive::is_started() const noexcept { return this->connected; }

void KeepAlive::start(time_t now) noexcept
{    
    this->connected = true;
    this->timeout    = now + 2 * this->grace_delay;
    this->renew_time = now + this->grace_delay;
}

void KeepAlive::stop() noexcept { this->connected = false; }
