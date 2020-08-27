#pragma once

#include <chrono>

#include "utils/log.hpp"
#include "configs/config.hpp"

class KeepAlive
{
public :
    KeepAlive(std::chrono::seconds grace_delay_);
    bool is_started() const noexcept;
    void start(time_t now) noexcept;
    void stop() noexcept;

    template <typename TInifile>
    bool check(time_t now, TInifile & ini)
    {        
        if (this->connected) {
            if (now > this->timeout) {
                LOG(LOG_INFO, "auth::keep_alive_or_inactivity : connection closed by manager (timeout)");
                return true;
            }
        
            // Keepalive received positive response
            if (this->wait_answer
                && !ini.template is_asked<cfg::context::keepalive>()
                && ini.template get<cfg::context::keepalive>()) {
                LOG_IF(bool(bool(ini.template get<cfg::debug::session>()&0x08) & 2),
                       LOG_INFO, "auth::keep_alive ACL incoming event");
                this->timeout    = now + 2*this->grace_delay;
                this->renew_time = now + this->grace_delay;
                this->wait_answer = false;
            }

            // Keep alive asking for an answer from ACL
            if (!this->wait_answer
                && (now > this->renew_time)) {

                this->wait_answer = true;

                ini.template ask<cfg::context::keepalive>();
            }
        }
        return false;
    }

private :
    // Keep alive Variables
    int  grace_delay;
    long timeout;
    long renew_time;
    bool wait_answer;     // true when we are waiting for a positive response
    // false when positive response has been received and
    // timers have been set to new timers.
    bool connected;
};

