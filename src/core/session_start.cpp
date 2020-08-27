#include <utility>

#include "configs/config.hpp"
#include "transport/socket_transport.hpp"
#include "transport/ws_transport.hpp"
#include "core/session.hpp"

#include "core/session_start.hpp"

namespace
{
    template <class TSocketTransport, class... TArgs>
    void session_start_sck(char const* name,
                           unique_fd&& sck,
                           Inifile& ini,
                           TArgs&&... args)
    {
        uint32_t verbose = ini.get<cfg::debug::front>()
            | ((ini.get<cfg::globals::host>() == "127.0.0.1")
               ? uint64_t(SocketTransport::Verbose::watchdog) : 0u);
        TSocketTransport front_trans(name,
                                     std::move(sck),
                                     "",
                                     0,
                                     ini.get<cfg::client::recv_timeout>(),
                                     static_cast<TArgs&&>(args)...,
                                     to_verbose_flags(verbose));        
        Session session(front_trans, ini);

        session.run();
    }
}

void session_start_tls(unique_fd sck, Inifile& ini)
{
    session_start_sck<SocketTransport>
        ("RDP Client",
         std::move(sck),
         ini);
}

void session_start_ws(unique_fd sck, Inifile& ini)
{
    session_start_sck<WsTransport>
        ("RDP Ws Client",
         std::move(sck),
         ini,
         WsTransport::UseTls::
         No, WsTransport::TlsOptions());
}

void session_start_wss(unique_fd sck, Inifile& ini)
{
    session_start_sck<WsTransport>
        ("RDP Wss Client",
         std::move(sck),
         ini,
         WsTransport::UseTls::Yes,
         WsTransport::TlsOptions
         {
             ini.get<cfg::globals::certificate_password>(),
             ini.get<cfg::client::ssl_cipher_list>(),
             ini.get<cfg::client::tls_min_level>(),
             ini.get<cfg::client::tls_max_level>(),
             ini.get<cfg::client::show_common_cipher_list>(),
         });
}
