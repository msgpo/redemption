/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Product name: redemption, a FLOSS RDP proxy
   Copyright (C) Wallix 2010-2012
   Author(s): Christophe Grosjean, Javier Caverni, Raphael Zhou, Meng Tan
*/

#pragma once

#include "acl/mod_pack.hpp"
#include "acl/module_manager/enums.hpp"
#include "capture/capture.hpp"
#include "mod/mod_api.hpp"
#include "utils/invalid_socket.hpp"
#include "utils/netutils.hpp"
#include "utils/select.hpp"
#include "utils/difftimeval.hpp"
#include "utils/redirection_info.hpp"
#include "utils/file.hpp"
#include "core/RDP/tpdu_type.hpp"

#include "capture/cryptofile.hpp"
#include "utils/genrandom.hpp"
#include "utils/genfstat.hpp"
#include "utils/timebase.hpp"
#include "core/events.hpp"
#include "acl/sesman.hpp"
#include "front/front.hpp"
#include "acl/keep_alive.hpp"
#include "acl/inactivity.hpp"
#include "acl/acl_serializer.hpp"
#include "acl/session_logfile.hpp"
#include "core/font.hpp"
#include "utils/theme.hpp"
#include "utils/redirection_info.hpp"
#include "RAIL/client_execute.hpp"
#include "acl/mod_wrapper.hpp"
#include "acl/perf_log_file_writer.hpp"
#include "acl/session_mod_replacer.hpp"
#include "acl/end_session_error.hpp"

class SocketTransport;
class Inifile;
class EndSessionWarning;
class MultiplexorSelect;

class Session
{
public :
    Session(SocketTransport& front_trans, Inifile& ini);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session();
    void run();

private :
    enum { SELECT_TIMEOUT_TV_SEC = 3 };

    SocketTransport& _front_trans;
    Inifile& _ini;
    CryptoContext _cctx;
    UdevRandom _rnd;
    Fstat _fstat;
    TimeBase _time_base;
    EventContainer _events;
    Sesman _sesman;
    Front _front;
    KeepAlive _keepalive;
    Inactivity _inactivity;
    AclSerializer _acl_serial;
    SessionLogFile _log_file;
    Font _glyphs;
    Theme _theme;
    RedirectionInfo _redir_info;
    ClientExecute _rail_client_execute;
    windowing_api *_winapi = nullptr;
    ModWrapper _mod_wrapper;
    PerfLogFileWriter<File, &getpid, &getrusage> _perf_log_file_writer;
    SessionModReplacer _session_mod_replacer;
    EndSessionError _end_session_error;

    ModuleIndex _last_state = MODULE_UNKNOWN;
    
    inline void start_loop();
    bool perform_delayed_writes(SocketTransport *pmod_trans,
                                bool& run_session);
    void front_incoming_data();
    void next_backend_module(bool& run_session);
    void next_backend_module_post(bool& run_session);
    void propagate_acl_change_to_sesman(const std::string& session_type);
    void receive_data_from_sesman(MultiplexorSelect& ioswitch,
                                  std::string& session_type);
    void wabam_settings();
    void rt_display();
    bool process_data_from_front(MultiplexorSelect& ioswitch,
                                 bool& run_session);
    bool handle_authentifier_connection(bool& run_session,
                                        std::unique_ptr<Transport>& auth_trans);
    void throw_error_session_close_if();
    void prepare_multiplexor_listening(MultiplexorSelect& ioswitch);
    void update_multiplexor_timeout(MultiplexorSelect& ioswitch);
    void close_target_connection(bool& run_session);
    void display_osd_message(time_t start_time,
                             EndSessionWarning& end_session_warning);
    void established_target_connection();
    bool check_back_event_mod_signal(bool& run_session);
    void modified_fields_for_sesman(bool& run_session);
    void do_actions_depending_on_current_mod(bool& is_first_loop_on_mod_selector);
    void monitoring_data_from_fds_failed(bool& run_session);
    bool process_when_front_up_and_running(bool& run_session,
                                           bool& is_first_loop_on_mod_selector,
                                           time_t start_time,
                                           EndSessionWarning& end_session_warning);
};
