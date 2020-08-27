#include <cassert>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <unistd.h>

#include "configs/config.hpp"
#include "transport/socket_transport.hpp"
#include "acl/end_session_warning.hpp"
#include "acl/multiplexor_select.hpp"
#include "utils/log_siem.hpp"
#include "utils/load_theme.hpp"
#include "utils/translation.hpp"
#include "core/RDP/tpdu_type.hpp"

#include "core/session.hpp"

Session::Session(SocketTransport& front_trans, Inifile& ini) :
    _front_trans(front_trans),
    _ini(ini),
    _cctx(),
    _rnd(),
    _fstat(),
    _time_base(tvtime()),
    _events(),
    _sesman(_ini, _time_base),
    _front(_time_base,
           _events,
           _sesman,
           _front_trans,
           _rnd,
           _ini,
           _cctx,
           _ini.get<cfg::client::fast_path>()),
    _keepalive(_ini.get<cfg::globals::keepalive_grace_delay>()),
    _inactivity(),
    _acl_serial(_ini),
    _log_file(_ini,                  
              _time_base,
              _cctx,
              _rnd,
              _fstat,
              [this](const Error& error)
              {
                  if (error.errnum == ENOSPC)
                      {
                          // error.id = ERR_TRANSPORT_WRITE_NO_ROOM;
                          _sesman.report("FILESYSTEM_FULL",
                                         "100|unknown");
                      }
              }),
    _glyphs(app_path(AppPath::DefaultFontFile),
            _ini.get<cfg::globals::spark_view_specific_glyph_width>()),
    _theme(),
    _redir_info(),
    _rail_client_execute(_time_base,
                         _events,
                         _front,
                         _front,
                         _front.client_info.window_list_caps,
                         _ini.get<cfg::debug::mod_internal>() & 1),
    _mod_wrapper(_front,
                 _front.get_palette(),
                 _front,
                 _front.keymap,
                 _front.client_info,
                 _glyphs,
                 _rail_client_execute,
                 _winapi,
                 _ini,
                 _sesman),
    _perf_log_file_writer(),
    _session_mod_replacer(_mod_wrapper,
                          _ini,
                          _front,
                          _rail_client_execute,
                          _sesman,
                          _acl_serial,
                          _time_base,
                          _events,
                          _redir_info,
                          _glyphs,
                          _theme,
                          _rnd,
                          _cctx),
    _end_session_error(_mod_wrapper,
                       _ini,
                       _redir_info,
                       _sesman,
                       _keepalive,
                       _rail_client_execute,
                       _inactivity,
                       _session_mod_replacer,
                       _acl_serial,
                       _front)
{
    _sesman.set_front(&_front);
    _sesman.set_login_language
        (_ini.get<cfg::translation::login_language>());
    _acl_serial.on_inactivity_timeout = [this]
    {
        auto timeout = (_ini.get<cfg::globals::inactivity_timeout>().count() != 0) ?
            _ini.get<cfg::globals::inactivity_timeout>() :
            _ini.get<cfg::globals::session_timeout>();
        
        _inactivity.update_inactivity_timeout(timeout);
    };
    ::load_theme(_theme, _ini);
    TRANSLATIONCONF.set_ini(&_ini);
}

Session::~Session()
{    
    if (_ini.get<cfg::debug::performance>() & 0x8000)
    {
        _perf_log_file_writer.write
            (_ini.get<cfg::video::record_tmp_path>().c_str(),
             _perf_log_file_writer.get_perf_last_info_collect_time() + 3,
             SELECT_TIMEOUT_TV_SEC);
    }
    /* Suppress Session file from disk
       (original name with PID or renamed with session_id) */
    auto const& session_id = _ini.get<cfg::context::session_id>();
        
    if (!session_id.empty())
    {
        char new_session_file[256];
        
        snprintf(new_session_file,
                 sizeof(new_session_file),
                 "%s/session_%s.pid",
                 app_path(AppPath::LockDir).c_str(),
                 session_id.c_str());
        unlink(new_session_file);
    }
    else
    {
        int child_pid = getpid();
        char old_session_file[256];
        
        sprintf(old_session_file,
                "%s/session_%d.pid",
                app_path(AppPath::LockDir).c_str(),
                child_pid);
        unlink(old_session_file);
    }
}

void Session::run()
{            
    bool source_is_localhost =
        _ini.get<cfg::globals::host>() == "127.0.0.1";

    try
    {
        // Start the session loop here
        start_loop();
        _mod_wrapper.disconnect();
        _front.disconnect();
    }
    catch (const Error& e)
    {
        // silent message for localhost for watchdog
        if (!source_is_localhost || e.id != ERR_TRANSPORT_WRITE_FAILED)
        {
            LOG(LOG_INFO, "Session Init exception %s", e.errmsg());
        }
    }
    catch (const std::exception & e)
    {
        LOG(LOG_ERR, "Session exception %s!", e.what());
    }
    catch (...)
    {
        LOG(LOG_ERR, "Session unexpected exception");
    }
    // silent message for localhost for watchdog
    if (!source_is_localhost
        && !_ini.is_asked<cfg::globals::host>())
    {
        LOG(LOG_INFO, "Client Session Disconnected");
    }
    _front.must_be_stop_capture();
}

void Session::start_loop()
{
    using namespace std::chrono_literals;
        
    std::string session_type;
    std::unique_ptr<Transport> auth_trans;
    time_t start_time = ::time(nullptr);
    bool run_session = true;
    bool is_first_loop_on_mod_selector = true;
    EndSessionWarning end_session_warning;
        
    if (_ini.get<cfg::debug::performance>() & 0x8000)
    {
        _perf_log_file_writer.write
            (_ini.get<cfg::video::record_tmp_path>().c_str(),
             start_time,
             SELECT_TIMEOUT_TV_SEC);
    }
    while (run_session)
    {
        SocketTransport *pmod_trans = _mod_wrapper.get_mod_transport();
        
        _time_base.set_current_time(tvtime());    
        if (perform_delayed_writes(pmod_trans, run_session))
        {
            continue;
        }

        // =============================================================
        // prepare select for listening on all read sockets
        // timeout or immediate wakeups are managed using timeout
        // =============================================================
        timeval multiplexor_timeout
        {
            _time_base.get_current_time().tv_sec + SELECT_TIMEOUT_TV_SEC,
            _time_base.get_current_time().tv_usec
        };
        MultiplexorSelect ioswitch(multiplexor_timeout);
            
        prepare_multiplexor_listening(ioswitch);
        
        int num = ioswitch.monitor_fds(_time_base.get_current_time());
        
        if (num < 0)
        {
            monitoring_data_from_fds_failed(run_session);
            continue;
        }

        _time_base.set_current_time(tvtime());
        
        if (_ini.get<cfg::debug::performance>() & 0x8000)
        {
            _perf_log_file_writer.write
                (_ini.get<cfg::video::record_tmp_path>().c_str(),
                 _time_base.get_current_time().tv_sec,
                 SELECT_TIMEOUT_TV_SEC);
        }

        if (process_data_from_front(ioswitch, run_session))
        {
            continue;
        }
        
        // exchange data with sesman
        if (_acl_serial.is_connected())
        {
            receive_data_from_sesman(ioswitch, session_type);
            
            /* propagate changes made in sesman structure
               to actual acl changes */
            propagate_acl_change_to_sesman(session_type);
        }
        else if (handle_authentifier_connection(run_session, auth_trans))
        {
            continue;
        }
        try
        {
            _events.execute_events
                (_time_base.get_current_time(),
                 [&ioswitch](int fd)
                 {
                     return ioswitch.is_set_for_reading(fd);
                 },
                 bool(_ini.get<cfg::debug::session>() & 0x02));
            if (_front.state == Front::FRONT_UP_AND_RUNNING
                && process_when_front_up_and_running(run_session,
                                                     is_first_loop_on_mod_selector,
                                                     start_time,
                                                     end_session_warning))
            {
                continue;
            }
        }
        catch (const Error& e)
        {       
            run_session = false;
            if (_front.state != Front::FRONT_UP_AND_RUNNING)
            {
                _sesman.flush_acl_disconnect_target([this]()
                {
                    _log_file.close_session_log();
                });
                continue;
            }
            _end_session_error.on_error(e, run_session, _last_state);
        }
    }
}

// This function takes care of outgoing data waiting in buffers
// happening because system write buffer is full and immediate send failed
// hopefully it should be a rare case
bool Session::perform_delayed_writes(SocketTransport *pmod_trans,
                                     bool& run_session)
{
    bool front_has_waiting_data_to_write =
        _front_trans.has_data_to_write();
    bool mod_has_waiting_data_to_write =
        pmod_trans && pmod_trans->has_data_to_write();

    if (front_has_waiting_data_to_write || mod_has_waiting_data_to_write)
    {
        timeval now = _time_base.get_current_time();
        timeval multiplexor_timeout
        {
         now.tv_sec + SELECT_TIMEOUT_TV_SEC,
         now.tv_usec
        };
        MultiplexorSelect ioswitch(multiplexor_timeout);
        
        if (front_has_waiting_data_to_write)
        {
            ioswitch.set_write_sck(_front_trans.sck);
        }
        if (mod_has_waiting_data_to_write)
        {
            ioswitch.set_write_sck(pmod_trans->sck);
        }

        int num = ioswitch.monitor_fds(now);
        
        if (num < 0)
        {
            if (errno != EINTR)
            {
                // Cope with EBADF, EINVAL, ENOMEM : none of these should ever happen
                // EBADF: means fd has been closed (by me) or as already returned an error on another call
                // EINVAL: invalid value in timeout (my fault again)
                // ENOMEM: no enough memory in kernel (unlikely fort 3 sockets)
                LOG(LOG_ERR,
                    "Proxy send wait raised error %d : %s",
                    errno,
                    strerror(errno));
                run_session = false;
                return true;
            }
        }

        if (pmod_trans && ioswitch.is_set_for_writing(pmod_trans->sck))
        {
            pmod_trans->send_waiting_data();
        }

        if (_front_trans.sck != INVALID_SOCKET
            && ioswitch.is_set_for_writing(_front_trans.sck))
        {
            _front_trans.send_waiting_data();
        }

        if (num > 0)
        {
            return true;
        }
        // if the select stopped on timeout or EINTR we will give a try to reading
    }
    return false;
}

void Session::front_incoming_data()
{
    if (_front.front_must_notify_resize)
    {
        LOG(LOG_INFO, "Notify resize to front");
        _front.notify_resize(_mod_wrapper.get_callback());
    }

    _front.rbuf.load_data(_front_trans);

    while (_front.rbuf.next(TpduType::PDU))
        // or TdpuBufferType::CredSSP in NLA
    {
        bytes_view tpdu = _front.rbuf.current_pdu_buffer();
        uint8_t current_pdu_type = _front.rbuf.current_pdu_get_type();
        
        _front.incoming(tpdu, current_pdu_type,
                        _mod_wrapper.get_callback());
    }
}

void Session::next_backend_module(bool& run_session)
{
    ModuleIndex next_state =
        get_module_id(_ini.get<cfg::context::module>());

    if (next_state == MODULE_RDP)
    {
        if (_mod_wrapper.is_connected())
        { 
            if (_ini.get<cfg::context::auth_error_message>().empty())
            {
                _ini.set<cfg::context::auth_error_message>
                    (TR(trkeys::end_connection, language(_ini)));
            }
            throw Error(ERR_SESSION_CLOSE_MODULE_NEXT);
        }
        if (_mod_wrapper.current_mod != next_state)
        {
            _log_file.open_session_log();
            _sesman.set_connect_target();
        }
    }
    else if (next_state == MODULE_VNC)
    {   
        if (_mod_wrapper.is_connected())
        {
            if (_ini.get<cfg::context::auth_error_message>().empty())
            {
                _ini.set<cfg::context::auth_error_message>
                    (TR(trkeys::end_connection, language(_ini)));
            }
            throw Error(ERR_SESSION_CLOSE_MODULE_NEXT);
        }
        if (_mod_wrapper.current_mod != next_state)
        {
            _log_file.open_session_log();
            _sesman.set_connect_target();
        }
    }
    else if (next_state == MODULE_INTERNAL_CLOSE
             || next_state == MODULE_INTERNAL_CLOSE_BACK)
    {
        throw Error(ERR_SESSION_CLOSE_MODULE_NEXT);
    }
    _session_mod_replacer.replace(next_state, _last_state);
    next_backend_module_post(run_session);
}

void Session::next_backend_module_post(bool& run_session)
{
    if (!_ini.get<cfg::context::disconnect_reason>().empty())
    {
        _acl_serial.acl_manager_disconnect_reason =
            _ini.get<cfg::context::disconnect_reason>();
        _ini.set<cfg::context::disconnect_reason>("");
        _ini.set_acl<cfg::context::disconnect_reason_ack>(true);
    }
    else if (!_ini.get<cfg::context::auth_command>().empty())
    {
        if (!::strcasecmp
            (_ini.get<cfg::context::auth_command>().c_str(),
             "rail_exec"))
        {
            const uint16_t flags =
                _ini.get<cfg::context::auth_command_rail_exec_flags>();
            const char *original_exe_or_file =
                _ini.get<cfg::context::auth_command_rail_exec_original_exe_or_file>().c_str();
            const char *exe_or_file =
                _ini.get<cfg::context::auth_command_rail_exec_exe_or_file>().c_str();
            const char *working_dir =
                _ini.get<cfg::context::auth_command_rail_exec_working_dir>().c_str();
            const char *arguments =
                _ini.get<cfg::context::auth_command_rail_exec_arguments>().c_str();
            const uint16_t exec_result =
                _ini.get<cfg::context::auth_command_rail_exec_exec_result>();
            const char *account =
                _ini.get<cfg::context::auth_command_rail_exec_account>().c_str();
            const char *password =
                _ini.get<cfg::context::auth_command_rail_exec_password>().c_str();
            
            rdp_api *rdpapi = _mod_wrapper.get_rdp_api();
            
            if (!exec_result)
            {
                if (rdpapi)
                {
                    rdpapi->auth_rail_exec(flags,
                                           original_exe_or_file,
                                           exe_or_file, working_dir,
                                           arguments,
                                           account,
                                           password);
                }
            }
            else
            {
                if (rdpapi)
                {
                    rdpapi->auth_rail_exec_cancel(flags,
                                                  original_exe_or_file,
                                                  exec_result);
                }
            }
        }
        _ini.set<cfg::context::auth_command>("");
    }
    run_session = true;
}

void Session::propagate_acl_change_to_sesman(const std::string& session_type)
{    
    _sesman.flush_acl_report([this](zstring_view reason,
                                    zstring_view message)
   {
       _ini.ask<cfg::context::keepalive>();
       
       char report[1024];
       
       snprintf(report,
                sizeof(report),
                "%s:%s:%s",
                reason.c_str(),
                _ini.get<cfg::globals::target_device>().c_str(),
                message.c_str());
       _ini.set_acl<cfg::context::reporting>(report);
   });
    _sesman.flush_acl_log6([this, &session_type](LogId id, KVList kv_list)
    {
        // const timeval time = timebase.get_current_time();
        /* Log to SIEM (redirected syslog) */
        log_siem_syslog(id, kv_list, _ini, session_type);
        log_siem_arcsight(_time_base.get_current_time().tv_sec,
                          id, kv_list, _ini, session_type);
        _log_file.log6(id, kv_list);
    });
    _sesman.flush_acl(bool(_ini.get<cfg::debug::session>() & 0x04));
        
    // send over wire if any field changed
    if (_ini.changed_field_size())
    {
        for (auto field : _ini.get_fields_changed())
        {
            zstring_view key = field.get_acl_name();
            
            LOG_IF(bool(_ini.get<cfg::debug::session>() & 0x08),
                   LOG_INFO,
                   "field to send: %s",
                   key.c_str());
        }
        _acl_serial.remote_answer = false;
        _acl_serial.send_acl_data();
    }
    _sesman.flush_acl_disconnect_target([this]()
    {
        _log_file.close_session_log();
    });
}

void Session::receive_data_from_sesman(MultiplexorSelect& ioswitch,
                                       std::string& session_type)
{
    if (ioswitch.is_set_for_reading(_acl_serial.auth_trans->get_sck()))
    {
        try
        {
            _acl_serial.incoming();
            if (_ini.get<cfg::context::module>() == "RDP"
                || _ini.get<cfg::context::module>() == "VNC")
                {
                    session_type = _ini.get<cfg::context::module>();
                        }
            _acl_serial.remote_answer = true;
        }
        catch (...)
        {
            LOG(LOG_INFO, "acl_serial.incoming() Session lost");
            // acl connection lost
            _acl_serial.acl_status =
                AclSerializer::acl_state_disconnected_by_authentifier;
            _ini.set_acl<cfg::context::authenticated>(false);
            
            if (_acl_serial.acl_manager_disconnect_reason.empty())
            {
                _ini.set_acl<cfg::context::rejected>
                    (TR(trkeys::manager_close_cnx, language(_ini)));
            }
            else
            {
                _ini.set_acl<cfg::context::rejected>
                    (_acl_serial.acl_manager_disconnect_reason);
                _acl_serial.acl_manager_disconnect_reason.clear();
            }
        }
        if (!_ini.changed_field_size())
        {
            _mod_wrapper.acl_update();
        }
    }
}
    
void Session::wabam_settings()
{
    if (_ini.get<cfg::client::force_bitmap_cache_v2_with_am>()
        && _ini.get<cfg::context::is_wabam>())
    {
        _front.force_using_cache_bitmap_r2();
    }
}

void Session::rt_display()
{
    auto const rt_status =
        _front.set_rt_display(_ini.get<cfg::video::rt_display>());

    if (_ini.get<cfg::client::enable_osd_4_eyes>())
    {
        Translator tr(language(_ini));
            
        if (rt_status != Capture::RTDisplayResult::Unchanged)
        {
            std::string message =
                tr((rt_status == Capture::RTDisplayResult::Enabled) ?
                   trkeys::enable_rt_display :
                   trkeys::disable_rt_display)
                .to_string();
            
            _mod_wrapper.display_osd_message(message);
        }
    }
}

bool Session::process_data_from_front(MultiplexorSelect& ioswitch,
                                      bool& run_session)
{
    try
    {
        bool const front_is_set =
            _front_trans.has_tls_pending_data()
            || (_front_trans.sck != INVALID_SOCKET
                && ioswitch.is_set_for_reading(_front_trans.sck));
        
        if (front_is_set)
        {
            front_incoming_data();
        }
    }
    catch (Error const& e)
    {
        if (ERR_TRANSPORT_WRITE_FAILED == e.id
            || ERR_TRANSPORT_NO_MORE_DATA == e.id)
        {
            SocketTransport *socket_transport_ptr =
                _mod_wrapper.get_mod_transport();
            
            if (socket_transport_ptr
                && (e.data == socket_transport_ptr->sck)
                && _ini.get<cfg::mod_rdp::auto_reconnection_on_losing_target_link>()
                && _mod_wrapper.get_mod()->is_auto_reconnectable()
                && !_mod_wrapper.get_mod()->server_error_encountered())
            {
                LOG(LOG_INFO,
                    "Session::Session: target link exception. %s",
                    (ERR_TRANSPORT_WRITE_FAILED == e.id ? "ERR_TRANSPORT_WRITE_FAILED" : "ERR_TRANSPORT_NO_MORE_DATA"));
                
                _ini.set<cfg::context::perform_automatic_reconnection>(true);
                LOG(LOG_INFO, "Retry RDP");
                _acl_serial.remote_answer = false;
                _session_mod_replacer.replace(MODULE_RDP, _last_state);
                return true;
            }
        }
            
        // RemoteApp disconnection initiated by user
        // ERR_DISCONNECT_BY_USER == e.id
        if (// Can be caused by client disconnect.
            (e.id != ERR_X224_RECV_ID_IS_RD_TPDU)
            // Can be caused by client disconnect.
            && (e.id != ERR_MCS_APPID_IS_MCS_DPUM)
            && (e.id != ERR_RDP_HANDSHAKE_TIMEOUT)
            // Can be caused by wabwatchdog.
            && (e.id != ERR_TRANSPORT_NO_MORE_DATA))
        {
            LOG(LOG_ERR,
                "Proxy data processing raised error %u : %s",
                e.id,
                e.errmsg(false));
        }
        _front_trans.sck = INVALID_SOCKET;
        run_session = false;
        return true;
    }
    catch (...)
    {
        LOG(LOG_ERR, "Proxy data processing raised an unknown error");
        run_session = false;
        return true;
    }
    return false;
}

bool Session::handle_authentifier_connection(bool& run_session,
                                             std::unique_ptr<Transport>& auth_trans)
{
    if (_mod_wrapper.current_mod != MODULE_INTERNAL_CLOSE)
    {
        if (_acl_serial.is_after_connexion())
        {
            _ini.set<cfg::context::auth_error_message>
                ("Authentifier closed connexion");
            _mod_wrapper.disconnect();
            run_session = false;
            LOG(LOG_INFO, "Session Closed by ACL : %s",
                (_acl_serial.acl_status
                 == AclSerializer::acl_state_disconnected_by_authentifier) ? "closed by authentifier" : "closed by proxy");
            if (_ini.get<cfg::globals::enable_close_box>())
            {
                _session_mod_replacer.replace(MODULE_INTERNAL_CLOSE,
                                              _last_state);
                run_session = true;
            }
            return true;
        }
        else if (_acl_serial.is_before_connexion())
        {
            try
            {
                unique_fd client_sck =
                    addr_connect_non_blocking
                    (_ini.get<cfg::globals::authfile>().c_str(),
                     (strcmp(_ini.get<cfg::globals::host>().c_str(),
                             "127.0.0.1") == 0));
                
                if (!client_sck.is_open())
                {
                    LOG(LOG_ERR,
                        "Failed to connect to authentifier (%s)",
                        _ini.get<cfg::globals::authfile>().c_str());
                    _acl_serial.set_failed_auth_trans();
                    // will go to the catch below
                    throw Error(ERR_SOCKET_CONNECT_AUTHENTIFIER_FAILED);
                }
                auth_trans = std::make_unique<SocketTransport>
                    ("Authentifier",
                     std::move(client_sck),
                     _ini.get<cfg::globals::authfile>().c_str(),
                     0,
                     std::chrono::seconds(1),
                     SocketTransport::Verbose::none);
                _acl_serial.set_auth_trans(auth_trans.get());
            }
            catch (...)
            {
                _ini.set<cfg::context::auth_error_message>
                    ("No authentifier available");
                run_session = false;
                LOG(LOG_INFO,
                    "Start of acl failed : no authentifier available");
                if (_ini.get<cfg::globals::enable_close_box>())
                {
                    _session_mod_replacer.replace(MODULE_INTERNAL_CLOSE,
                                                  _last_state);
                    run_session = true;
                }
            }
            return true;
        }
        else
        {
            LOG_IF(bool(_ini.get<cfg::debug::session>() & 0x04),
                   LOG_ERR,
                   "can't flush acl: not connected yet");
        }
    }
    return false;
}

void Session::throw_error_session_close_if()
{        
    const uint32_t enddate =
        _ini.get<cfg::context::end_date_cnx>();
        
    if (enddate != 0
        && (static_cast<uint32_t>(_time_base.get_current_time().tv_sec)
            > enddate))
    {
        throw Error(ERR_SESSION_CLOSE_ENDDATE_REACHED);
    }
    if (!_ini.get<cfg::context::rejected>().empty())
    {
        throw Error(ERR_SESSION_CLOSE_REJECTED_BY_ACL_MESSAGE);
    }
    if (_keepalive.check(_time_base.get_current_time().tv_sec, _ini))
    {
        throw Error(ERR_SESSION_CLOSE_ACL_KEEPALIVE_MISSED);
    }
    if (_mod_wrapper.current_mod != MODULE_INTERNAL_CLOSE_BACK
        && !_inactivity.activity(_time_base.get_current_time().tv_sec,
                                 _front.has_user_activity))
    {
        throw Error(ERR_SESSION_CLOSE_USER_INACTIVITY);
    }
}

void Session::prepare_multiplexor_listening(MultiplexorSelect& ioswitch)
{
    if (_mod_wrapper.get_mod_transport())
    {
        int fd = _mod_wrapper.get_mod_transport()->sck;
        
        if (fd != INVALID_SOCKET)
        {
            ioswitch.set_read_sck(fd);
        }
    }

    if (_front_trans.sck != INVALID_SOCKET)
    {
        ioswitch.set_read_sck(_front_trans.sck);
    }

    // gather fd from events
    _events.get_fds([&ioswitch](int fd) { ioswitch.set_read_sck(fd); });
        
    if (_acl_serial.is_connected())
    {
        ioswitch.set_read_sck(_acl_serial.auth_trans->get_sck());
    }
    update_multiplexor_timeout(ioswitch);
}
    
void Session::update_multiplexor_timeout(MultiplexorSelect& ioswitch)
{   
    timeval ultimatum = ioswitch.get_timeout();
    auto tv = _events.next_timeout();
    
    // tv {0,0} means no timeout to trigger
    if ((tv.tv_sec != 0) || (tv.tv_usec != 0))
    {
        ultimatum = std::min(tv, ultimatum);
    }
    if (_front.front_must_notify_resize)
    {
        ultimatum = _time_base.get_current_time();
    }
    if ((_mod_wrapper.get_mod_transport()
         && _mod_wrapper.get_mod_transport()->has_tls_pending_data()))
    {
        ultimatum = _time_base.get_current_time();
    }
    if (_front_trans.has_tls_pending_data())
    {
        ultimatum = _time_base.get_current_time();
    }
    ioswitch.set_timeout(ultimatum);
}

void Session::close_target_connection(bool& run_session)
{
    LOG(LOG_INFO, "Exited from target connection");
    _mod_wrapper.disconnect();
        
    auto next_state = MODULE_INTERNAL_CLOSE_BACK;
        
    if (_acl_serial.is_connected())
    {
        for (auto field : _ini.get_fields_changed())
        {
            zstring_view key = field.get_acl_name();
            
            LOG_IF(bool(_ini.get<cfg::debug::session>() & 0x08),
                   LOG_INFO,
                   "field to send: %s",
                   key.c_str());
        }
        _keepalive.stop();
        _sesman.set_disconnect_target();
        _acl_serial.remote_answer = false;
        _acl_serial.send_acl_data();
    }
    else
    {
        next_state = MODULE_INTERNAL_CLOSE;
    }
    if (_ini.get<cfg::globals::enable_close_box>())
    {
        _session_mod_replacer.replace(next_state, _last_state);
        _mod_wrapper.get_mod()->set_mod_signal(BACK_EVENT_NONE);
    }
    else
    {
        LOG(LOG_INFO, "Close Box disabled : ending session");
        run_session = false;
    }
}

void Session::display_osd_message(time_t start_time,
                                  EndSessionWarning& end_session_warning)
{
    if (_ini.get<cfg::globals::enable_osd>())
    {
        const uint32_t enddate =
            _ini.get<cfg::context::end_date_cnx>();
        
        if (enddate && _mod_wrapper.is_up_and_running())
        {
            std::string message =
                end_session_warning.update_osd_state
                (language(_ini),
                 start_time,
                 static_cast<time_t>(enddate),
                 _time_base.get_current_time().tv_sec);
            
            _mod_wrapper.display_osd_message(message);
        }
    }
}

void Session::established_target_connection()
{        
    if (_ini.get<cfg::globals::inactivity_timeout>().count() != 0)
    {
        _inactivity.update_inactivity_timeout
            (_ini.get<cfg::globals::inactivity_timeout>());
    }
    _keepalive.start(_time_base.get_current_time().tv_sec);
}

bool Session::check_back_event_mod_signal(bool& run_session)
{
    if (_mod_wrapper.get_mod_signal() == BACK_EVENT_STOP)
    {
        LOG(LOG_INFO, "Module asked Front Disconnection");
        run_session = false;
        return true;
    }
    
    // BACK FROM EXTERNAL MODULE (RDP, VNC)
    if ((_mod_wrapper.get_mod_signal() == BACK_EVENT_NEXT)
        && _mod_wrapper.is_connected())
    {
        close_target_connection(run_session);
        return true;
    }

    LOG_IF(bool(_ini.get<cfg::debug::session>() & 0x08),
           LOG_INFO,
           " Current Mod is %s Previous %s Acl_mod %s",
           get_module_name(_mod_wrapper.current_mod),
           get_module_name(_last_state),
           _ini.get<cfg::context::module>());

    if (_mod_wrapper.get_mod_signal() == BACK_EVENT_STOP)
    {
        throw Error(ERR_UNEXPECTED);
    }

    if (_mod_wrapper.get_mod_signal() == BACK_EVENT_NEXT)
    {
        _session_mod_replacer.replace(MODULE_INTERNAL_TRANSITION,
                                      _last_state);
    }
    return false;
}

void Session::modified_fields_for_sesman(bool& run_session)
{        
    // There are modified fields to send to sesman
    if (_acl_serial.is_connected() && _acl_serial.remote_answer)
    {
        _acl_serial.remote_answer = false;
        
        auto next_state =
            get_module_id(_ini.get<cfg::context::module>());
        
        if (_mod_wrapper.current_mod == MODULE_INTERNAL_TRANSITION
            || next_state == MODULE_TRANSITORY)
        {
            next_backend_module(run_session);
        }
    }
}

void Session::do_actions_depending_on_current_mod(bool& is_first_loop_on_mod_selector)
{
    if (_mod_wrapper.is_connected()
        && (_mod_wrapper.current_mod == MODULE_RDP))
    {
        auto mod = _mod_wrapper.get_mod();
        // AuthCHANNEL CHECK
        // if an answer has been received, send it to
        // rdp serveur via mod (should be rdp module)
        auto& auth_channel_answer =
            _ini.get<cfg::context::auth_channel_answer>();
                        
        if (_ini.get<cfg::mod_rdp::auth_channel>()[0]
            // Get sesman answer to AUTHCHANNEL_TARGET
            && !auth_channel_answer.empty())
        {
            // If set, transmit to auth_channel
            mod->send_auth_channel_data(auth_channel_answer.c_str());
            // Erase the context variable
            _ini.set<cfg::context::auth_channel_answer>("");
        }
        
        // CheckoutCHANNEL CHECK
        // if an answer has been received, send it to
        // rdp serveur via mod (should be rdp module)
        auto& pm_response = _ini.get<cfg::context::pm_response>();
                        
        if (_ini.get<cfg::mod_rdp::checkout_channel>()[0]
            // Get sesman answer to AUTHCHANNEL_TARGET
            && !pm_response.empty())
        {
            // If set, transmit to auth_channel channel
            mod->send_checkout_channel_data(pm_response.c_str());
            // Erase the context variable
            _ini.set<cfg::context::pm_response>("");
        }
        
        auto& rd_shadow_type =
            _ini.get<cfg::context::rd_shadow_type>();
        
        if (!rd_shadow_type.empty())
        {
            auto& rd_shadow_userdata =
                _ini.get<cfg::context::rd_shadow_userdata>();
            
            LOG(LOG_INFO,
                "got rd_shadow_type calling create_shadow_session()");
            mod->create_shadow_session(rd_shadow_userdata.c_str(),
                                       rd_shadow_type.c_str());
            _ini.set<cfg::context::rd_shadow_type>("");
        }
    }
    
    if (_mod_wrapper.current_mod == MODULE_INTERNAL_SELECTOR)
    {
        _inactivity.start_timer
            (_ini.get<cfg::globals::session_timeout>(),
             _time_base.get_current_time().tv_sec);
        if (is_first_loop_on_mod_selector)
        {
            LoginLanguage login_lang =
                ::to_login_language(_ini.get<cfg::translation::language>());
            
            _ini.set_acl<cfg::translation::login_language>(login_lang);
            is_first_loop_on_mod_selector = false;
        }
    }
    else if (_mod_wrapper.current_mod == MODULE_INTERNAL_LOGIN)
    {
        _inactivity.stop_timer();
    }
}

void Session::monitoring_data_from_fds_failed(bool& run_session)
{        
    if (errno != EINTR)
    {
        // Cope with EBADF, EINVAL, ENOMEM : none of these should ever happen
        // EBADF: means fd has been closed (by me) or as already returned an error on another call
        // EINVAL: invalid value in timeout (my fault again)
        // ENOMEM: no enough memory in kernel (unlikely fort 3 sockets)
        LOG(LOG_ERR,
            "Proxy data wait loop raised error %d : %s",
            errno,
            strerror(errno));
        run_session = false;
    }
}

bool Session::process_when_front_up_and_running(bool& run_session,
                                                bool& is_first_loop_on_mod_selector,
                                                time_t start_time,
                                                EndSessionWarning& end_session_warning)
{
    throw_error_session_close_if();

    // new value incoming from authentifier
    if (_ini.check_from_acl())
    {
        wabam_settings();
        rt_display();
    }
    display_osd_message(start_time, end_session_warning);
    if (_acl_serial.is_connected()
        && !_keepalive.is_started()
        && _mod_wrapper.is_connected())
    {
        established_target_connection();
    }
    
    if (check_back_event_mod_signal(run_session))
    {
        return true;
    }
    modified_fields_for_sesman(run_session);
    do_actions_depending_on_current_mod(is_first_loop_on_mod_selector);
    return false;
}
