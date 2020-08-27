#include "core/error.hpp"
#include "utils/log.hpp"
#include "utils/translation.hpp"
#include "acl/end_session_result.hpp"
#include "acl/mod_wrapper.hpp"
#include "configs/config.hpp"
#include "utils/redirection_info.hpp"
#include "acl/sesman.hpp"
#include "acl/keep_alive.hpp"
#include "RAIL/client_execute.hpp"
#include "acl/inactivity.hpp"
#include "acl/session_mod_replacer.hpp"
#include "acl/acl_serializer.hpp"
#include "front/front.hpp"

#include "end_session_error.hpp"

EndSessionError::EndSessionError(ModWrapper& mod_wrapper,
                                 Inifile& ini,
                                 RedirectionInfo& redir_info,
                                 Sesman& sesman,
                                 KeepAlive& keepalive,
                                 ClientExecute& rail_client_exec,
                                 Inactivity& inactivity,
                                 SessionModReplacer& session_mod_replacer,
                                 AclSerializer& acl_serial,
                                 Front& front) :
    _mod_wrapper(mod_wrapper),
    _ini(ini),
    _redir_info(redir_info),
    _sesman(sesman),
    _keepalive(keepalive),
    _rail_client_exec(rail_client_exec),
    _inactivity(inactivity),
    _session_mod_replacer(session_mod_replacer),
    _acl_serial(acl_serial),
    _front(front)
{ }

void EndSessionError::on_error(const Error& e,
                               bool& run_session,
                               ModuleIndex& last_state)
{
    switch (end_session_exception(e))
    {
        case EndSessionResult::close_box :
            on_close_box(run_session, last_state);
            break;
        case EndSessionResult::redirection :
            on_redirection();
            REDEMPTION_CXX_FALLTHROUGH;
        case EndSessionResult::retry :
            on_retry(last_state);
    }
}

EndSessionResult EndSessionError::end_session_exception(const Error& e)
{
    if (e.id == ERR_RAIL_LOGON_FAILED_OR_WARNING)
    {
        _ini.set_acl<cfg::context::session_probe_launch_error_message>
            (local_err_msg(e, language(_ini)));
    }

    if ((e.id == ERR_SESSION_PROBE_LAUNCH)
        ||  (e.id == ERR_SESSION_PROBE_ASBL_FSVC_UNAVAILABLE)
        ||  (e.id == ERR_SESSION_PROBE_ASBL_MAYBE_SOMETHING_BLOCKS)
        ||  (e.id == ERR_SESSION_PROBE_ASBL_UNKNOWN_REASON)
        ||  (e.id == ERR_SESSION_PROBE_CBBL_FSVC_UNAVAILABLE)
        ||  (e.id == ERR_SESSION_PROBE_CBBL_CBVC_UNAVAILABLE)
        ||  (e.id == ERR_SESSION_PROBE_CBBL_DRIVE_NOT_READY_YET)
        ||  (e.id == ERR_SESSION_PROBE_CBBL_MAYBE_SOMETHING_BLOCKS)
        ||  (e.id == ERR_SESSION_PROBE_CBBL_LAUNCH_CYCLE_INTERRUPTED)
        ||  (e.id == ERR_SESSION_PROBE_CBBL_UNKNOWN_REASON_REFER_TO_SYSLOG)
        ||  (e.id == ERR_SESSION_PROBE_RP_LAUNCH_REFER_TO_SYSLOG))
     {
         if (_ini.get<cfg::mod_rdp::session_probe_on_launch_failure>()
             == SessionProbeOnLaunchFailure::retry_without_session_probe)
         {
             LOG(LOG_INFO, "Retry connection without session probe");
             _ini.set<cfg::mod_rdp::enable_session_probe>(false);
             return EndSessionResult::retry;
         }
         _ini.set<cfg::context::auth_error_message>
             (local_err_msg(e, language(_ini)));
         return EndSessionResult::close_box;
     }
    else if (e.id == ERR_SESSION_PROBE_DISCONNECTION_RECONNECTION)
    {
        LOG(LOG_INFO, "Retry Session Probe Disconnection Reconnection");
        return EndSessionResult::close_box;
    }
    else if (e.id == ERR_AUTOMATIC_RECONNECTION_REQUIRED)
    {
        LOG(LOG_INFO, "Retry Automatic Reconnection Required");
        _ini.set<cfg::context::perform_automatic_reconnection>(true);
        return EndSessionResult::retry;
    }
    else if (e.id == ERR_RAIL_NOT_ENABLED)
    {
        LOG(LOG_INFO, "Retry without native remoteapp capability");
        _ini.set<cfg::mod_rdp::use_native_remoteapp_capability>(false);
        return EndSessionResult::retry;
    }
    else if (e.id == ERR_RDP_SERVER_REDIR)
    {
        if (_ini.get<cfg::mod_rdp::server_redirection_support>())
        {
            LOG(LOG_INFO, "Server redirection");
            return EndSessionResult::redirection;
        }
        else
        {
            LOG(LOG_ERR,
                "Start Session Failed: forbidden redirection = %s",
                e.errmsg());
            _ini.set<cfg::context::auth_error_message>
                (local_err_msg(e, language(_ini)));
            return EndSessionResult::close_box;
        }
    }
    else if (e.id == ERR_SESSION_CLOSE_ENDDATE_REACHED)
    {
        LOG(LOG_INFO, "Close because disconnection time reached");
        _ini.set<cfg::context::auth_error_message>
            (TR(trkeys::session_out_time, language(_ini)));
        return EndSessionResult::close_box;
    }
    else if (e.id == ERR_MCS_APPID_IS_MCS_DPUM)
    {
        LOG(LOG_INFO, "Remote Session Closed by User");
        _ini.set<cfg::context::auth_error_message>
            (TR(trkeys::end_connection, language(_ini)));
        return EndSessionResult::close_box;
    }
    else if (e.id == ERR_SESSION_CLOSE_REJECTED_BY_ACL_MESSAGE)
    {
        // Close by rejeted message received
        _ini.set<cfg::context::auth_error_message>
            (_ini.get<cfg::context::rejected>());
        LOG(LOG_INFO,
            "Close because rejected message was received : %s",
            _ini.get<cfg::context::rejected>());
        _ini.set_acl<cfg::context::rejected>("");
        return EndSessionResult::close_box;
    }
    else if (e.id == ERR_SESSION_CLOSE_ACL_KEEPALIVE_MISSED)
    {
        LOG(LOG_INFO, "Close because of missed ACL keepalive");
        _ini.set<cfg::context::auth_error_message>
            (TR(trkeys::miss_keepalive, language(_ini)));
        return EndSessionResult::close_box;
    }
    else if (e.id == ERR_SESSION_CLOSE_USER_INACTIVITY)
    {
        LOG(LOG_INFO, "Close because of user Inactivity");
        _ini.set<cfg::context::auth_error_message>
            (TR(trkeys::close_inactivity, language(_ini)));
        return EndSessionResult::close_box;
    }
    else if (e.id == ERR_SESSION_CLOSE_MODULE_NEXT)
    {
        LOG(LOG_INFO, "Acl confirmed user close");
        return EndSessionResult::close_box;
    }
    else if ((e.id == ERR_TRANSPORT_WRITE_FAILED
              || e.id == ERR_TRANSPORT_NO_MORE_DATA)
             && _mod_wrapper.get_mod_transport()
             && _mod_wrapper.get_mod_transport()->sck == e.data
             && _ini.get<cfg::mod_rdp::auto_reconnection_on_losing_target_link>()
             && _mod_wrapper.get_mod()->is_auto_reconnectable()
             && !_mod_wrapper.get_mod()->server_error_encountered())
    {
        LOG(LOG_INFO,
            "Session::end_session_exception: target link exception. %s",
            ERR_TRANSPORT_WRITE_FAILED == e.id ? "ERR_TRANSPORT_WRITE_FAILED" : "ERR_TRANSPORT_NO_MORE_DATA");
        _ini.set<cfg::context::perform_automatic_reconnection>(true);
        return EndSessionResult::retry;
    }

    LOG(LOG_INFO,
        "ModTrans=<%p> Sock=%d AutoReconnection=%s AutoReconnectable=%s ErrorEncountered=%s",
        _mod_wrapper.get_mod_transport(),
        (_mod_wrapper.get_mod_transport() ? _mod_wrapper.get_mod_transport()->sck : -1),
        (_ini.get<cfg::mod_rdp::auto_reconnection_on_losing_target_link>() ? "Yes" : "No"),
        (_mod_wrapper.get_mod()->is_auto_reconnectable() ? "Yes" : "No"),
        (_mod_wrapper.get_mod()->server_error_encountered() ? "Yes" : "No"));
        
    _ini.set<cfg::context::auth_error_message>
        (local_err_msg(e, language(_ini)));
    return EndSessionResult::close_box;
}

void EndSessionError::on_close_box(bool& run_session, ModuleIndex& last_state)
{
    _keepalive.stop();
    _sesman.set_disconnect_target();
    _mod_wrapper.disconnect();
    if (_ini.get<cfg::globals::enable_close_box>())
    {
        _rail_client_exec.enable_remote_program
            (_front.client_info.remote_program);
        _session_mod_replacer.replace(MODULE_INTERNAL_CLOSE_BACK,
                                      last_state);
        _mod_wrapper.get_mod()->set_mod_signal(BACK_EVENT_NONE);
        run_session = true;
        _inactivity.stop_timer();
    }
    else
    {
        LOG(LOG_INFO, "Close Box disabled : ending session");
    }
}

void EndSessionError::on_redirection()
{
    // SET new target in ini
    const char *host = char_ptr_cast(_redir_info.host);
    const char *password = char_ptr_cast(_redir_info.password);
    const char *username = char_ptr_cast(_redir_info.username);
    const char *change_user = "";
                        
    if (_redir_info.dont_store_username && username[0] != 0)
    {
        LOG(LOG_INFO,
            "SrvRedir: Change target username to '%s'",
            username);
        _ini.set_acl<cfg::globals::target_user>(username);
        change_user = username;
    }
    if (password[0] != 0)
    {
        LOG(LOG_INFO, "SrvRedir: Change target password");
        _ini.set_acl<cfg::context::target_password>(password);
    }
    LOG(LOG_INFO,
        "SrvRedir: Change target host to '%s'",
        host);
    _ini.set_acl<cfg::context::target_host>(host);
            
    auto message = str_concat(change_user, '@', host);
            
    _sesman.report("SERVER_REDIRECTION", message.c_str());
}

void EndSessionError::on_retry(ModuleIndex& last_state)
{    
    LOG(LOG_INFO, "Retry RDP");
    _acl_serial.remote_answer = false;
    _session_mod_replacer.replace(MODULE_RDP, last_state);
}
