#include "acl/mod_wrapper.hpp"
#include "utils/timebase.hpp"
#include "acl/sesman.hpp"
#include "core/events.hpp"
#include "front/front.hpp"
#include "utils/redirection_info.hpp"
#include "configs/config.hpp"
#include "core/font.hpp"
#include "utils/theme.hpp"
#include "RAIL/client_execute.hpp"
#include "utils/genrandom.hpp"
#include "capture/cryptofile.hpp"
#include "utils/log_siem.hpp"
#include "acl/acl_serializer.hpp"

#include "session_mod_replacer.hpp"

SessionModReplacer::SessionModReplacer(ModWrapper& mod_wrapper,
                                       Inifile& ini,
                                       Front& front,
                                       ClientExecute& rail_client_exec,
                                       Sesman& sesman,
                                       AclSerializer& acl_serial,
                                       TimeBase& time_base,
                                       EventContainer& events,
                                       RedirectionInfo& redir_info,
                                       Font& glyphs,
                                       Theme& theme,
                                       UdevRandom& rnd,
                                       CryptoContext& cctx) :
    _mod_wrapper(mod_wrapper),
    _ini(ini),
    _front(front),
    _rail_client_exec(rail_client_exec),
    _sesman(sesman),
    _acl_serial(acl_serial),
    _mod_factory(mod_wrapper,
                 time_base,
                 sesman,
                 events,
                 front.client_info,
                 front,
                 front,
                 redir_info,
                 ini,
                 glyphs,
                 theme,
                 rail_client_exec,
                 front.keymap,
                 rnd,
                 cctx)
{ }

void SessionModReplacer::replace(ModuleIndex mod_index, ModuleIndex& last_state)
{    
    switch (mod_index)
    {
        case MODULE_RDP :
            on_mod_rdp_asked(last_state);
            break;
        case MODULE_VNC :
            on_mod_vnc_asked(last_state);
            break;
        case MODULE_UNKNOWN :
            on_mod_unknown_asked(last_state);
            break;
        case MODULE_TRANSITORY :
            on_mod_transitory_asked(last_state);
            break;
        case MODULE_INTERNAL :
            on_mod_internal_asked(last_state);
            break;
        case MODULE_INTERNAL_TRANSITION :
            on_mod_internal_transition_asked(last_state);
            break;
        case MODULE_INTERNAL_CLOSE :
            on_mod_internal_close_asked(last_state);
            break;
        case MODULE_INTERNAL_CLOSE_BACK :
            on_mod_internal_close_back_asked(last_state);
            break;
        case MODULE_INTERNAL_LOGIN :
            on_mod_internal_login_asked(last_state);
            break;
        case MODULE_INTERNAL_WAIT_INFO :
            on_mod_internal_wait_info_asked(last_state);
            break;
        case MODULE_INTERNAL_DIALOG_DISPLAY_MESSAGE :
            on_mod_internal_dialog_display_message_asked(last_state);
            break;
        case MODULE_INTERNAL_DIALOG_CHALLENGE :
            on_mod_internal_dialog_challenge_asked(last_state);
            break;
        default :
            on_mod_default_behavior(mod_index, last_state);
            break;
    }
}

void SessionModReplacer::new_mod(ModuleIndex mod_index, ModuleIndex& last_state)
{   
    if (_mod_wrapper.current_mod
        != MODULE_INTERNAL_TRANSITION)
    {
        last_state = _mod_wrapper.current_mod;
        LOG_IF(bool(_ini.get<cfg::debug::session>() & 0x08),
               LOG_INFO,
               "new_mod::changed state Current Mod is %s Previous %s next %s",
               get_module_name(_mod_wrapper.current_mod),
               get_module_name(last_state),
               get_module_name(mod_index));
    }

    if (_mod_wrapper.current_mod != mod_index)
    {
        if ((_mod_wrapper.current_mod == MODULE_RDP)
            || (_mod_wrapper.current_mod == MODULE_VNC))
        {
                _front.must_be_stop_capture();
        }
    }

    auto mod_pack = _mod_factory.create_mod(mod_index);
        
    _mod_wrapper.set_mod(mod_index, mod_pack);
}

// NO MODULE CHANGE INFO YET, ASK MORE FROM ACL
void SessionModReplacer::on_mod_transitory_asked(ModuleIndex& last_state)
{
    /* In case of transitory we are still expecting
       spontaneous data */
    _acl_serial.remote_answer = true;
        
    new_mod(MODULE_INTERNAL_TRANSITION, last_state);
}

void SessionModReplacer::on_mod_rdp_asked(ModuleIndex& last_state)
{
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    log_proxy::set_user
        (_ini.get<cfg::globals::auth_user>().c_str());
    try
    {
        new_mod(MODULE_RDP, last_state);
        if (_ini.get<cfg::globals::bogus_refresh_rect>()
            && _ini.get<cfg::globals::allow_using_multiple_monitors>()
            && (_front.client_info.cs_monitor.monitorCount > 1))
        {
            _mod_wrapper.get_mod()->rdp_suppress_display_updates();
            _mod_wrapper.get_mod()->rdp_allow_display_updates
                (0,
                 0,
                 _front.client_info.screen_info.width,
                 _front.client_info.screen_info.height);
        }
        _mod_wrapper.get_mod()->rdp_input_invalidate
            (Rect(0,
                  0,
                  _front.client_info.screen_info.width,
                  _front.client_info.screen_info.height));
        _ini.set<cfg::context::auth_error_message>("");
    }
    catch (...)
    {
        _sesman.log6(LogId::SESSION_CREATION_FAILED, { });
        _front.must_be_stop_capture();
        throw;
    }
}
    
void SessionModReplacer::on_mod_vnc_asked(ModuleIndex& last_state)
{   
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    log_proxy::set_user
        (_ini.get<cfg::globals::auth_user>().c_str());
                
    try
    {
        new_mod(MODULE_VNC, last_state);        
        _ini.set<cfg::context::auth_error_message>("");
    }
    catch (...)
    {
        _sesman.log6(LogId::SESSION_CREATION_FAILED, {});
        throw;
    }
}

void SessionModReplacer::on_mod_internal_asked(ModuleIndex& last_state)
{
    ModuleIndex mod_index = get_internal_module_id_from_target
        (_ini.get<cfg::context::target_host>());
        
    if (mod_index != last_state)
    {
        _rail_client_exec.enable_remote_program
            (_front.client_info.remote_program);
        log_proxy::set_user
            (_ini.get<cfg::globals::auth_user>().c_str());
        new_mod(mod_index, last_state);
    }
}

void SessionModReplacer::on_mod_internal_transition_asked(ModuleIndex& last_state)
{
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    log_proxy::set_user(_ini.get<cfg::globals::auth_user>()
                        .c_str());
    new_mod(MODULE_INTERNAL_TRANSITION, last_state);
}

void SessionModReplacer::on_mod_unknown_asked(ModuleIndex&)
{
    throw Error(ERR_SESSION_CLOSE_MODULE_NEXT);
}

void SessionModReplacer::on_mod_internal_close_asked(ModuleIndex& last_state)
{
    new_mod(MODULE_INTERNAL_CLOSE, last_state);
}

void SessionModReplacer::on_mod_internal_close_back_asked(ModuleIndex& last_state)
{
    new_mod(MODULE_INTERNAL_CLOSE_BACK, last_state);
}

void SessionModReplacer::on_mod_internal_login_asked(ModuleIndex& last_state)
{        
    log_proxy::set_user("");
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    new_mod(MODULE_INTERNAL_LOGIN, last_state);
}

void SessionModReplacer::on_mod_internal_wait_info_asked(ModuleIndex& last_state)
{
    log_proxy::set_user("");
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    new_mod(MODULE_INTERNAL_WAIT_INFO, last_state);
}

void SessionModReplacer::on_mod_internal_dialog_display_message_asked(ModuleIndex& last_state)
{
    log_proxy::set_user("");
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    new_mod(MODULE_INTERNAL_DIALOG_DISPLAY_MESSAGE,
            last_state);
}
    
void SessionModReplacer::on_mod_internal_dialog_valid_message_asked(ModuleIndex& last_state)
{
    log_proxy::set_user("");
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    new_mod(MODULE_INTERNAL_DIALOG_VALID_MESSAGE, last_state);
}

void SessionModReplacer::on_mod_internal_dialog_challenge_asked(ModuleIndex& last_state)
{
    log_proxy::set_user("");
    _rail_client_exec
        .enable_remote_program(_front.client_info.remote_program);
    new_mod(MODULE_INTERNAL_DIALOG_CHALLENGE, last_state);
}

void SessionModReplacer::on_mod_default_behavior(ModuleIndex mod_index,
                                                 ModuleIndex& last_state)
{
    log_proxy::set_user
        (_ini.get<cfg::globals::auth_user>().c_str());
    new_mod(mod_index, last_state);
}
