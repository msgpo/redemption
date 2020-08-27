#pragma once

#include "acl/module_manager/enums.hpp"
#include "acl/module_manager/mod_factory.hpp"

class ModWrapper;
class Inifile;
class Front;
class ClientExecute;
class Sesman;
class AclSerializer;
class TimeBase;
class EventContainer;
class RedirectionInfo;
class Font;
class Theme;
class UdevRandom;
class CryptoContext;

class SessionModReplacer
{
public :
    SessionModReplacer(ModWrapper& mod_wrapper,
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
                       CryptoContext& cctx);
    void replace(ModuleIndex mod_index, ModuleIndex& last_state);
    
private :
    ModWrapper& _mod_wrapper;
    Inifile& _ini;
    Front& _front;
    ClientExecute& _rail_client_exec;
    Sesman& _sesman;
    AclSerializer& _acl_serial;
    ModFactory _mod_factory;

    void new_mod(ModuleIndex mod_index, ModuleIndex& last_state);
    void on_mod_transitory_asked(ModuleIndex& last_state);
    void on_mod_rdp_asked(ModuleIndex& last_state);
    void on_mod_vnc_asked(ModuleIndex& last_state);
    void on_mod_internal_asked(ModuleIndex& last_state);
    void on_mod_internal_transition_asked(ModuleIndex& last_state);
    void on_mod_unknown_asked(ModuleIndex&);
    void on_mod_internal_close_asked(ModuleIndex& last_state);
    void on_mod_internal_close_back_asked(ModuleIndex& last_state);
    void on_mod_internal_login_asked(ModuleIndex& last_state);
    void on_mod_internal_wait_info_asked(ModuleIndex& last_state);
    void on_mod_internal_dialog_display_message_asked(ModuleIndex& last_state);
    void on_mod_internal_dialog_valid_message_asked(ModuleIndex& last_state);
    void on_mod_internal_dialog_challenge_asked(ModuleIndex& last_state);
    void on_mod_default_behavior(ModuleIndex mod_index, ModuleIndex& last_state);
};
