#pragma once

#include "acl/module_manager/enums.hpp"
#include "acl/end_session_result.hpp"

class ModWrapper;
class Inifile;
class RedirectionInfo;
class Sesman;
class KeepAlive;
class ClientExecute;
class Inactivity;
class SessionModReplacer;
class AclSerializer;
class Front;
class Error;

class EndSessionError
{
public :
    EndSessionError(ModWrapper& mod_wrapper,
                    Inifile& ini,
                    RedirectionInfo& redir_info,
                    Sesman& sesman,
                    KeepAlive& keepalive,
                    ClientExecute& rail_client_exec,
                    Inactivity& inactivity,
                    SessionModReplacer& session_mod_replacer,
                    AclSerializer& acl_serial,
                    Front& front);
    
    void on_error(const Error& e, bool& run_session, ModuleIndex& last_state);

private :
    ModWrapper& _mod_wrapper;
    Inifile& _ini;
    RedirectionInfo& _redir_info;
    Sesman& _sesman;
    KeepAlive& _keepalive;
    ClientExecute& _rail_client_exec;
    Inactivity& _inactivity;
    SessionModReplacer& _session_mod_replacer;
    AclSerializer& _acl_serial;
    Front& _front;
    
    EndSessionResult end_session_exception(const Error& e);
    void on_close_box(bool& run_session, ModuleIndex& last_state);
    void on_redirection();
    void on_retry(ModuleIndex& last_state);
};
