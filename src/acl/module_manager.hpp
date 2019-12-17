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
  Copyright (C) Wallix 2010
  Author(s): Christophe Grosjean, Javier Caverni, Xavier Dunat,
             Raphael Zhou, Meng Tan

  Manage Modules Life cycle : creation, destruction and chaining
  find out the next module to run from context reading
*/

#pragma once

#include "acl/mod_osd.hpp"
#include "acl/end_session_warning.hpp"

#include "acl/module_manager/mod_factory.hpp"
#include "acl/auth_api.hpp"
#include "acl/file_system_license_store.hpp"
#include "acl/module_manager/enums.hpp"
#include "configs/config.hpp"
#include "core/log_id.hpp"
#include "core/session_reactor.hpp"
#include "front/front.hpp"
#include "gdi/protected_graphics.hpp"

#include "mod/internal/rail_module_host_mod.hpp"

#include "mod/mod_api.hpp"
#include "mod/null/null.hpp"
#include "mod/rdp/windowing_api.hpp"
#include "mod/xup/xup.hpp"

#include "transport/socket_transport.hpp"

#include "utils/load_theme.hpp"
#include "utils/netutils.hpp"
#include "utils/sugar/algostring.hpp"
#include "utils/sugar/scope_exit.hpp"
#include "utils/sugar/update_lock.hpp"
#include "utils/log_siem.hpp"
#include "utils/fileutils.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "acl/module_manager/enums.hpp"
#include "core/back_event_t.hpp"

#include "core/session_reactor.hpp"
#include "acl/mod_wrapper.hpp"
#include "acl/time_before_closing.hpp"

class rdp_api;
class AuthApi;
class ReportMessageApi;

class ModuleManager
{
    ModFactory & mod_factory;
    ModWrapper & mod_wrapper;
public:

    ModWrapper & get_mod_wrapper() const
    {
        return mod_wrapper;
    }

    mod_api* get_mod()
    {
        return this->mod_wrapper.get_mod();
    }

    [[nodiscard]] mod_api const* get_mod() const
    {
        return this->mod_wrapper.get_mod();
    }

public:
    bool last_module{false};
    bool connected{false};

    bool is_connected() {
        return this->connected;
    }
    bool is_up_and_running() {
        return this->mod_wrapper.is_up_and_running();
    }

    Inifile& ini;
    SessionReactor& session_reactor;
    CryptoContext & cctx;

    FileSystemLicenseStore file_system_license_store{ app_path(AppPath::License).to_string() };

    class sock_mod_barrier {};

    template<class Mod>
    class ModWithSocket final : public mod_api
    {
        SocketTransport socket_transport;
    public:
        Mod mod;
    private:
        ModOSD & mod_osd;
        ModWrapper & mod_wrapper;
        Inifile & ini;
        bool target_info_is_shown = false;

    public:
        template<class... Args>
        ModWithSocket(ModWrapper & mod_wrapper, ModOSD & mod_osd, Inifile & ini, AuthApi & /*authentifier*/,
            const char * name, unique_fd sck, uint32_t verbose,
            std::string * error_message, sock_mod_barrier /*unused*/, Args && ... mod_args)
        : socket_transport( name, std::move(sck)
                         , ini.get<cfg::context::target_host>().c_str()
                         , ini.get<cfg::context::target_port>()
                         , std::chrono::milliseconds(ini.get<cfg::globals::mod_recv_timeout>())
                         , to_verbose_flags(verbose), error_message)
        , mod(this->socket_transport, std::forward<Args>(mod_args)...)
        , mod_osd(mod_osd)
        , mod_wrapper(mod_wrapper)
        , ini(ini)
        {
            this->mod_wrapper.set_psocket_transport(&this->socket_transport);
        }

        ~ModWithSocket()
        {
            this->mod_wrapper.set_psocket_transport(nullptr);
            log_proxy::target_disconnection(
                this->ini.template get<cfg::context::auth_error_message>().c_str());
        }

        // from RdpInput
        void rdp_input_scancode(long param1, long param2, long param3, long param4, Keymap2 * keymap) override
        {
            //LOG(LOG_INFO, "mod_osd::rdp_input_scancode: keyCode=0x%X keyboardFlags=0x%04X this=<%p>", param1, param3, this);
            if (this->mod_osd.try_input_scancode(param1, param2, param3, param4, keymap)) {
                this->target_info_is_shown = false;
                return ;
            }

            this->mod.rdp_input_scancode(param1, param2, param3, param4, keymap);

            Inifile const& ini = this->ini;

            if (ini.get<cfg::globals::enable_osd_display_remote_target>() && (param1 == Keymap2::F12)) {
                bool const f12_released = (param3 & SlowPath::KBDFLAGS_RELEASE);
                if (this->target_info_is_shown && f12_released) {
                    // LOG(LOG_INFO, "Hide info");
                    this->mod_osd.clear_osd_message();
                    this->target_info_is_shown = false;
                }
                else if (!this->target_info_is_shown && !f12_released) {
                    // LOG(LOG_INFO, "Show info");
                    std::string msg;
                    msg.reserve(64);
                    if (ini.get<cfg::client::show_target_user_in_f12_message>()) {
                        msg  = ini.get<cfg::globals::target_user>();
                        msg += "@";
                    }
                    msg += ini.get<cfg::globals::target_device>();
                    const uint32_t enddate = ini.get<cfg::context::end_date_cnx>();
                    if (enddate) {
                        const auto now = time(nullptr);
                        const auto elapsed_time = enddate - now;
                        // only if "reasonable" time
                        if (elapsed_time < 60*60*24*366L) {
                            msg += "  [";
                            msg += time_before_closing(elapsed_time, Translator(ini));
                            msg += ']';
                        }
                    }
                    this->mod_osd.osd_message_fn(std::move(msg), false);
                    this->target_info_is_shown = true;
                }
            }
        }

        // from RdpInput
        void rdp_input_mouse(int device_flags, int x, int y, Keymap2 * keymap) override
        {
            if (this->mod_osd.try_input_mouse(device_flags, x, y, keymap)) {
                this->target_info_is_shown = false;
                return ;
            }

            this->mod.rdp_input_mouse(device_flags, x, y, keymap);
        }

        // from RdpInput
        void rdp_input_unicode(uint16_t unicode, uint16_t flag) override {
            this->mod.rdp_input_unicode(unicode, flag);
        }

        // from RdpInput
        void rdp_input_invalidate(const Rect r) override
        {
            if (this->mod_osd.try_input_invalidate(r)) {
                return ;
            }

            this->mod.rdp_input_invalidate(r);
        }

        // from RdpInput
        void rdp_input_invalidate2(array_view<Rect const> vr) override
        {
            if (this->mod_osd.try_input_invalidate2(vr)) {
                return ;
            }

            this->mod.rdp_input_invalidate2(vr);
        }

        // from RdpInput
        void rdp_input_synchronize(uint32_t time, uint16_t device_flags, int16_t param1, int16_t param2) override
        {
            return this->mod.rdp_input_synchronize(time, device_flags, param1, param2);
        }

        void refresh(Rect clip) override
        {
            return this->mod.refresh(clip);
        }

        // from mod_api
        [[nodiscard]] bool is_up_and_running() const override { return false; }

        // from mod_api
        // support auto-reconnection
        bool is_auto_reconnectable() override {
            return this->mod.is_auto_reconnectable();
        }

        // from mod_api
        void disconnect() override 
        {
            return this->mod.disconnect();
        }

        // from mod_api
        void display_osd_message(std::string const & message) override 
        {
            this->mod_osd.osd_message_fn(message, true);
            //return this->mod.display_osd_message(message);
        }

        // from mod_api
        void move_size_widget(int16_t left, int16_t top, uint16_t width, uint16_t height) override
        {
            return this->mod.move_size_widget(left, top, width, height);
        }

        // from mod_api
        bool disable_input_event_and_graphics_update(bool disable_input_event, bool disable_graphics_update) override 
        {
            return this->mod.disable_input_event_and_graphics_update(disable_input_event, disable_graphics_update);
        }

        // from mod_api
        void send_input(int time, int message_type, int device_flags, int param1, int param2) override 
        {
            return this->mod.send_input(time, message_type, device_flags, param1, param2);
        }

        // from mod_api
        [[nodiscard]] Dimension get_dim() const override 
        {
            return this->mod.get_dim();
        }

        // from mod_api
        void log_metrics() override 
        {
            return this->mod.log_metrics();
        }

        // from mod_api
        void DLP_antivirus_check_channels_files() override
        {
            return this->mod.DLP_antivirus_check_channels_files(); 
        }
    };


public:
    void DLP_antivirus_check_channels_files() {
        this->get_mod_wrapper().mod->DLP_antivirus_check_channels_files();
    }

    gdi::GraphicApi & get_graphic_wrapper()
    {
        gdi::GraphicApi& gd = this->mod_osd.get_protected_rect().isempty()
          ? this->graphics : this->mod_osd;
        if (this->rail_module_host_mod_ptr) {
            return this->rail_module_host_mod_ptr->proxy_gd(gd);
        }
        return gd;
    }

    Callback & get_callback() noexcept
    {
        return *this->get_mod_wrapper().mod;
    }

private:
    RailModuleHostMod* rail_module_host_mod_ptr = nullptr;
    FrontAPI & front;
    gdi::GraphicApi & graphics;
    Keymap2 & keymap;
    ClientInfo & client_info;
    ClientExecute & rail_client_execute;
    ModOSD & mod_osd;
    Random & gen;
    TimeObj & timeobj;

    std::array<uint8_t, 28> server_auto_reconnect_packet {};

    ModuleIndex old_target_module = MODULE_UNKNOWN;

public:


    REDEMPTION_VERBOSE_FLAGS(private, verbose)
    {
        none,
        new_mod = 0x1,
    };

    int validator_fd = -1;

private:
    rdp_api*       rdpapi = nullptr;

    windowing_api* &winapi;

    EndSessionWarning & end_session_warning;
    Font & glyphs;
    Theme & theme;

public:
    ModuleManager(EndSessionWarning & end_session_warning, ModFactory & mod_factory, SessionReactor& session_reactor, FrontAPI & front, gdi::GraphicApi & graphics, Keymap2 & keymap, ClientInfo & client_info, windowing_api* &winapi, ModWrapper & mod_wrapper, ClientExecute & rail_client_execute, ModOSD & mod_osd, Font & glyphs, Theme & theme, Inifile & ini, CryptoContext & cctx, Random & gen, TimeObj & timeobj)
        : mod_factory(mod_factory)
        , mod_wrapper(mod_wrapper)
        , ini(ini)
        , session_reactor(session_reactor)
        , cctx(cctx)
        , front(front)
        , graphics(graphics)
        , keymap(keymap)
        , client_info(client_info)
        , rail_client_execute(rail_client_execute)
        , mod_osd(mod_osd)
        , gen(gen)
        , timeobj(timeobj)
        , verbose(static_cast<Verbose>(ini.get<cfg::debug::auth>()))
        , winapi(winapi)
        , end_session_warning(end_session_warning)
        , glyphs(glyphs)
        , theme(theme)
    {
    }

    void remove_mod()
    {
        if (this->get_mod_wrapper().has_mod()){
            this->mod_osd.clear_osd_message();
            this->get_mod_wrapper().remove_mod();
            this->rdpapi = nullptr;
            this->winapi = nullptr;
            this->rail_module_host_mod_ptr = nullptr;
        }
    }

    ~ModuleManager()
    {
        this->remove_mod();
    }

private:
    void set_mod(not_null_ptr<mod_api> mod, rdp_api* rdpapi = nullptr, windowing_api* winapi = nullptr)
    {
        while (this->keymap.nb_char_available()) {
            this->keymap.get_char();
        }
        while (this->keymap.nb_kevent_available()) {
            this->keymap.get_kevent();
        }

        this->mod_osd.clear_osd_message();

        this->get_mod_wrapper().set_mod(mod.get());

        this->rail_module_host_mod_ptr = nullptr;
        this->rdpapi = rdpapi;
        this->winapi = winapi;
    }

public:
    void new_mod(ModuleIndex target_module, AuthApi & authentifier, ReportMessageApi & report_message)
    {
        if (target_module != MODULE_INTERNAL_TRANSITION) {
            LOG(LOG_INFO, "----------> ACL new_mod <--------");
            LOG(LOG_INFO, "target_module=%s(%d)",
                get_module_name(target_module), target_module);
        }

        this->rail_client_execute.enable_remote_program(this->client_info.remote_program);

        switch (target_module) {
        case MODULE_INTERNAL_CLOSE:
        case MODULE_INTERNAL_WIDGET_LOGIN:
            log_proxy::set_user("");
            break;
        default:
            log_proxy::set_user(this->ini.get<cfg::globals::auth_user>().c_str());
            break;
        }

        this->connected = false;

        if (this->old_target_module != target_module) {
            this->front.must_be_stop_capture();

            auto is_remote_mod = [](int mod_type){
                return
                    (mod_type == MODULE_XUP)
                 || (mod_type == MODULE_RDP)
                 || (mod_type == MODULE_VNC);
            };

            if (is_remote_mod(this->old_target_module)) {
                authentifier.delete_remote_mod();
            }

            if (is_remote_mod(target_module)) {
                authentifier.new_remote_mod();
            }
        }
        this->old_target_module = target_module;

        if ((target_module == MODULE_INTERNAL_WIDGET_SELECTOR)
        && (report_message.get_inactivity_timeout() != this->ini.get<cfg::globals::session_timeout>().count())) {
            report_message.update_inactivity_timeout();
        }


        switch (target_module)
        {
        case MODULE_INTERNAL_BOUNCER2:
            this->set_mod(mod_factory.create_mod_bouncer());
        break;
        case MODULE_INTERNAL_TEST:
            this->set_mod(mod_factory.create_mod_replay());
        break;
        case MODULE_INTERNAL_WIDGETTEST:
            this->set_mod(mod_factory.create_widget_test_mod());
        break;
        case MODULE_INTERNAL_CARD:
            this->set_mod(mod_factory.create_test_card_mod());
        break;
        case MODULE_INTERNAL_WIDGET_SELECTOR:
            this->set_mod(mod_factory.create_selector_mod());
        break;
        case MODULE_INTERNAL_CLOSE:
            this->set_mod(mod_factory.create_close_mod());
        break;
        case MODULE_INTERNAL_CLOSE_BACK:
            this->set_mod(mod_factory.create_close_mod_back_to_selector());
        break;
        case MODULE_INTERNAL_TARGET:
            this->set_mod(mod_factory.create_interactive_target_mod());
        break;
        case MODULE_INTERNAL_DIALOG_VALID_MESSAGE:
            this->set_mod(mod_factory.create_valid_message_mod());
        break;
        case MODULE_INTERNAL_DIALOG_DISPLAY_MESSAGE:
            this->set_mod(mod_factory.create_display_message_mod());
        break;
        case MODULE_INTERNAL_DIALOG_CHALLENGE:
            this->set_mod(mod_factory.create_dialog_challenge_mod());
        break;
        case MODULE_INTERNAL_WAIT_INFO:
            this->set_mod(mod_factory.create_wait_info_mod());
        break;
        case MODULE_INTERNAL_TRANSITION:
            this->set_mod(mod_factory.create_transition_mod());
        break;
        case MODULE_INTERNAL_WIDGET_LOGIN: 
            this->set_mod(mod_factory.create_login_mod());
        break;

        case MODULE_XUP: {
            unique_fd client_sck = this->connect_to_target_host(
                    report_message, trkeys::authentification_x_fail);

            this->set_mod(mod_factory.create_xup_mod(client_sck));

            this->ini.get_mutable_ref<cfg::context::auth_error_message>().clear();
            this->connected = true;
            break;
        }

        case MODULE_RDP:
            this->create_mod_rdp(
                authentifier, report_message, this->ini,
                this->graphics, this->front, this->client_info,
                this->rail_client_execute, this->keymap.key_flags,
                this->server_auto_reconnect_packet);
            break;

        case MODULE_VNC:
            this->create_mod_vnc(
                authentifier, report_message, this->ini,
                this->graphics, this->front, this->client_info,
                this->rail_client_execute, this->keymap.key_flags);
            break;

        default:
            LOG(LOG_INFO, "ModuleManager::Unknown backend exception");
            throw Error(ERR_SESSION_UNKNOWN_BACKEND);
        }
    }

    [[nodiscard]] rdp_api* get_rdp_api() const {
        return this->rdpapi;
    }

    void invoke_close_box(
        bool enable_close_box,
        const char * auth_error_message, BackEvent_t & signal,
        AuthApi & authentifier, ReportMessageApi & report_message)
    {
        LOG(LOG_INFO, "----------> ACL invoke_close_box <--------");
        this->last_module = true;
        if (auth_error_message) {
            this->ini.set<cfg::context::auth_error_message>(auth_error_message);
        }
        if (this->get_mod_wrapper().has_mod()) {
            try {
                this->get_mod_wrapper().mod->disconnect();
            }
            catch (Error const& e) {
                LOG(LOG_INFO, "MMIni::invoke_close_box exception = %u!", e.id);
            }
        }

        this->remove_mod();
        if (enable_close_box) {
            this->new_mod(MODULE_INTERNAL_CLOSE, authentifier, report_message);
            signal = BACK_EVENT_NONE;
        }
        else {
            signal = BACK_EVENT_STOP;
        }
    }

    ModuleIndex next_module()
    {
        auto & module_cstr = this->ini.get<cfg::context::module>();
        auto module_id = get_module_id(module_cstr);
        LOG(LOG_INFO, "----------> ACL next_module : %s %u <--------", module_cstr, unsigned(module_id));

        if (this->connected && ((module_id == MODULE_RDP)||(module_id == MODULE_VNC))) {
            LOG(LOG_INFO, "===========> Connection close asked by admin while connected");
            if (this->ini.get<cfg::context::auth_error_message>().empty()) {
                this->ini.set<cfg::context::auth_error_message>(TR(trkeys::end_connection, language(this->ini)));
            }
            return MODULE_INTERNAL_CLOSE;
        }
        if (module_id == MODULE_INTERNAL)
        {
            auto module_id = get_internal_module_id_from_target(this->ini.get<cfg::context::target_host>());
            LOG(LOG_INFO, "===========> %s (from target)", get_module_name(module_id));
            return module_id;
        }
        if (module_id == MODULE_UNKNOWN)
        {
            LOG(LOG_INFO, "===========> UNKNOWN MODULE (closing)");
            return MODULE_INTERNAL_CLOSE;
        }
        return module_id;
    }

    void check_module() 
    {
        if (this->ini.get<cfg::context::forcemodule>() && !this->is_connected()) {
            this->session_reactor.set_next_event(BACK_EVENT_NEXT);
            this->ini.set<cfg::context::forcemodule>(false);
            // Do not send back the value to sesman.
        }
    }

private:
    unique_fd connect_to_target_host(ReportMessageApi& report_message, trkeys::TrKey const& authentification_fail)
    {
        auto throw_error = [this, &report_message](char const* error_message, int id) {
            LOG_PROXY_SIEM("TARGET_CONNECTION_FAILED",
                R"(target="%s" host="%s" port="%u" reason="%s")",
                this->ini.get<cfg::globals::target_user>(),
                this->ini.get<cfg::context::target_host>(),
                this->ini.get<cfg::context::target_port>(),
                error_message);

            report_message.log6(LogId::CONNECTION_FAILED, this->session_reactor.get_current_time(), {});

            this->ini.set<cfg::context::auth_error_message>(TR(trkeys::target_fail, language(this->ini)));

            LOG(LOG_ERR, "%s", (id == 1)
                ? "Failed to connect to remote TCP host (1)"
                : "Failed to connect to remote TCP host (2)");
            throw Error(ERR_SOCKET_CONNECT_FAILED);
        };

        LOG_PROXY_SIEM("TARGET_CONNECTION",
            R"(target="%s" host="%s" port="%u")",
            this->ini.get<cfg::globals::target_user>(),
            this->ini.get<cfg::context::target_host>(),
            this->ini.get<cfg::context::target_port>());

        const char * ip = this->ini.get<cfg::context::target_host>().c_str();
        char ip_addr[256] {};
        in_addr s4_sin_addr;
        if (auto error_message = resolve_ipv4_address(ip, s4_sin_addr)) {
            // TODO: actually this is DNS Failure or invalid address
            throw_error(error_message, 1);
        }

        snprintf(ip_addr, sizeof(ip_addr), "%s", inet_ntoa(s4_sin_addr));

        char const* error_message = nullptr;
        unique_fd client_sck = ip_connect(ip, this->ini.get<cfg::context::target_port>(), &error_message);

        if (!client_sck.is_open()) {
            throw_error(error_message, 2);
        }

        this->ini.set<cfg::context::auth_error_message>(TR(authentification_fail, language(this->ini)));
        this->ini.set<cfg::context::ip_target>(ip_addr);

        return client_sck;
    }


    void create_mod_rdp(
        AuthApi& authentifier, ReportMessageApi& report_message,
        Inifile& ini, gdi::GraphicApi & drawable, FrontAPI& front, ClientInfo client_info,
        ClientExecute& rail_client_execute, Keymap2::KeyFlags key_flags,
        std::array<uint8_t, 28>& server_auto_reconnect_packet);

    void create_mod_vnc(
        AuthApi& authentifier, ReportMessageApi& report_message,
        Inifile& ini, gdi::GraphicApi & drawable, FrontAPI& front, ClientInfo const& client_info,
        ClientExecute& rail_client_execute, Keymap2::KeyFlags key_flags);
};
