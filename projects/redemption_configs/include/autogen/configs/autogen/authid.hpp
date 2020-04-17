//
// DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
//

#pragma once

enum authid_t : unsigned {
    AUTHID_GLOBALS_CAPTURE_CHUNK,
    AUTHID_GLOBALS_AUTH_USER,
    AUTHID_GLOBALS_HOST,
    AUTHID_GLOBALS_TARGET,
    AUTHID_GLOBALS_TARGET_DEVICE,
    AUTHID_GLOBALS_DEVICE_ID,
    AUTHID_GLOBALS_PRIMARY_USER_ID,
    AUTHID_GLOBALS_TARGET_USER,
    AUTHID_GLOBALS_TARGET_APPLICATION,
    AUTHID_GLOBALS_TARGET_APPLICATION_ACCOUNT,
    AUTHID_GLOBALS_TARGET_APPLICATION_PASSWORD,
    AUTHID_GLOBALS_INACTIVITY_TIMEOUT,
    AUTHID_GLOBALS_TRACE_TYPE,
    AUTHID_GLOBALS_IS_REC,
    AUTHID_GLOBALS_MOVIE_PATH,
    AUTHID_GLOBALS_UNICODE_KEYBOARD_EVENT_SUPPORT,
    AUTHID_GLOBALS_MOD_RECV_TIMEOUT,
    AUTHID_SESSION_LOG_LOG_PATH,
    AUTHID_SESSION_LOG_KEYBOARD_INPUT_MASKING_LEVEL,
    AUTHID_CLIENT_KEYBOARD_LAYOUT,
    AUTHID_CLIENT_DISABLE_TSK_SWITCH_SHORTCUTS,
    AUTHID_MOD_RDP_ENABLE_NLA,
    AUTHID_MOD_RDP_ENABLE_KERBEROS,
    AUTHID_MOD_RDP_SERVER_REDIRECTION_SUPPORT,
    AUTHID_MOD_RDP_LOAD_BALANCE_INFO,
    AUTHID_MOD_RDP_BOGUS_SC_NET_SIZE,
    AUTHID_MOD_RDP_PROXY_MANAGED_DRIVES,
    AUTHID_MOD_RDP_IGNORE_AUTH_CHANNEL,
    AUTHID_MOD_RDP_ALTERNATE_SHELL,
    AUTHID_MOD_RDP_SHELL_ARGUMENTS,
    AUTHID_MOD_RDP_SHELL_WORKING_DIRECTORY,
    AUTHID_MOD_RDP_USE_CLIENT_PROVIDED_ALTERNATE_SHELL,
    AUTHID_MOD_RDP_USE_CLIENT_PROVIDED_REMOTEAPP,
    AUTHID_MOD_RDP_USE_NATIVE_REMOTEAPP_CAPABILITY,
    AUTHID_MOD_RDP_ENABLE_SESSION_PROBE,
    AUTHID_MOD_RDP_SESSION_PROBE_USE_CLIPBOARD_BASED_LAUNCHER,
    AUTHID_MOD_RDP_SESSION_PROBE_ENABLE_LAUNCH_MASK,
    AUTHID_MOD_RDP_SESSION_PROBE_ON_LAUNCH_FAILURE,
    AUTHID_MOD_RDP_SESSION_PROBE_LAUNCH_TIMEOUT,
    AUTHID_MOD_RDP_SESSION_PROBE_LAUNCH_FALLBACK_TIMEOUT,
    AUTHID_MOD_RDP_SESSION_PROBE_START_LAUNCH_TIMEOUT_TIMER_ONLY_AFTER_LOGON,
    AUTHID_MOD_RDP_SESSION_PROBE_KEEPALIVE_TIMEOUT,
    AUTHID_MOD_RDP_SESSION_PROBE_ON_KEEPALIVE_TIMEOUT,
    AUTHID_MOD_RDP_SESSION_PROBE_END_DISCONNECTED_SESSION,
    AUTHID_MOD_RDP_SESSION_PROBE_ENABLE_LOG,
    AUTHID_MOD_RDP_SESSION_PROBE_ENABLE_LOG_ROTATION,
    AUTHID_MOD_RDP_SESSION_PROBE_DISCONNECTED_APPLICATION_LIMIT,
    AUTHID_MOD_RDP_SESSION_PROBE_DISCONNECTED_SESSION_LIMIT,
    AUTHID_MOD_RDP_SESSION_PROBE_IDLE_SESSION_LIMIT,
    AUTHID_MOD_RDP_SESSION_PROBE_CLIPBOARD_BASED_LAUNCHER_CLIPBOARD_INITIALIZATION_DELAY,
    AUTHID_MOD_RDP_SESSION_PROBE_CLIPBOARD_BASED_LAUNCHER_START_DELAY,
    AUTHID_MOD_RDP_SESSION_PROBE_CLIPBOARD_BASED_LAUNCHER_LONG_DELAY,
    AUTHID_MOD_RDP_SESSION_PROBE_CLIPBOARD_BASED_LAUNCHER_SHORT_DELAY,
    AUTHID_MOD_RDP_SESSION_PROBE_ENABLE_CRASH_DUMP,
    AUTHID_MOD_RDP_SESSION_PROBE_HANDLE_USAGE_LIMIT,
    AUTHID_MOD_RDP_SESSION_PROBE_MEMORY_USAGE_LIMIT,
    AUTHID_MOD_RDP_SESSION_PROBE_DISABLED_FEATURES,
    AUTHID_MOD_RDP_SESSION_PROBE_IGNORE_UI_LESS_PROCESSES_DURING_END_OF_SESSION_CHECK,
    AUTHID_MOD_RDP_SESSION_PROBE_CHILDLESS_WINDOW_AS_UNIDENTIFIED_INPUT_FIELD,
    AUTHID_MOD_RDP_SESSION_PROBE_LAUNCHER_ABORT_DELAY,
    AUTHID_MOD_RDP_SERVER_CERT_STORE,
    AUTHID_MOD_RDP_SERVER_CERT_CHECK,
    AUTHID_MOD_RDP_SERVER_ACCESS_ALLOWED_MESSAGE,
    AUTHID_MOD_RDP_SERVER_CERT_CREATE_MESSAGE,
    AUTHID_MOD_RDP_SERVER_CERT_SUCCESS_MESSAGE,
    AUTHID_MOD_RDP_SERVER_CERT_FAILURE_MESSAGE,
    AUTHID_MOD_RDP_SERVER_CERT_ERROR_MESSAGE,
    AUTHID_MOD_RDP_ENABLE_RDPDR_DATA_ANALYSIS,
    AUTHID_MOD_RDP_WABAM_USES_TRANSLATED_REMOTEAPP,
    AUTHID_MOD_RDP_ENABLE_RESTRICTED_ADMIN_MODE,
    AUTHID_MOD_VNC_CLIPBOARD_UP,
    AUTHID_MOD_VNC_CLIPBOARD_DOWN,
    AUTHID_MOD_VNC_SERVER_CLIPBOARD_ENCODING_TYPE,
    AUTHID_MOD_VNC_BOGUS_CLIPBOARD_INFINITE_LOOP,
    AUTHID_MOD_VNC_SERVER_IS_APPLE,
    AUTHID_MOD_VNC_SERVER_UNIX_ALT,
    AUTHID_MOD_REPLAY_REPLAY_ON_LOOP,
    AUTHID_VIDEO_DISABLE_KEYBOARD_LOG,
    AUTHID_VIDEO_RT_DISPLAY,
    AUTHID_CRYPTO_KEY0,
    AUTHID_CRYPTO_KEY1,
    AUTHID_REMOTE_PROGRAM_ALLOW_RESIZE_HOSTED_DESKTOP,
    AUTHID_TRANSLATION_LANGUAGE,
    AUTHID_TRANSLATION_PASSWORD_EN,
    AUTHID_TRANSLATION_PASSWORD_FR,
    AUTHID_CONTEXT_PSID,
    AUTHID_CONTEXT_OPT_BITRATE,
    AUTHID_CONTEXT_OPT_FRAMERATE,
    AUTHID_CONTEXT_OPT_QSCALE,
    AUTHID_CONTEXT_OPT_BPP,
    AUTHID_CONTEXT_OPT_HEIGHT,
    AUTHID_CONTEXT_OPT_WIDTH,
    AUTHID_CONTEXT_SELECTOR,
    AUTHID_CONTEXT_SELECTOR_CURRENT_PAGE,
    AUTHID_CONTEXT_SELECTOR_DEVICE_FILTER,
    AUTHID_CONTEXT_SELECTOR_GROUP_FILTER,
    AUTHID_CONTEXT_SELECTOR_PROTO_FILTER,
    AUTHID_CONTEXT_SELECTOR_LINES_PER_PAGE,
    AUTHID_CONTEXT_SELECTOR_NUMBER_OF_PAGES,
    AUTHID_CONTEXT_TARGET_PASSWORD,
    AUTHID_CONTEXT_TARGET_HOST,
    AUTHID_CONTEXT_TARGET_STR,
    AUTHID_CONTEXT_TARGET_SERVICE,
    AUTHID_CONTEXT_TARGET_PORT,
    AUTHID_CONTEXT_TARGET_PROTOCOL,
    AUTHID_CONTEXT_PASSWORD,
    AUTHID_CONTEXT_REPORTING,
    AUTHID_CONTEXT_AUTH_CHANNEL_ANSWER,
    AUTHID_CONTEXT_AUTH_CHANNEL_TARGET,
    AUTHID_CONTEXT_MESSAGE,
    AUTHID_CONTEXT_ACCEPT_MESSAGE,
    AUTHID_CONTEXT_DISPLAY_MESSAGE,
    AUTHID_CONTEXT_REJECTED,
    AUTHID_CONTEXT_AUTHENTICATED,
    AUTHID_CONTEXT_KEEPALIVE,
    AUTHID_CONTEXT_SESSION_ID,
    AUTHID_CONTEXT_END_DATE_CNX,
    AUTHID_CONTEXT_END_TIME,
    AUTHID_CONTEXT_MODE_CONSOLE,
    AUTHID_CONTEXT_TIMEZONE,
    AUTHID_CONTEXT_REAL_TARGET_DEVICE,
    AUTHID_CONTEXT_AUTHENTICATION_CHALLENGE,
    AUTHID_CONTEXT_TICKET,
    AUTHID_CONTEXT_COMMENT,
    AUTHID_CONTEXT_DURATION,
    AUTHID_CONTEXT_DURATION_MAX,
    AUTHID_CONTEXT_WAITINFORETURN,
    AUTHID_CONTEXT_SHOWFORM,
    AUTHID_CONTEXT_FORMFLAG,
    AUTHID_CONTEXT_MODULE,
    AUTHID_CONTEXT_FORCEMODULE,
    AUTHID_CONTEXT_PROXY_OPT,
    AUTHID_CONTEXT_PATTERN_KILL,
    AUTHID_CONTEXT_PATTERN_NOTIFY,
    AUTHID_CONTEXT_OPT_MESSAGE,
    AUTHID_CONTEXT_LOGIN_MESSAGE,
    AUTHID_CONTEXT_SESSION_PROBE_OUTBOUND_CONNECTION_MONITORING_RULES,
    AUTHID_CONTEXT_SESSION_PROBE_PROCESS_MONITORING_RULES,
    AUTHID_CONTEXT_SESSION_PROBE_EXTRA_SYSTEM_PROCESSES,
    AUTHID_CONTEXT_SESSION_PROBE_WINDOWS_OF_THESE_APPLICATIONS_AS_UNIDENTIFIED_INPUT_FIELD,
    AUTHID_CONTEXT_DISCONNECT_REASON,
    AUTHID_CONTEXT_DISCONNECT_REASON_ACK,
    AUTHID_CONTEXT_RECORDING_STARTED,
    AUTHID_CONTEXT_AUTH_COMMAND,
    AUTHID_CONTEXT_AUTH_NOTIFY,
    AUTHID_CONTEXT_AUTH_NOTIFY_RAIL_EXEC_FLAGS,
    AUTHID_CONTEXT_AUTH_NOTIFY_RAIL_EXEC_EXE_OR_FILE,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_EXEC_RESULT,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_FLAGS,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_ORIGINAL_EXE_OR_FILE,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_EXE_OR_FILE,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_WORKING_DIR,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_ARGUMENTS,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_ACCOUNT,
    AUTHID_CONTEXT_AUTH_COMMAND_RAIL_EXEC_PASSWORD,
    AUTHID_CONTEXT_RAIL_DISCONNECT_MESSAGE_DELAY,
    AUTHID_CONTEXT_USE_SESSION_PROBE_TO_LAUNCH_REMOTE_PROGRAM,
    AUTHID_CONTEXT_SESSION_PROBE_LAUNCH_ERROR_MESSAGE,
    AUTHID_CONTEXT_IS_WABAM,
    MAX_AUTHID,
    AUTHID_UNKNOWN
};
constexpr char const * const authstr[] = {
    "capture_chunk",
    "login",
    "ip_client",
    "ip_target",
    "target_device",
    "device_id",
    "primary_user_id",
    "target_login",
    "target_application",
    "target_application_account",
    "target_application_password",
    "inactivity_timeout",
    "trace_type",
    "is_rec",
    "rec_path",
    "unicode_keyboard_event_support",
    "mod_recv_timeout",
    "session_log_path",
    "keyboard_input_masking_level",
    "keyboard_layout",
    "disable_tsk_switch_shortcuts",
    "enable_nla",
    "enable_kerberos",
    "server_redirection",
    "load_balance_info",
    "rdp_bogus_sc_net_size",
    "proxy_managed_drives",
    "ignore_auth_channel",
    "alternate_shell",
    "shell_arguments",
    "shell_working_directory",
    "use_client_provided_alternate_shell",
    "use_client_provided_remoteapp",
    "use_native_remoteapp_capability",
    "session_probe",
    "session_probe_use_smart_launcher",
    "session_probe_enable_launch_mask",
    "session_probe_on_launch_failure",
    "session_probe_launch_timeout",
    "session_probe_launch_fallback_timeout",
    "session_probe_start_launch_timeout_timer_only_after_logon",
    "session_probe_keepalive_timeout",
    "session_probe_on_keepalive_timeout",
    "session_probe_end_disconnected_session",
    "session_probe_enable_log",
    "session_probe_enable_log_rotation",
    "session_probe_disconnected_application_limit",
    "session_probe_disconnected_session_limit",
    "session_probe_idle_session_limit",
    "session_probe_smart_launcher_clipboard_initialization_delay",
    "session_probe_smart_launcher_start_delay",
    "session_probe_smart_launcher_long_delay",
    "session_probe_smart_launcher_short_delay",
    "session_probe_enable_crash_dump",
    "session_probe_handle_usage_limit",
    "session_probe_memory_usage_limit",
    "session_probe_disabled_features",
    "session_probe_ignore_ui_less_processes_during_end_of_session_check",
    "session_probe_childless_window_as_unidentified_input_field",
    "session_probe_launcher_abort_delay",
    "server_cert_store",
    "server_cert_check",
    "server_access_allowed_message",
    "server_cert_create_message",
    "server_cert_success_message",
    "server_cert_failure_message",
    "server_cert_error_message",
    "enable_rdpdr_data_analysis",
    "wabam_uses_translated_remoteapp",
    "enable_restricted_admin_mode",
    "clipboard_up",
    "clipboard_down",
    "vnc_server_clipboard_encoding_type",
    "vnc_bogus_clipboard_infinite_loop",
    "server_is_apple",
    "server_unix_alt",
    "replay_on_loop",
    "disable_keyboard_log",
    "rt_display",
    "encryption_key",
    "sign_key",
    "allow_resize_hosted_desktop",
    "language",
    "password_en",
    "password_fr",
    "psid",
    "bitrate",
    "framerate",
    "qscale",
    "bpp",
    "height",
    "width",
    "selector",
    "selector_current_page",
    "selector_device_filter",
    "selector_group_filter",
    "selector_proto_filter",
    "selector_lines_per_page",
    "selector_number_of_pages",
    "target_password",
    "target_host",
    "target_str",
    "target_service",
    "target_port",
    "proto_dest",
    "password",
    "reporting",
    "auth_channel_answer",
    "auth_channel_target",
    "message",
    "accept_message",
    "display_message",
    "rejected",
    "authenticated",
    "keepalive",
    "session_id",
    "timeclose",
    "end_time",
    "mode_console",
    "timezone",
    "real_target_device",
    "authentication_challenge",
    "ticket",
    "comment",
    "duration",
    "duration_max",
    "waitinforeturn",
    "showform",
    "formflag",
    "module",
    "forcemodule",
    "proxy_opt",
    "pattern_kill",
    "pattern_notify",
    "opt_message",
    "login_message",
    "session_probe_outbound_connection_monitoring_rules",
    "session_probe_process_monitoring_rules",
    "session_probe_extra_system_processes",
    "session_probe_windows_of_these_applications_as_unidentified_input_field",
    "disconnect_reason",
    "disconnect_reason_ack",
    "recording_started",
    "auth_command",
    "auth_notify",
    "auth_notify_rail_exec_flags",
    "auth_notify_rail_exec_exe_or_file",
    "auth_command_rail_exec_exec_result",
    "auth_command_rail_exec_flags",
    "auth_command_rail_exec_original_exe_or_file",
    "auth_command_rail_exec_exe_or_file",
    "auth_command_rail_exec_working_dir",
    "auth_command_rail_exec_arguments",
    "auth_command_rail_exec_account",
    "auth_command_rail_exec_password",
    "rail_disconnect_message_delay",
    "use_session_probe_to_launch_remote_program",
    "session_probe_launch_error_message",
    "is_wabam",
};
