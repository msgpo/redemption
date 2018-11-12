R"([general]

# Secondary login Transformation rule
# ${LOGIN} will be replaced by login
# ${DOMAIN} (optional) will be replaced by domain if it exists.
# Empty value means no transformation rule.
transformation_rule = string(default='')

# Account Mapping password retriever
# Transformation to apply to find the correct account.
# ${USER} will be replaced by the user's login.
# ${DOMAIN} will be replaced by the user's domain (in case of LDAP mapping).
# ${USER_DOMAIN} will be replaced by the user's login + "@" + user's domain (or just user's login if there's no domain).
# ${GROUP} will be replaced by the authorization's user group.
# ${DEVICE} will be replaced by the device's name.
# A regular expression is allowed to transform a variable, with the syntax: ${USER:/regex/replacement}, groups can be captured with parentheses and used with \1, \2, ...
# For example to replace leading "A" by "B" in the username: ${USER:/^A/B}
# Empty value means no transformation rule.
vault_transformation_rule = string(default='')


)""[rdp]\n\n"

"# NLA authentication in secondary target.\n"
"enable_nla = boolean(default=True)\n\n"

"# If enabled, NLA authentication will try Kerberos before NTLM.\n"
"# (if enable_nla is disabled, this value is ignored).\n"
"enable_kerberos = boolean(default=False)\n\n"

"# Enables Server Redirection Support.\n"
"server_redirection = boolean(default=False)\n\n"

"load_balance_info = string(default='')\n\n"

"use_client_provided_alternate_shell = boolean(default=False)\n\n"

"use_client_provided_remoteapp = boolean(default=False)\n\n"

"use_native_remoteapp_capability = boolean(default=True)\n\n"

"# Delay before showing disconnect message after the last RemoteApp window is closed.\n"
"# (is in millisecond)\n"
"remote_programs_disconnect_message_delay = integer(min=0, default=3000)\n\n"

"# Use Session Probe to launch Remote Program as much as possible.\n"
"use_session_probe_to_launch_remote_program = boolean(default=True)\n\n"

"[server_cert]\n\n"

"# Keep known server certificates on WAB\n"
"server_cert_store = boolean(default=True)\n\n"

"# Behavior of certificates check.\n"
"#   0: fails if certificates doesn't match or miss.\n"
"#   1: fails if certificate doesn't match, succeed if no known certificate.\n"
"#   2: succeed if certificates exists (not checked), fails if missing.\n"
"#   3: always succeed.\n"
"# System errors like FS access rights issues or certificate decode are always check errors leading to connection rejection.\n"
"server_cert_check = option(0, 1, 2, 3, default=1)\n\n"

"# Warn if check allow connexion to server.\n"
"#   0: nobody\n"
"#   1: message sent to syslog\n"
"#   2: User notified (through proxy interface)\n"
"#   4: admin notified (wab notification)\n"
"# (note: values can be added (everyone: 1+2+4=7, mute: 0))\n"
"server_access_allowed_message = integer(min=0, max=7, default=1)\n\n"

"# Warn that new server certificate file was created.\n"
"#   0: nobody\n"
"#   1: message sent to syslog\n"
"#   2: User notified (through proxy interface)\n"
"#   4: admin notified (wab notification)\n"
"# (note: values can be added (everyone: 1+2+4=7, mute: 0))\n"
"server_cert_create_message = integer(min=0, max=7, default=1)\n\n"

"# Warn that server certificate file was successfully checked.\n"
"#   0: nobody\n"
"#   1: message sent to syslog\n"
"#   2: User notified (through proxy interface)\n"
"#   4: admin notified (wab notification)\n"
"# (note: values can be added (everyone: 1+2+4=7, mute: 0))\n"
"server_cert_success_message = integer(min=0, max=7, default=1)\n\n"

"# Warn that server certificate file checking failed.\n"
"#   0: nobody\n"
"#   1: message sent to syslog\n"
"#   2: User notified (through proxy interface)\n"
"#   4: admin notified (wab notification)\n"
"# (note: values can be added (everyone: 1+2+4=7, mute: 0))\n"
"server_cert_failure_message = integer(min=0, max=7, default=1)\n\n"

"[session]\n\n"

"# No traffic auto disconnection.\n"
"# (is in second)\n"
"inactivity_timeout = integer(min=0, default=0)\n\n"

"[session_probe]\n\n"

"enable_session_probe = boolean(default=False)\n\n"

"# Minimum supported server : Windows Server 2008.\n"
"# Clipboard redirection should be remain enabled on Terminal Server.\n"
"use_smart_launcher = boolean(default=True)\n\n"

"enable_launch_mask = boolean(default=True)\n\n"

"# Behavior on failure to launch Session Probe.\n"
"#   0: ignore failure and continue.\n"
"#   1: disconnect user.\n"
"#   2: reconnect without Session Probe.\n"
"on_launch_failure = option(0, 1, 2, default=2)\n\n"

"# This parameter is used if session_probe_on_launch_failure is 1 (disconnect user).\n"
"# 0 to disable timeout.\n"
"# (is in millisecond)\n"
"launch_timeout = integer(min=0, default=20000)\n\n"

"# This parameter is used if session_probe_on_launch_failure is 0 (ignore failure and continue) or 2 (reconnect without Session Probe).\n"
"# 0 to disable timeout.\n"
"# (is in millisecond)\n"
"launch_fallback_timeout = integer(min=0, default=7000)\n\n"

"# Minimum supported server : Windows Server 2008.\n"
"start_launch_timeout_timer_only_after_logon = boolean(default=True)\n\n"

"# (is in millisecond)\n"
"keepalive_timeout = integer(min=0, default=5000)\n\n"

"#   0: ignore and continue\n"
"#   1: disconnect user\n"
"#   2: freeze connection and wait\n"
"on_keepalive_timeout = option(0, 1, 2, default=1)\n\n"

"# End automatically a disconnected session\n"
"end_disconnected_session = boolean(default=False)\n\n"

"enable_log = boolean(default=False)\n\n"

"enable_log_rotation = boolean(default=True)\n\n"

"# This policy setting allows you to configure a time limit for disconnected application sessions.\n"
"# 0 to disable timeout.\n"
"# (is in millisecond)\n"
"disconnected_application_limit = integer(min=0, default=0)\n\n"

"# This policy setting allows you to configure a time limit for disconnected Terminal Services sessions.\n"
"# 0 to disable timeout.\n"
"# (is in millisecond)\n"
"disconnected_session_limit = integer(min=0, default=0)\n\n"

"# This parameter allows you to specify the maximum amount of time that an active Terminal Services session can be idle (without user input) before it is automatically locked by Session Probe.\n"
"# 0 to disable timeout.\n"
"# (is in millisecond)\n"
"idle_session_limit = integer(min=0, default=0)\n\n"

"# (is in millisecond)\n"
"smart_launcher_clipboard_initialization_delay = integer(min=0, default=2000)\n\n"

"# (is in millisecond)\n"
"smart_launcher_start_delay = integer(min=0, default=0)\n\n"

"# (is in millisecond)\n"
"smart_launcher_long_delay = integer(min=0, default=500)\n\n"

"# (is in millisecond)\n"
"smart_launcher_short_delay = integer(min=0, default=50)\n\n"

"enable_crash_dump = boolean(default=False)\n\n"

"handle_usage_limit = integer(min=0, default=0)\n\n"

"memory_usage_limit = integer(min=0, default=0)\n\n"

"public_session = boolean(default=False)\n\n"

"# Comma-separated rules (Ex.: $deny:192.168.0.0/24:*,$allow:host.domain.net:3389,$allow:192.168.0.110:*)\n"
"# (Ex. for backwards compatibility only: 10.1.0.0/16:22)\n"
"outbound_connection_monitoring_rules = string(default='')\n\n"

"# Comma-separated rules (Ex.: $deny:Taskmgr)\n"
"# @ = All child processes of Bastion Application (Ex.: $deny:@)\n"
"process_monitoring_rules = string(default='')\n\n"

"# Comma-separated extra system processes (Ex.: dllhos.exe,TSTheme.exe)\n"
"extra_system_processes = string(default='')\n\n"

