//
// DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
//

#pragma once

enum authid_t : unsigned;

namespace cfg {
    struct globals {
        struct capture_chunk;
        struct auth_user;
        struct host;
        struct target;
        struct target_device;
        struct device_id;
        struct primary_user_id;
        struct target_user;
        struct target_application;
        struct target_application_account;
        struct target_application_password;
        struct bitmap_cache;
        struct glyph_cache;
        struct port;
        struct nomouse;
        struct notimestamp;
        struct encryptionLevel;
        struct authfile;
        struct handshake_timeout;
        struct session_timeout;
        struct inactivity_timeout;
        struct keepalive_grace_delay;
        struct authentication_timeout;
        struct close_timeout;
        struct trace_type;
        struct listen_address;
        struct enable_transparent_mode;
        struct certificate_password;
        struct png_path;
        struct wrm_path;
        struct is_rec;
        struct movie_path;
        struct enable_bitmap_update;
        struct enable_close_box;
        struct enable_osd;
        struct enable_osd_display_remote_target;
        struct persistent_path;
        struct enable_wab_integration;
        struct allow_using_multiple_monitors;
        struct bogus_refresh_rect;
        struct codec_id;
        struct video_quality;
        struct large_pointer_support;
        struct unicode_keyboard_event_support;
        struct mod_recv_timeout;
        struct spark_view_specific_glyph_width;
        struct experimental_enable_serializer_data_block_size_limit;
        struct experimental_support_resize_session_during_recording;
        struct rdp_keepalive_connection_interval;
    };

    struct session_log {
        struct enable_session_log;
        struct log_path;
        struct keyboard_input_masking_level;
        struct hide_non_printable_kbd_input;
    };

    struct client {
        struct keyboard_layout;
        struct keyboard_layout_proposals;
        struct ignore_logon_password;
        struct performance_flags_default;
        struct performance_flags_force_present;
        struct performance_flags_force_not_present;
        struct auto_adjust_performance_flags;
        struct tls_fallback_legacy;
        struct tls_support;
        struct tls_min_level;
        struct bogus_neg_request;
        struct bogus_user_id;
        struct disable_tsk_switch_shortcuts;
        struct rdp_compression;
        struct max_color_depth;
        struct persistent_disk_bitmap_cache;
        struct cache_waiting_list;
        struct persist_bitmap_cache_on_disk;
        struct bitmap_compression;
        struct fast_path;
        struct enable_suppress_output;
        struct ssl_cipher_list;
        struct show_target_user_in_f12_message;
        struct enable_new_pointer_update;
        struct bogus_ios_glyph_support_level;
        struct transform_glyph_to_bitmap;
        struct bogus_number_of_fastpath_input_event;
        struct recv_timeout;
    };

    struct mod_rdp {
        struct rdp_compression;
        struct disconnect_on_logon_user_change;
        struct open_session_timeout;
        struct extra_orders;
        struct enable_nla;
        struct enable_kerberos;
        struct persistent_disk_bitmap_cache;
        struct cache_waiting_list;
        struct persist_bitmap_cache_on_disk;
        struct allow_channels;
        struct deny_channels;
        struct fast_path;
        struct server_redirection_support;
        struct redir_info;
        struct load_balance_info;
        struct bogus_sc_net_size;
        struct proxy_managed_drives;
        struct ignore_auth_channel;
        struct auth_channel;
        struct checkout_channel;
        struct alternate_shell;
        struct shell_arguments;
        struct shell_working_directory;
        struct use_client_provided_alternate_shell;
        struct use_client_provided_remoteapp;
        struct use_native_remoteapp_capability;
        struct enable_session_probe;
        struct session_probe_use_clipboard_based_launcher;
        struct session_probe_enable_launch_mask;
        struct session_probe_on_launch_failure;
        struct session_probe_launch_timeout;
        struct session_probe_launch_fallback_timeout;
        struct session_probe_start_launch_timeout_timer_only_after_logon;
        struct session_probe_keepalive_timeout;
        struct session_probe_on_keepalive_timeout;
        struct session_probe_end_disconnected_session;
        struct session_probe_customize_executable_name;
        struct session_probe_enable_log;
        struct session_probe_enable_log_rotation;
        struct session_probe_disconnected_application_limit;
        struct session_probe_disconnected_session_limit;
        struct session_probe_idle_session_limit;
        struct session_probe_exe_or_file;
        struct session_probe_arguments;
        struct session_probe_clipboard_based_launcher_clipboard_initialization_delay;
        struct session_probe_clipboard_based_launcher_start_delay;
        struct session_probe_clipboard_based_launcher_long_delay;
        struct session_probe_clipboard_based_launcher_short_delay;
        struct session_probe_launcher_abort_delay;
        struct session_probe_allow_multiple_handshake;
        struct session_probe_enable_crash_dump;
        struct session_probe_handle_usage_limit;
        struct session_probe_memory_usage_limit;
        struct session_probe_ignore_ui_less_processes_during_end_of_session_check;
        struct session_probe_childless_window_as_unidentified_input_field;
        struct session_probe_disabled_features;
        struct session_probe_public_session;
        struct server_cert_store;
        struct server_cert_check;
        struct server_access_allowed_message;
        struct server_cert_create_message;
        struct server_cert_success_message;
        struct server_cert_failure_message;
        struct server_cert_error_message;
        struct hide_client_name;
        struct clean_up_32_bpp_cursor;
        struct bogus_ios_rdpdr_virtual_channel;
        struct enable_rdpdr_data_analysis;
        struct remoteapp_bypass_legal_notice_delay;
        struct remoteapp_bypass_legal_notice_timeout;
        struct log_only_relevant_clipboard_activities;
        struct experimental_fix_input_event_sync;
        struct experimental_fix_too_long_cookie;
        struct split_domain;
    };

    struct metrics {
        struct enable_rdp_metrics;
        struct enable_vnc_metrics;
        struct log_dir_path;
        struct log_interval;
        struct log_file_turnover_interval;
        struct sign_key;
    };

    struct mod_vnc {
        struct clipboard_up;
        struct clipboard_down;
        struct encodings;
        struct server_clipboard_encoding_type;
        struct bogus_clipboard_infinite_loop;
        struct server_is_apple;
        struct server_unix_alt;
    };

    struct mod_replay {
        struct on_end_of_data;
        struct replay_on_loop;
    };

    struct ocr {
        struct version;
        struct locale;
        struct interval;
        struct on_title_bar_only;
        struct max_unrecog_char_rate;
    };

    struct video {
        struct capture_groupid;
        struct capture_flags;
        struct png_interval;
        struct frame_interval;
        struct break_interval;
        struct png_limit;
        struct replay_path;
        struct hash_path;
        struct record_tmp_path;
        struct record_path;
        struct disable_keyboard_log;
        struct disable_clipboard_log;
        struct disable_file_system_log;
        struct rt_display;
        struct wrm_color_depth_selection_strategy;
        struct wrm_compression_algorithm;
        struct bogus_vlc_frame_rate;
        struct l_bitrate;
        struct l_framerate;
        struct l_height;
        struct l_width;
        struct l_qscale;
        struct m_bitrate;
        struct m_framerate;
        struct m_height;
        struct m_width;
        struct m_qscale;
        struct h_bitrate;
        struct h_framerate;
        struct h_height;
        struct h_width;
        struct h_qscale;
        struct smart_video_cropping;
        struct play_video_with_corrupted_bitmap;
    };

    struct crypto {
        struct key0;
        struct key1;
    };

    struct debug {
        struct fake_target_ip;
        struct x224;
        struct mcs;
        struct sec;
        struct rdp;
        struct primary_orders;
        struct secondary_orders;
        struct bitmap_update;
        struct bitmap;
        struct capture;
        struct auth;
        struct session;
        struct front;
        struct mod_rdp;
        struct mod_vnc;
        struct mod_internal;
        struct mod_xup;
        struct widget;
        struct input;
        struct password;
        struct compression;
        struct cache;
        struct performance;
        struct pass_dialog_box;
        struct ocr;
        struct ffmpeg;
        struct config;
    };

    struct remote_program {
        struct allow_resize_hosted_desktop;
    };

    struct translation {
        struct language;
        struct password_en;
        struct password_fr;
    };

    struct internal_mod {
        struct theme;
    };

    struct context {
        struct opt_bitrate;
        struct opt_framerate;
        struct opt_qscale;
        struct opt_bpp;
        struct opt_height;
        struct opt_width;
        struct auth_error_message;
        struct selector;
        struct selector_current_page;
        struct selector_device_filter;
        struct selector_group_filter;
        struct selector_proto_filter;
        struct selector_lines_per_page;
        struct selector_number_of_pages;
        struct target_password;
        struct target_host;
        struct target_str;
        struct target_service;
        struct target_port;
        struct target_protocol;
        struct password;
        struct reporting;
        struct auth_channel_answer;
        struct auth_channel_target;
        struct message;
        struct accept_message;
        struct display_message;
        struct rejected;
        struct authenticated;
        struct keepalive;
        struct session_id;
        struct end_date_cnx;
        struct end_time;
        struct mode_console;
        struct timezone;
        struct real_target_device;
        struct authentication_challenge;
        struct ticket;
        struct comment;
        struct duration;
        struct duration_max;
        struct waitinforeturn;
        struct showform;
        struct formflag;
        struct module;
        struct forcemodule;
        struct proxy_opt;
        struct pattern_kill;
        struct pattern_notify;
        struct opt_message;
        struct login_message;
        struct session_probe_outbound_connection_monitoring_rules;
        struct session_probe_process_monitoring_rules;
        struct session_probe_extra_system_processes;
        struct session_probe_windows_of_these_applications_as_unidentified_input_field;
        struct disconnect_reason;
        struct disconnect_reason_ack;
        struct ip_target;
        struct recording_started;
        struct rt_ready;
        struct perform_automatic_reconnection;
        struct auth_command;
        struct auth_notify;
        struct auth_notify_rail_exec_flags;
        struct auth_notify_rail_exec_exe_or_file;
        struct auth_command_rail_exec_exec_result;
        struct auth_command_rail_exec_flags;
        struct auth_command_rail_exec_original_exe_or_file;
        struct auth_command_rail_exec_exe_or_file;
        struct auth_command_rail_exec_working_dir;
        struct auth_command_rail_exec_arguments;
        struct auth_command_rail_exec_account;
        struct auth_command_rail_exec_password;
        struct rail_disconnect_message_delay;
        struct use_session_probe_to_launch_remote_program;
        struct session_probe_launch_error_message;
        struct close_box_extra_message;
    };

} // namespace cfg
