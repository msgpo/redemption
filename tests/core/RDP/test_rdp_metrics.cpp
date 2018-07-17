/*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
*   Product name: redemption, a FLOSS RDP proxy
*   Copyright (C) Wallix 2010-2017
*   Author(s): Clément Moroldo
*/

#include "utils/log.hpp"
#include "test_only/get_file_contents.hpp"

#define RED_TEST_MODULE TestRDPMetrics
#include "system/redemption_unit_tests.hpp"

#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <linux/hdreg.h>

#include "utils/fileutils.hpp"
#include "utils/sugar/unique_fd.hpp"

#include "core/RDP/rdp_metrics.hpp"



RED_AUTO_TEST_CASE(TestRDPMetricsOutputFileTurnOver) {

    ClientInfo info;
    const char * templace_path_file = "/tmp/rdp_metrics_file_test1";
    RDPMetrics metrics( templace_path_file
                      , 1
                      , "user"
                      , "admin"
                      , "10.10.13.12"
                      , info
                      , 0
                      , "RDP1");

    char current_date[24] {};
    timeval now = tvtime();
    metrics.set_current_formated_date(current_date, false, now.tv_sec);

    char complete_file_path[4096] = {'\0'};
    ::snprintf(complete_file_path, sizeof(complete_file_path), "%s-%s.log", templace_path_file, current_date);
    RED_CHECK(unique_fd(complete_file_path, O_RDONLY).is_open());

    time_t yesterday_time = metrics.last_date - 3600*24;
    metrics.last_date = yesterday_time;
    metrics.log();
    metrics.log();

    char yesterday_date[24] {};
    metrics.set_current_formated_date(yesterday_date, false, yesterday_time);
    char yesterday_complete_path[4096] = {'\0'};
    ::snprintf(yesterday_complete_path, sizeof(yesterday_complete_path), "%s-%s.log", templace_path_file, yesterday_date);
    RED_CHECK(!unique_fd(yesterday_complete_path, O_RDONLY).is_open());
    RED_CHECK(yesterday_time <= metrics.last_date);

    RED_CHECK(unique_fd(complete_file_path, O_RDONLY).is_open());
    remove(complete_file_path);
}


RED_AUTO_TEST_CASE(TestRDPMetricsOutputLogHeader) {

    ClientInfo info;
    const char * templace_path_file = "/tmp/rdp_metrics_file_test2";
    RDPMetrics metrics( templace_path_file
                      , 1
                      , "user"
                      , "admin"
                      , "10.10.13.12"
                      , info
                      , 0
                      , "RDP1");

    char current_date[24] = {'\0'};
    timeval now = tvtime();
    metrics.set_current_formated_date(current_date, false, now.tv_sec);

    char complete_file_path[4096] = {'\0'};
    ::snprintf(complete_file_path, sizeof(complete_file_path), "%s-%s.log", templace_path_file, current_date);
    metrics.log();

    std::string expected_log("Session_starting_time=");
    expected_log += metrics.start_full_date_time;
    expected_log +=
        " delta_time(s)=0 Session_id=1"
        " user=D033E22AE348AEB5660FC2140AEC35850C4DA997"
        " account=12DEA96FEC20593566AB75692C9949596833ADC9"
        " hostname=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        " target_service=EE5D8A196324C9649DCB8B0E98B77C574E635C6A"
        " session_info=1709919F0A4B52AE2A778DCDE07E5602FEBA1155"
        " main_channel_data_from_client=0 right_click_sent=0 left_click_sent=0"
        " keys_sent=0 mouse_move=0 main_channel_data_from_serveur=0"
        " cliprdr_channel_data_from_server=0 nb_text_paste_server=0"
        " nb_image_paste_server=0 nb_file_paste_server=0 nb_text_copy_server=0"
        " nb_image_copy_server=0 nb_file_copy_server=0 cliprdr_channel_data_from_client=0"
        " nb_text_paste_client=0 nb_image_paste_client=0 nb_file_paste_client=0"
        " nb_text_copy_client=0 nb_image_copy_client=0 nb_file_copy_client=0"
        " rdpdr_channel_data_from_client=0 rdpdr_channel_data_from_server=0"
        " nb_more_1k_byte_read_file=0 nb_deleted_file_or_folder=0 nb_write_file=0"
        " nb_rename_file=0 nb_open_folder=0 rail_channel_data_from_client=0"
        " rail_channel_data_from_serveur=0 other_channel_data_from_client=0"
        " other_channel_data_from_serveur=0\n"
    ;

    RED_CHECK(unique_fd(complete_file_path, O_RDONLY).is_open());
    auto data = get_file_contents(complete_file_path);
    RED_CHECK_EQUAL(data, expected_log);

    remove(complete_file_path);
}


RED_AUTO_TEST_CASE(TestRDPMetricsOutputData) {



}


