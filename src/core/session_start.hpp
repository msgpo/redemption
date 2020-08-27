#pragma once

#include "utils/sugar/unique_fd.hpp"

void session_start_tls(unique_fd sck, Inifile& ini);
void session_start_ws(unique_fd sck, Inifile& ini);
void session_start_wss(unique_fd sck, Inifile& ini);
