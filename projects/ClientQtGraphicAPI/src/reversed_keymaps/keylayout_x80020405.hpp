#pragma once

#include "keylayout_r.hpp"

namespace
{

constexpr static int x80020405_LCID = 0x20405;

constexpr static char const * x80020405_locale_name = "cs-CZ.programmers";

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_noMod[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       0,       0,       0,       0,       0,       0,      40,
       0,       0,      55,      78,      83,      74,      52,      98,
      82,      79,      80,      81,      75,      76,      77,      71,
      72,      73,       0,      39,       0,      13,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      26,      86,      27,       0,       0,
      41,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_noMod[] {
    { 0x00, x80020405_scancode_0x00_noMod },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_noMod{ array_view{x80020405_data_noMod} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_shift[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,       0,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       2,      40,       4,       5,       6,       8,       0,
      10,      11,      55,      78,      83,      74,       0,     104,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      39,       0,      51,       0,      52,      53,
       3,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,       0,       0,       0,       7,      12,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      26,      86,      27,      41,      99,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_shift[] {
    { 0x00, x80020405_scancode_0x00_shift },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_shift{ array_view{x80020405_data_shift} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      27,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      52,      41,       0,      12,       0,      51,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      40,
      43,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      13,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      86,
       0,       9,       0,       0,       0,       0,       0,       0,
       0,      11,       0,       0,       0,      10,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      26,       0,       0,       8,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x01_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       5,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       3,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       6,       0,       0,       0,       0,       0,       0,
       0,       4,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      39,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       7,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x20_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      18,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_altGr[] {
    { 0x00, x80020405_scancode_0x00_altGr },
    { 0x01, x80020405_scancode_0x01_altGr },
    { 0x20, x80020405_scancode_0x20_altGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_altGr{ array_view{x80020405_data_altGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_shiftAltGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,      40,      39,       0,       0,      12,       0,       0,
      27,       0,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,      43,      53,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
      41,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      51,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      52,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x02_shiftAltGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      13,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,      86,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_shiftAltGr[] {
    { 0x00, x80020405_scancode_0x00_shiftAltGr },
    { 0x02, x80020405_scancode_0x02_shiftAltGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_shiftAltGr{ array_view{x80020405_data_shiftAltGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_capslock_noMod[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       0,       0,       0,       0,       0,       0,      40,
       0,       0,      55,      78,      83,      74,      52,      98,
      11,       2,       3,       4,       5,       6,       7,       8,
       9,      10,       0,      39,       0,      13,       0,       0,
       0,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,      26,      86,      27,       0,       0,
      41,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_capslock_noMod[] {
    { 0x00, x80020405_scancode_0x00_capslock_noMod },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_capslock_noMod{ array_view{x80020405_data_capslock_noMod} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_capslock_shift[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       2,      40,       4,       5,       6,       8,       0,
      10,      11,      55,      78,      83,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      39,       0,      51,       0,      52,      53,
       3,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       7,      12,
       0,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,      26,      86,      27,      41,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_capslock_shift[] {
    { 0x00, x80020405_scancode_0x00_capslock_shift },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_capslock_shift{ array_view{x80020405_data_capslock_shift} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_capslock_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      27,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      52,      41,       0,      12,       0,      51,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      40,
      43,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      13,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      86,
       0,       9,       0,       0,       0,       0,       0,       0,
       0,      11,       0,       0,       0,      10,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      26,       0,       0,       8,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x01_capslock_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       5,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       3,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       6,       0,       0,       0,       0,       0,       0,
       0,       4,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      39,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       7,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x20_capslock_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      18,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_capslock_altGr[] {
    { 0x00, x80020405_scancode_0x00_capslock_altGr },
    { 0x01, x80020405_scancode_0x01_capslock_altGr },
    { 0x20, x80020405_scancode_0x20_capslock_altGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_capslock_altGr{ array_view{x80020405_data_capslock_altGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_capslock_shiftAltGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,      40,      39,       0,       0,      12,       0,       0,
      27,       0,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,      43,      53,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
      41,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      51,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      52,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x02_capslock_shiftAltGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      13,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,      86,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_capslock_shiftAltGr[] {
    { 0x00, x80020405_scancode_0x00_capslock_shiftAltGr },
    { 0x02, x80020405_scancode_0x02_capslock_shiftAltGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_capslock_shiftAltGr{ array_view{x80020405_data_capslock_shiftAltGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80020405_scancode_0x00_ctrl[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      27,      43,      39,       0,       0,
      57,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80020405_data_ctrl[] {
    { 0x00, x80020405_scancode_0x00_ctrl },
};

constexpr Keylayout_r::KeyLayoutMap_t x80020405_ctrl{ array_view{x80020405_data_ctrl} };

constexpr Keylayout_r::KeyLayoutMap_t x80020405_deadkeys {
};

constexpr static uint8_t x80020405_nbDeadkeys = 6;

static const Keylayout_r keylayout_x80020405(
    x80020405_LCID,
    x80020405_locale_name,
    x80020405_noMod,
    x80020405_shift,
    x80020405_altGr,
    x80020405_shiftAltGr,
    x80020405_ctrl,
    x80020405_capslock_noMod,
    x80020405_capslock_shift,
    x80020405_capslock_altGr,
    x80020405_capslock_shiftAltGr,
    x80020405_deadkeys,
    x80020405_nbDeadkeys
);

}

