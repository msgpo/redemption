#pragma once

#include "keylayout_r.hpp"

namespace
{

constexpr static int x8000080a_LCID = 0x80a;

constexpr static char const * x8000080a_locale_name = "es-MX";

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_noMod[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       0,       0,       0,       0,       0,       0,      12,
       0,       0,      55,      78,      51,      74,      83,      98,
      82,      79,      80,      81,      75,      76,      77,      71,
      72,      73,       0,       0,      86,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,      40,      41,      43,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      26,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      13,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      39,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_noMod[] {
    { 0x00, x8000080a_scancode_0x00_noMod },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_noMod{ array_view{x8000080a_data_noMod} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_shift[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,       0,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       2,       3,       4,       5,       6,       7,       0,
       9,      10,      55,      78,       0,      74,      83,     104,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      52,      51,       0,      11,      86,      12,
       0,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,      40,       0,      43,       0,      53,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      99,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      13,       0,       0,       0,       0,       0,       0,
      26,       0,       0,       0,       0,       0,       0,       0,
      41,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      39,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_shift[] {
    { 0x00, x8000080a_scancode_0x00_shift },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_shift{ array_view{x8000080a_data_shift} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
      16,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      12,       0,      40,       0,
      43,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,      27,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      41,       0,       0,       0,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_altGr[] {
    { 0x00, x8000080a_scancode_0x00_altGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_altGr{ array_view{x8000080a_data_altGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_shiftAltGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_shiftAltGr[] {
    { 0x00, x8000080a_scancode_0x00_shiftAltGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_shiftAltGr{ array_view{x8000080a_data_shiftAltGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_capslock_noMod[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       0,       0,       0,       0,       0,       0,      12,
       0,       0,      55,      78,      51,      74,      83,      98,
      11,       2,       3,       4,       5,       6,       7,       8,
       9,      10,       0,       0,      86,       0,       0,       0,
       0,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      40,      41,      43,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      26,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,      13,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      39,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_capslock_noMod[] {
    { 0x00, x8000080a_scancode_0x00_capslock_noMod },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_capslock_noMod{ array_view{x8000080a_data_capslock_noMod} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_capslock_shift[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       2,       3,       4,       5,       6,       7,       0,
       9,      10,      55,      78,       0,      74,      83,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      52,      51,       0,      11,      86,      12,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      40,       0,      43,       0,      53,
       0,      30,      48,      46,      32,      18,      33,      34,
      35,      23,      36,      37,      38,      50,      49,      24,
      25,      16,      19,      31,      20,      22,      47,      17,
      45,      21,      44,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      13,       0,       0,       0,       0,       0,       0,
      26,       0,       0,       0,       0,       0,       0,       0,
      41,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,      39,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
};

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_capslock_shift[] {
    { 0x00, x8000080a_scancode_0x00_capslock_shift },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_capslock_shift{ array_view{x8000080a_data_capslock_shift} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_capslock_altGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,      55,      78,       0,      74,       0,      98,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
      16,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      12,       0,      40,       0,
      43,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,      27,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,      41,       0,       0,       0,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_capslock_altGr[] {
    { 0x00, x8000080a_scancode_0x00_capslock_altGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_capslock_altGr{ array_view{x8000080a_data_capslock_altGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_capslock_shiftAltGr[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_capslock_shiftAltGr[] {
    { 0x00, x8000080a_scancode_0x00_capslock_shiftAltGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_capslock_shiftAltGr{ array_view{x8000080a_data_capslock_shiftAltGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x8000080a_scancode_0x00_ctrl[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      40,      86,      43,       0,       0,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x8000080a_data_ctrl[] {
    { 0x00, x8000080a_scancode_0x00_ctrl },
};

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_ctrl{ array_view{x8000080a_data_ctrl} };

constexpr Keylayout_r::KeyLayoutMap_t x8000080a_deadkeys {
};

constexpr static uint8_t x8000080a_nbDeadkeys = 4;

static const Keylayout_r keylayout_x8000080a(
    x8000080a_LCID,
    x8000080a_locale_name,
    x8000080a_noMod,
    x8000080a_shift,
    x8000080a_altGr,
    x8000080a_shiftAltGr,
    x8000080a_ctrl,
    x8000080a_capslock_noMod,
    x8000080a_capslock_shift,
    x8000080a_capslock_altGr,
    x8000080a_capslock_shiftAltGr,
    x8000080a_deadkeys,
    x8000080a_nbDeadkeys
);

}

