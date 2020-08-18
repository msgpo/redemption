#pragma once

#include "keylayout_r.hpp"

namespace
{

constexpr static int x80010402_LCID = 0x10402;

constexpr static char const * x80010402_locale_name = "bg-BG.latin";

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_noMod[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       0,       0,       0,       0,       0,       0,      40,
       0,       0,      55,      78,      51,      74,      83,      98,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_noMod[] {
    { 0x00, x80010402_scancode_0x00_noMod },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_noMod{ array_view{x80010402_data_noMod} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_shift[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,       0,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       2,      40,       4,       5,       6,       8,       0,
      10,      11,      55,      78,       0,      74,      83,     104,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_shift[] {
    { 0x00, x80010402_scancode_0x00_shift },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_shift{ array_view{x80010402_data_shift} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_altGr[] {
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_altGr[] {
    { 0x00, x80010402_scancode_0x00_altGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_altGr{ array_view{x80010402_data_altGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_shiftAltGr[] {
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_shiftAltGr[] {
    { 0x00, x80010402_scancode_0x00_shiftAltGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_shiftAltGr{ array_view{x80010402_data_shiftAltGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_capslock_noMod[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       0,       0,       0,       0,       0,       0,      40,
       0,       0,      55,      78,      51,      74,      83,      98,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_capslock_noMod[] {
    { 0x00, x80010402_scancode_0x00_capslock_noMod },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_capslock_noMod{ array_view{x80010402_data_capslock_noMod} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_capslock_shift[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       1,       0,       0,       0,       0,
      57,       2,      40,       4,       5,       6,       8,       0,
      10,      11,      55,      78,       0,      74,      83,      98,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_capslock_shift[] {
    { 0x00, x80010402_scancode_0x00_capslock_shift },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_capslock_shift{ array_view{x80010402_data_capslock_shift} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_capslock_altGr[] {
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_capslock_altGr[] {
    { 0x00, x80010402_scancode_0x00_capslock_altGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_capslock_altGr{ array_view{x80010402_data_capslock_altGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_capslock_shiftAltGr[] {
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_capslock_shiftAltGr[] {
    { 0x00, x80010402_scancode_0x00_capslock_shiftAltGr },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_capslock_shiftAltGr{ array_view{x80010402_data_capslock_shiftAltGr} };

constexpr Keylayout_r::KeyLayoutMap_t::scancode_type x80010402_scancode_0x00_ctrl[] {
       0,       0,       0,       0,       0,       0,       0,       0,
      14,      15,       0,       0,       0,     100,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,      26,      86,      27,       0,       0,
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

constexpr Keylayout_r::KeyLayoutMap_t::data_type x80010402_data_ctrl[] {
    { 0x00, x80010402_scancode_0x00_ctrl },
};

constexpr Keylayout_r::KeyLayoutMap_t x80010402_ctrl{ array_view{x80010402_data_ctrl} };

constexpr Keylayout_r::KeyLayoutMap_t x80010402_deadkeys {
};

constexpr static uint8_t x80010402_nbDeadkeys = 0;

static const Keylayout_r keylayout_x80010402(
    x80010402_LCID,
    x80010402_locale_name,
    x80010402_noMod,
    x80010402_shift,
    x80010402_altGr,
    x80010402_shiftAltGr,
    x80010402_ctrl,
    x80010402_capslock_noMod,
    x80010402_capslock_shift,
    x80010402_capslock_altGr,
    x80010402_capslock_shiftAltGr,
    x80010402_deadkeys,
    x80010402_nbDeadkeys
);

}

