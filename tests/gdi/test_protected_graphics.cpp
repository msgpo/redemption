/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Product name: redemption, a FLOSS RDP proxy
   Copyright (C) Wallix 2012
   Author(s): Christophe Grosjean

   Unit test to conversion of RDP drawing orders to PNG images
*/

#include "test_only/test_framework/redemption_unit_tests.hpp"
#include "test_only/test_framework/img_sig.hpp"
#include "test_only/transport/test_transport.hpp"

#include "core/RDP/orders/RDPOrdersPrimaryOpaqueRect.hpp"
#include "core/RDP/orders/RDPOrdersPrimaryMemBlt.hpp"
#include "core/RDP/bitmapupdate.hpp"
#include "gdi/protected_graphics.hpp"
#include "utils/bitmap_from_file.hpp"
#include "test_only/gdi/test_graphic.hpp"

#include <chrono>

namespace
{
    template<class F>
    auto make_osd(gdi::GraphicApi & drawable, Rect const rect, F f)
    {
        struct OSD : gdi::ProtectedGraphics
        {
            OSD(GraphicApi & drawable, Rect const rect, F f)
            : gdi::ProtectedGraphics(drawable, rect)
            , f(f)
            {}

            void refresh_rects(array_view<Rect> /*unused*/) override
            {
                f();
            }

            F f;
        };
        return OSD(drawable, rect, f);
    }
} // namespace


RED_AUTO_TEST_CASE(TestModOSD)
{
    Rect screen_rect(0, 0, 800, 600);
    TestGraphic drawable(screen_rect.cx, screen_rect.cy);
    auto const color_cxt = gdi::ColorCtx::depth24();

    drawable.show_mouse_cursor(false);

    drawable->draw(RDPOpaqueRect(Rect(0, 0, screen_rect.cx, screen_rect.cy), encode_color24()(RED)), screen_rect, color_cxt);

    Bitmap const bmp = bitmap_from_file(FIXTURES_PATH "/ad8b.bmp", BLACK);
    int const bmp_x = 200;
    int const bmp_y = 200;
    Rect const bmp_rect(bmp_x, bmp_y, bmp.cx(), bmp.cy());
    Rect const rect = bmp_rect.intersect(screen_rect.cx, screen_rect.cy);
    drawable->draw(RDPMemBlt(0, bmp_rect, 0xCC, 0, 0, 0), rect, bmp);

    RED_CHECK_IMG_SIG(drawable,
        "\x5b\xc8\x0f\x75\xcd\x3c\x87\x21\x70\xc6\x54\x20\x49\x0d\x97\xcd\x1c\xd3\x16\xf3");

    auto osd = make_osd(drawable, rect, []{RED_FAIL("refresh_rects is called");});
    osd.draw(RDPOpaqueRect(Rect(100, 100, 200, 200), encode_color24()(GREEN)), screen_rect, color_cxt);
    RED_CHECK_IMG_SIG(drawable,
        "\xc3\x04\x1e\xd3\x82\xa8\x98\x25\x51\x50\x2b\x7f\xa8\x81\x90\x12\xbb\x11\xd8\x94");
}

RED_AUTO_TEST_CASE(TestModOSD2)
{
    Rect screen_rect(0, 0, 800, 600);
    TestGraphic drawable(screen_rect.cx, screen_rect.cy);
    auto const color_cxt = gdi::ColorCtx::depth24();

    drawable.show_mouse_cursor(false);

    drawable->draw(RDPOpaqueRect(Rect(0, 0, screen_rect.cx, screen_rect.cy), encode_color24()(RED)), screen_rect, color_cxt);

    Rect const rect = Rect(100, 100, 200, 200);
    drawable->draw(RDPOpaqueRect(rect, encode_color24()(GREEN)), screen_rect, color_cxt);

    RED_CHECK_IMG_SIG(drawable,
        "\x67\x3a\xb4\xb9\x9f\x7f\xe9\x47\xbb\x49\xd3\xf7\x03\xf1\x5c\x07\x80\xeb\x1f\x62");

    Bitmap const bmp = bitmap_from_file(FIXTURES_PATH "/ad8b.bmp", BLACK);
    int const bmp_x = 200;
    int const bmp_y = 200;
    Rect const bmp_rect(bmp_x, bmp_y, bmp.cx(), bmp.cy());
    auto osd = make_osd(drawable, rect, []{});
    osd.draw(RDPMemBlt(0, bmp_rect, 0xCC, 0, 0, 0), bmp_rect.intersect(screen_rect.cx, screen_rect.cy), bmp);

    RED_CHECK_IMG_SIG(drawable,
        "\x04\xb7\xd8\x57\xf0\xde\x62\x8c\x42\x6f\x4d\x2a\x26\xc4\x68\xfc\xa1\xf5\x29\x9f");
}

RED_AUTO_TEST_CASE(TestModOSD3)
{
    Rect screen_rect(0, 0, 800, 600);
    TestGraphic drawable(screen_rect.cx, screen_rect.cy);
    auto const color_cxt = gdi::ColorCtx::depth24();

    drawable.show_mouse_cursor(false);

    drawable->draw(RDPOpaqueRect(Rect(0, 0, screen_rect.cx, screen_rect.cy), encode_color24()(RED)), screen_rect, color_cxt);

    Rect const rect = Rect(100, 100, 200, 200);
    drawable->draw(RDPOpaqueRect(rect, encode_color24()(GREEN)), screen_rect, color_cxt);

    RED_CHECK_IMG_SIG(drawable,
        "\x67\x3a\xb4\xb9\x9f\x7f\xe9\x47\xbb\x49\xd3\xf7\x03\xf1\x5c\x07\x80\xeb\x1f\x62");

    Bitmap const bmp = bitmap_from_file(FIXTURES_PATH "/ad8b.bmp", BLACK);
    int const bmp_x = 200;
    int const bmp_y = 200;
    Rect const bmp_rect(bmp_x, bmp_y, bmp.cx(), bmp.cy());
    RDPBitmapData bmp_data;
    bmp_data.dest_left = bmp_rect.x;
    bmp_data.dest_top = bmp_rect.y;
    bmp_data.dest_right = bmp_data.dest_left + bmp_rect.cx - 1;
    bmp_data.dest_bottom = bmp_data.dest_top + bmp_rect.cy - 1;
    bmp_data.width = bmp.cx();
    bmp_data.height = bmp.cy();
    bmp_data.bits_per_pixel = safe_int(bmp.bpp());
    bmp_data.flags = 0;

    bmp_data.bitmap_length = bmp.bmp_size();
    auto osd = make_osd(drawable, rect, []{});
    osd.draw(bmp_data, bmp);

    RED_CHECK_IMG_SIG(drawable,
        "\x04\xb7\xd8\x57\xf0\xde\x62\x8c\x42\x6f\x4d\x2a\x26\xc4\x68\xfc\xa1\xf5\x29\x9f");
}
