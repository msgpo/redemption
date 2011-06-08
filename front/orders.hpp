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
   Copyright (C) Wallix 2010
   Author(s): Christophe Grosjean, Javier Caverni
   Based on xrdp Copyright (C) Jay Sorg 2004-2010

*/

#if !defined(__ORDERS_HPP__)
#define __ORDERS_HPP__

#include "font.hpp"
#include "constants.hpp"
#include "error.hpp"
#include "rect.hpp"
#include "NewRDPOrders.hpp"
#include "RDP/orders/RDPOrdersSecondaryBrushCache.hpp"
#include <algorithm>
#include "altoco.hpp"
#include "bitmap.hpp"

namespace RDP {

enum compression_type_t {
    NOT_COMPRESSED,
    COMPRESSED,
    COMPRESSED_SMALL_HEADERS,
    NEW_NOT_COMPRESSED,
    NEW_COMPRESSED
};

struct Orders
{
    // State
    RDPOrderCommon common;
    RDPDestBlt destblt;
    RDPPatBlt patblt;
    RDPScrBlt scrblt;
    RDPOpaqueRect opaquerect;
    RDPMemBlt memblt;
    RDPLineTo lineto;
    RDPGlyphIndex text;

    Stream out_stream;

    uint8_t* order_count_ptr;
    int order_count;
    int order_level;

    Orders() :
        common(0, Rect(0, 0, 1, 1)),
        destblt(Rect(), 0),
        patblt(Rect(), 0, 0, 0, RDPBrush()),
        scrblt(Rect(), 0, 0, 0),
        opaquerect(Rect(), 0),
        memblt(0, Rect(), 0, 0, 0, 0),
        lineto(0, 0, 0, 0, 0, 0, 0, RDPPen(0, 0, 0)),
        text(0, 0, 0, 0, 0, 0, Rect(0, 0, 1, 1), Rect(0, 0, 1, 1), RDPBrush(), 0, 0, 0, (uint8_t*)""),
        out_stream(16384)
    {
        this->order_count = 0;
        this->order_level = 0;
    }

    ~Orders()
    {
    }

    void reset_xx() throw (Error)
    {
        common = RDPOrderCommon(0,  Rect(0, 0, 1, 1));
        memblt = RDPMemBlt(0, Rect(), 0, 0, 0, 0);
        opaquerect = RDPOpaqueRect(Rect(), 0);
        scrblt = RDPScrBlt(Rect(), 0, 0, 0);
        destblt = RDPDestBlt(Rect(), 0);
        patblt = RDPPatBlt(Rect(), 0, 0, 0, RDPBrush());
        lineto = RDPLineTo(0, 0, 0, 0, 0, 0, 0, RDPPen(0, 0, 0));
        text = RDPGlyphIndex(0, 0, 0, 0, 0, 0, Rect(0, 0, 1, 1), Rect(0, 0, 1, 1), RDPBrush(), 0, 0, 0, (uint8_t*)"");
        common.order = PATBLT;

        this->order_count = 0;
        this->order_level = 0;
    }

    int init()
    {
        this->order_level++;
        if (this->order_level == 1) {
            this->order_count = 0;
        }
        return 0;
    }


    void opaque_rect(const RDPOpaqueRect & cmd, const Rect & clip)
    {
        RDPOrderCommon newcommon(RECT, clip);
        cmd.emit(this->out_stream, newcommon, this->common, this->opaquerect);
        this->common = newcommon;
        this->opaquerect = cmd;
    }

    void scr_blt(const RDPScrBlt & cmd, const Rect & clip)
    {
        RDPOrderCommon newcommon(SCREENBLT, clip);
        cmd.emit(this->out_stream, newcommon, this->common, this->scrblt);
        this->common = newcommon;
        this->scrblt = cmd;
    }

    void dest_blt(const RDPDestBlt & cmd, const Rect &clip)
    {
        RDPOrderCommon newcommon(DESTBLT, clip);
        cmd.emit(this->out_stream, newcommon, this->common, this->destblt);
        this->common = newcommon;
        this->destblt = cmd;
    }

    void pat_blt(const RDPPatBlt & cmd, const Rect &clip)
    {
        RDPOrderCommon newcommon(PATBLT, clip);
        cmd.emit(this->out_stream, newcommon, this->common, this->patblt);
        this->common = newcommon;
        this->patblt = cmd;
    }

    void mem_blt(const RDPMemBlt & cmd, const Rect & clip)
    {
        RDPOrderCommon newcommon(MEMBLT, clip);
        cmd.emit(this->out_stream, newcommon, this->common, this->memblt);

        char buffer[1024];
        cmd.str(buffer, 1024, this->common);
        LOG(LOG_INFO, "%s", buffer);

        this->common = newcommon;
        this->memblt = cmd;
    }

    void line_to(const RDPLineTo & cmd, const Rect & clip)
    {
        RDPOrderCommon newcommon(LINE, clip);
        cmd.emit(this->out_stream, newcommon, this->common, this->lineto);
        this->common = newcommon;
        this->lineto = cmd;
    }



    /*****************************************************************************/
    void glyph_index(const RDPGlyphIndex & glyph_index, const Rect & clip)
    {

        RDPOrderCommon newcommon(GLYPHINDEX, clip);
        glyph_index.emit(this->out_stream, newcommon, this->common, this->text);
        this->common = newcommon;
        this->text = glyph_index;
    }


    void color_cache(const uint32_t (& palette)[256], int cache_id)
    {
//        LOG(LOG_INFO, "color_cache[%d](cache_id=%d)\n", this->order_count, cache_id);

        RDPColCache newcmd;
        #warning why is it always palette 0 ? use cache_id
        memcpy(newcmd.palette[0], palette, 256);
        newcmd.emit(this->out_stream, 0);
    }

    void brush_cache(int width, int height, int bpp, int type, int size, uint8_t* data, int cache_id)
    {
        RDPBrushCache newcmd;
        #warning define a construcot with emit parameters
        newcmd.bpp = bpp;
        newcmd.width = width;
        newcmd.height = height;
        newcmd.type = type;
        newcmd.size = size;
        newcmd.data = data;
        newcmd.emit(this->out_stream, cache_id);
        newcmd.data = 0;
    }

    void send_bitmap_common(ClientInfo* client_info, Bitmap & bmp, uint8_t cache_id, uint16_t cache_idx)
    {
        using namespace RDP;

        RDPBmpCache bmp_order(&bmp, cache_id, cache_idx, client_info);

//        LOG(LOG_INFO, "/* send_bitmap[%d](bmp(bpp=%d, cx=%d, cy=%d, data=%p), cache_id=%d, cache_idx=%d) */\n", this->order_count, bmp.bpp, bmp.cx, bmp.cy, bmp.data_co, cache_id, cache_idx);

        bmp_order.emit(this->out_stream);
    }


// MS-RDPEGDI 2.2.2.2.1.2.5     Cache Glyph - Revision 1 (CACHE_GLYPH_ORDER)
// =========================================================================
//  The Cache Glyph - Revision 1 Secondary Drawing Order is used by the server
//  to instruct the client to store a glyph in a particular Glyph Cache entry.
//  Support for glyph caching is negotiated in the Glyph Cache Capability Set
//  (see [MS-RDPBCGR] section 2.2.7.1.8).

//  header (6 bytes): A Secondary Order Header, as defined in section
//  2.2.2.2.1.2.1.1. The embedded orderType field MUST be set to TS_CACHE_GLYPH
// (0x03). The embedded extraFlags field MAY contain the following flag.

// +----------------------------------+----------------------------------------+
// | 0x00100 CG_GLYPH_UNICODE_PRESENT | Indicates that the unicodeCharacters   |
// |                                  | field is present.                      |
// +----------------------------------+----------------------------------------+

// cacheId (1 byte): An 8-bit, unsigned integer. The glyph cache into which to
//   store the glyph data. This value MUST be in the range negotiated by the
//   Glyph Cache Capability Set (see [MS-RDPBCGR] section 2.2.7.1.8).

// cGlyphs (1 byte): An 8-bit, unsigned integer. The number of glyph entries in
//   the glyphData field.

// glyphData (variable): The specification for each of the glyphs in this order
//   (the number of glyphs is specified by the cGlyphs field) defined using
//   Cache Glyph Data structures.

//    MS-RDPEGDI 2.2.2.2.1.2.5.1 Cache Glyph Data (TS_CACHE_GLYPH_DATA)
//    -----------------------------------------------------------------
//    The TS_CACHE_GLYPH_DATA structure contains information describing a single
//    glyph.

// glyphData::cacheIndex (2 bytes): A 16-bit, unsigned integer. The index within
//   a specified Glyph Cache where the glyph data MUST be stored. This value
//   MUST be in the range negotiated by the Glyph Cache Capability Set (see
//   [MS-RDPBCGR] section 2.2.7.1.8).

// glyphData::x (2 bytes): A 16-bit, signed integer. The X component of the
//   coordinate that defines the origin of the character within the glyph
//   bitmap. The top-left corner of the bitmap is (0, 0).

// glyphData::y (2 bytes): A 16-bit, signed integer. The Y component of the
//   coordinate that defines the origin of the character within the glyph
//   bitmap. The top-left corner of the bitmap is (0, 0).

// glyphData::cx (2 bytes): A 16-bit, unsigned integer. The width of the glyph
//   bitmap in pixels.

// glyphData::cy (2 bytes): A 16-bit, unsigned integer. The height of the glyph
//   bitmap in pixels.

// glyphData::aj (variable): A variable-sized byte array containing a
//   1-bit-per-pixel bitmap of the glyph. The individual scan lines are encoded
//   in top-down order, and each scan line MUST be byte-aligned.
//   Once the array has been populated with bitmap data, it MUST be padded to a
//   double-word boundary (the size of the structure in bytes MUST be a multiple
//   of 4). For examples of 1-bit-per-pixel encoded glyph bitmaps, see sections
//   4.6.1 and 4.6.2.

// unicodeCharacters (variable): Contains the Unicode character representation
//   of each glyph in the glyphData field. The number of bytes in the field is
//   given by cGlyphs * 2. This string is used for diagnostic purposes only and
//   is not necessary for successfully decoding and caching the glyphs in the
//   glyphData field.

    void send_font(const FontChar & font_char, int font_index, int char_index)
    {

        int datasize = font_char.datasize();

//        LOG(LOG_INFO, "send_font[%d](font_index=%d, char_index=%d)\n", this->order_count, font_index, char_index);

        int order_flags = STANDARD | SECONDARY;
        this->out_stream.out_uint8(order_flags);
        int len = (datasize + 12) - 7; /* length after type minus 7 */
        this->out_stream.out_uint16_le(len);
        this->out_stream.out_uint16_le(8); /* flags */
        this->out_stream.out_uint8(TS_CACHE_GLYPH); /* type */
        this->out_stream.out_uint8(font_index);

        this->out_stream.out_uint8(1); /* num of chars */
        this->out_stream.out_uint16_le(char_index);
        this->out_stream.out_uint16_le(font_char.offset);
        this->out_stream.out_uint16_le(font_char.baseline);
        this->out_stream.out_uint16_le(font_char.width);
        this->out_stream.out_uint16_le(font_char.height);
        this->out_stream.out_copy_bytes(font_char.data, datasize);
    }

};
} /* namespaces */

#endif
