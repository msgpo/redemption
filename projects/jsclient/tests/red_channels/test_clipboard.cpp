/*
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

Product name: redemption, a FLOSS RDP proxy
Copyright (C) Wallix 2010-2019
Author(s): Jonathan Poelen
*/

#include "test_only/test_framework/redemption_unit_tests.hpp"
#include "binding_channel.hpp"

#include "red_channels/clipboard.hpp"

#include "core/RDP/clipboard.hpp"
#include "core/RDP/clipboard/format_list_serialize.hpp"
#include "utils/literals/utf16.hpp"

#include <tuple>
#include <vector>

namespace
{

struct DataChan : DataChan_tuple
{
    using DataChan_tuple::tuple;

    DataChan(bytes_view av, size_t total_len, uint32_t channel_flags)
    : DataChan(
        channel_names::cliprdr,
        {av.begin(), av.end()},
        total_len != ~0u ? total_len : av.size(),
        channel_flags)
    {}

    friend std::ostream& operator<<(std::ostream& out, DataChan const& x)
    {
        DataChan_tuple const& t = x;
        out << "DataChan{" << std::get<0>(t) << ", {";
        InStream in_stream(std::get<1>(t));
        RDPECLIP::CliprdrHeader header;
        header.recv(in_stream);
        out << "0x" << std::hex << header.msgType() << ", 0x" << header.msgFlags()
            << std::dec << ", " << header.dataLen() << ", ";
        print_bytes(out, in_stream.remaining_bytes());
        out << "}, " << std::get<2>(t) << ", 0x" << std::hex << std::get<3>(t) << std::dec << "}";
        return out;
    }
};

MAKE_BINDING_CALLBACKS(
    DataChan,
    (JS_x_f(setGeneralCapability, return generalFlags, uint32_t generalFlags))
    (JS_c(receiveFormatStart))
    (JS_d(receiveFormat, uint8_t, uint32_t formatId, bool isUTF8))
    (JS_c(receiveFormatStop))
    (JS_d(receiveData, uint8_t, uint32_t channelFlags))
    (JS_x(receiveNbFileName, uint32_t nb))
    (JS_d(receiveFileName, uint8_t, uint32_t attr, uint32_t flags, uint32_t sizeLow, uint32_t sizeHigh, uint32_t lastWriteTimeLow, uint32_t lastWriteTimeHigh))
    (JS_d(receiveFileContents, uint8_t, uint32_t streamId, uint32_t channelFlags))
    (JS_x(receiveFormatId, uint32_t format_id))
    (JS_x(receiveFileContentsRequest, uint32_t streamId, uint32_t type, uint32_t lindex, uint32_t nposLow, uint32_t nposHigh, uint32_t szRequested))
    (JS_x(receiveResponseFail, uint32_t messageType))
)

std::unique_ptr<redjs::ClipboardChannel> clip;

void test_init_channel(Callback& cb, emscripten::val&& v)
{
    clip = std::make_unique<redjs::ClipboardChannel>(cb, std::move(v), true);
}

constexpr int first_last_show_proto_channel_flags
    = CHANNELS::CHANNEL_FLAG_LAST
    | CHANNELS::CHANNEL_FLAG_FIRST
    | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL
;

constexpr int first_last_channel_flags
    = CHANNELS::CHANNEL_FLAG_LAST
    | CHANNELS::CHANNEL_FLAG_FIRST
;

void clip_raw_receive(bytes_view data, int channel_flags = first_last_show_proto_channel_flags)
{
    clip->receive(data, channel_flags);
}

enum class Padding : unsigned;

struct Serializer
{
    StaticOutStream<65536> out_stream;

    Serializer(uint16_t msgType, uint16_t msgFlags, bytes_view data, Padding padding_data)
    {
        RDPECLIP::CliprdrHeader header(msgType, msgFlags, data.size());
        header.emit(out_stream);
        out_stream.out_copy_bytes(data);
        auto padding = unsigned(padding_data);
        while (padding--) {
            out_stream.out_uint8(0);
        }
    }

    operator bytes_view () const
    {
        return out_stream.get_bytes();
    }
};

void clip_receive(
    uint16_t msgType, uint16_t msgFlags,
    bytes_view data = {},
    Padding padding_data = Padding{},
    uint32_t channel_flags = first_last_show_proto_channel_flags)
{
    clip_raw_receive(Serializer(msgType, msgFlags, data, padding_data), channel_flags);
}

DataChan data_chan(
    uint16_t msgType, uint16_t msgFlags,
    bytes_view data = {},
    Padding padding_data = Padding{},
    std::size_t len = ~0u, uint32_t channel_flags = first_last_show_proto_channel_flags)
{
    return DataChan{Serializer(msgType, msgFlags, data, padding_data), len, channel_flags};
}


#define RECEIVE_DATAS(...) ::clip_receive(__VA_ARGS__); CTX_CHECK_DATAS()
#define CALL_CB(...) clip->__VA_ARGS__; CTX_CHECK_DATAS()

}

RED_AUTO_TEST_CASE(TestClipboardChannel)
{
    using namespace RDPECLIP;
    namespace cbchan = redjs::channels::clipboard;
    init_js_channel();

    const bool is_utf = true;
    const bool not_utf = false;

    RECEIVE_DATAS(CB_CLIP_CAPS, CB_RESPONSE__NONE_,
        "\x01\x00\x00\x00\x01\x00\x0c\x00\x02\x00\x00\x00\x12\x00\x00\x00"_av, Padding(4))
    {
        CHECK_NEXT_DATA(setGeneralCapability{
            RDPECLIP::CB_USE_LONG_FORMAT_NAMES |
            RDPECLIP::CB_CAN_LOCK_CLIPDATA
        });
    };

    RECEIVE_DATAS(CB_MONITOR_READY, CB_RESPONSE__NONE_)
    {
        CHECK_NEXT_DATA(data_chan(CB_CLIP_CAPS, CB_RESPONSE__NONE_,
            "\x01\0\0\0\x01\0\x0C\0\x02\0\0\0\x12\0\0\0"_av));
        CHECK_NEXT_DATA(data_chan(CB_FORMAT_LIST, CB_ASCII_NAMES, ""_av));
    };

    RECEIVE_DATAS(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK)
    {
    };

    // copy (server -> client)

    RECEIVE_DATAS(CB_FORMAT_LIST, CB_RESPONSE__NONE_,
        "\x0d\x00\x00\x00\x00\x00"
        "\x10\x00\x00\x00\x00\x00"
        "\x01\x00\x00\x00\x00\x00"
        "\x07\x00\x00\x00\x00\x00"_av, Padding(4))
    {
        CHECK_NEXT_DATA(receiveFormatStart{});
        CHECK_NEXT_DATA(receiveFormat{""_av, CF_UNICODETEXT, is_utf});
        CHECK_NEXT_DATA(receiveFormat{""_av, CF_LOCALE, is_utf});
        CHECK_NEXT_DATA(receiveFormat{""_av, CF_TEXT, is_utf});
        CHECK_NEXT_DATA(receiveFormat{""_av, CF_OEMTEXT, is_utf});
        CHECK_NEXT_DATA(receiveFormatStop{});
        CHECK_NEXT_DATA(data_chan(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK));
    };

    CALL_CB(send_request_format(CF_UNICODETEXT, cbchan::CustomFormat::None))
    {
        CHECK_NEXT_DATA(data_chan(CB_FORMAT_DATA_REQUEST, CB_RESPONSE__NONE_, "\x0d\0\0\0"_av));
    };

    auto copy1 = "plop\0"_utf16_le;
    RECEIVE_DATAS(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, copy1, Padding(4))
    {
        CHECK_NEXT_DATA(receiveData(copy1, first_last_channel_flags));
    };

    // paste (client -> server)

    CALL_CB(send_format(CF_UNICODETEXT, cbchan::Charset::Utf16, ""_av))
    {
        CHECK_NEXT_DATA(data_chan(CB_FORMAT_LIST, CB_RESPONSE__NONE_, "\x0d\0\0\0\0\0"_av));
    };

    RECEIVE_DATAS(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK, ""_av, Padding(4))
    {
    };

    RECEIVE_DATAS(CB_FORMAT_DATA_REQUEST, CB_RESPONSE__NONE_, "\x0d\x00\x00\x00"_av, Padding(4))
    {
        CHECK_NEXT_DATA(receiveFormatId{CF_UNICODETEXT});
    };

    const auto paste1 = "xyz\0"_utf16_le;
    CALL_CB(send_header(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, paste1.size(), 0))
    {
        CHECK_NEXT_DATA(DataChan{"\x05\0\1\0\x08\0\0\0"_av, paste1.size() + 8,
            CHANNELS::CHANNEL_FLAG_FIRST | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL});
    };

    CALL_CB(send_data(paste1, 0, CHANNELS::CHANNEL_FLAG_LAST))
    {
        CHECK_NEXT_DATA(DataChan{paste1, 0,
            CHANNELS::CHANNEL_FLAG_LAST | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL});
    };

    // file copy (server -> client)

    RECEIVE_DATAS(CB_FORMAT_LIST, CB_RESPONSE__NONE_,
        "\x6e\xc0\x00\x00\x46\x00\x69\x00" //n...F.i. !
        "\x6c\x00\x65\x00\x47\x00\x72\x00\x6f\x00\x75\x00\x70\x00\x44\x00" //l.e.G.r.o.u.p.D. !
        "\x65\x00\x73\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x6f\x00" //e.s.c.r.i.p.t.o. !
        "\x72\x00\x57\x00\x00\x00" //r.W... !
        ""_av, Padding(4))
    {
        CHECK_NEXT_DATA(receiveFormatStart{});
        CHECK_NEXT_DATA(receiveFormat{"FileGroupDescriptorW"_utf16_le, 49262, not_utf});
        CHECK_NEXT_DATA(receiveFormatStop{});
        CHECK_NEXT_DATA(data_chan(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK));
    };

    CALL_CB(send_request_format(49262, cbchan::CustomFormat::FileGroupDescriptorW))
    {
        CHECK_NEXT_DATA(data_chan(CB_FORMAT_DATA_REQUEST, CB_RESPONSE__NONE_,
            "\x6e\xc0\x00\x00"_av));
    };

    RECEIVE_DATAS(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK,
        "\x01\x00\x00\x00\x00\x00\x00\x00" //....T........... !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x0c\x00\x00\x00\x61\x00\x62\x00\x63\x00\x00\x00\x00\x00\x00\x00" //....a.b.c....... !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //............ !
        ""_av
        , Padding(4))
    {
        CHECK_NEXT_DATA(receiveNbFileName{1});
        CHECK_NEXT_DATA(receiveFileName{"abc"_utf16_le,
            /*.attr=*/0, /*.flags=*/0,
            /*.sizeLow=*/12, /*.sizeHigh=*/0,
            /*.lastWriteTimeLow=*/0, /*.lastWriteTimeHigh=*/0});
    };

    CALL_CB(send_data(
        "\x08\x00\x01\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00" //................ !
        "\x00\x00\x00\x00"_av))
    {
        CHECK_NEXT_DATA(data_chan(CB_FILECONTENTS_REQUEST, CB_RESPONSE_OK,
            "\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\0\0\0\0"_av));
    };

    RECEIVE_DATAS(CB_FILECONTENTS_RESPONSE, CB_RESPONSE__NONE_,
        "\x00\x00\x00\x00""abcdefghijkl"_av, Padding(4))
    {
        CHECK_NEXT_DATA(receiveFileContents{"\0\0\0\0""abcdefghijkl"_av, 0,
            CHANNELS::CHANNEL_FLAG_FIRST | CHANNELS::CHANNEL_FLAG_LAST});
    };

    // response fail

    RECEIVE_DATAS(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_FAIL, ""_av, Padding(4))
    {
        CHECK_NEXT_DATA(receiveResponseFail{CB_FORMAT_LIST_RESPONSE});
    };
}
