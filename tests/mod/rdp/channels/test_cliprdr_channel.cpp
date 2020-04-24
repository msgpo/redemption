/*
    This program is free software; you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published by the
     Free Software Foundation; either version 2 of the License, or (at your
     option) any later version.

    This program is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
     Public License for more details.

    You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     675 Mass Ave, Cambridge, MA 02139, USA.

    Product name: redemption, a FLOSS RDP proxy
    Copyright (C) Wallix 2015
    Author(s): Christophe Grosjean, Raphael Zhou
*/


#include "test_only/test_framework/redemption_unit_tests.hpp"
#include "test_only/test_framework/working_directory.hpp"
#include "test_only/test_framework/file.hpp"

#include "test_only/transport/test_transport.hpp"
#include "test_only/fake_stat.hpp"
#include "test_only/lcg_random.hpp"
#include "mod/rdp/channels/cliprdr_channel.hpp"
#include "core/RDP/clipboard.hpp"
#include "core/session_reactor.hpp"
#include "core/RDP/clipboard/format_list_serialize.hpp"
#include "utils/sugar/algostring.hpp"
#include "capture/cryptofile.hpp"
#include "core/log_id.hpp"
#include "capture/fdx_capture.hpp"
#include "mod/file_validator_service.hpp"

#include "./test_channel.hpp"

namespace
{
    namespace data_full_auth
    {
        #include "fixtures/test_cliprdr_channel_xfreerdp_full_authorisation.hpp"
        const auto cb_params = []{ /*NOLINT*/
            ClipboardVirtualChannelParams clipboard_virtual_channel_params;
            clipboard_virtual_channel_params.clipboard_up_authorized   = true;
            clipboard_virtual_channel_params.clipboard_down_authorized = true;
            clipboard_virtual_channel_params.clipboard_file_authorized = true;
            return clipboard_virtual_channel_params;
        }();
    } // namespace data_full_auth

    namespace data_down_denied
    {
        #include "fixtures/test_cliprdr_channel_xfreerdp_down_denied.hpp"
        const auto cb_params = []{ /*NOLINT*/
            ClipboardVirtualChannelParams clipboard_virtual_channel_params;
            clipboard_virtual_channel_params.clipboard_up_authorized   = true;
            clipboard_virtual_channel_params.clipboard_down_authorized = false;
            clipboard_virtual_channel_params.clipboard_file_authorized = true;
            return clipboard_virtual_channel_params;
        }();
    } // namespace data_down_denied

    namespace data_up_denied
    {
        #include "fixtures/test_cliprdr_channel_xfreerdp_up_denied.hpp"
        const auto cb_params = []{ /*NOLINT*/
            ClipboardVirtualChannelParams clipboard_virtual_channel_params;
            clipboard_virtual_channel_params.clipboard_up_authorized   = false;
            clipboard_virtual_channel_params.clipboard_down_authorized = true;
            clipboard_virtual_channel_params.clipboard_file_authorized = true;
            return clipboard_virtual_channel_params;
        }();
    } // namespace data_up_denied

    namespace data_full_denied
    {
        #include "fixtures/test_cliprdr_channel_xfreerdp_full_denied.hpp"
        const auto cb_params = []{ /*NOLINT*/
            ClipboardVirtualChannelParams clipboard_virtual_channel_params;
            clipboard_virtual_channel_params.clipboard_up_authorized   = false;
            clipboard_virtual_channel_params.clipboard_down_authorized = false;
            clipboard_virtual_channel_params.clipboard_file_authorized = true;
            return clipboard_virtual_channel_params;
        }();
    } // namespace data_full_denied
} // anonymous namespace

RED_AUTO_TEST_CASE(TestCliprdrChannelXfreeRDPAuthorisation)
{
    NullReportMessage report_message;
    FileValidatorService * ipca_service = nullptr;

    BaseVirtualChannel::Params base_params(report_message, RDPVerbose::cliprdr /*| RDPVerbose::cliprdr_dump*/);

    struct D
    {
        char const* name;
        ClipboardVirtualChannelParams cb_params;
        bytes_view indata;
        bytes_view outdata;
    };

    #define F(name) D{#name,           \
        name::cb_params,               \
        cstr_array_view(name::indata), \
        cstr_array_view(name::outdata) \
    }

    RED_TEST_CONTEXT_DATA(D const& d, d.name, {
        F(data_full_auth),
        F(data_down_denied),
        F(data_up_denied),
        F(data_full_denied)
    })
    {
        TestTransport t(d.indata, d.outdata);

        TestToClientSender to_client_sender(t);
        TestToServerSender to_server_sender(t);

        SessionReactor session_reactor;
        Inifile ini;
        SesmanInterface sesman(ini);

        ClipboardVirtualChannel clipboard_virtual_channel(
            &to_client_sender, &to_server_sender, session_reactor,
            base_params, d.cb_params, ipca_service, {nullptr, false});

        RED_CHECK_EXCEPTION_ERROR_ID(
            CHECK_CHANNEL(t, clipboard_virtual_channel, sesman),
            ERR_TRANSPORT_NO_MORE_DATA);
    }
}


class NullSender : public VirtualChannelDataSender
{
public:
    void operator() (uint32_t /*total_length*/, uint32_t /*flags*/, bytes_view /*chunk_data*/) override {}
};

RED_AUTO_TEST_CASE(TestCliprdrChannelMalformedFormatListPDU)
{
    NullReportMessage report_message;
    FileValidatorService * ipca_service = nullptr;

    BaseVirtualChannel::Params base_params(report_message, RDPVerbose::cliprdr /*| RDPVerbose::cliprdr_dump*/);

    ClipboardVirtualChannelParams clipboard_virtual_channel_params;
    clipboard_virtual_channel_params.clipboard_down_authorized = true;
    clipboard_virtual_channel_params.clipboard_up_authorized   = true;
    clipboard_virtual_channel_params.clipboard_file_authorized = true;

    NullSender to_client_sender;
    NullSender to_server_sender;

    SessionReactor session_reactor;

    ClipboardVirtualChannel clipboard_virtual_channel(
        &to_client_sender, &to_server_sender, session_reactor,
        base_params, clipboard_virtual_channel_params, ipca_service, {nullptr, false});

    uint8_t  virtual_channel_data[CHANNELS::CHANNEL_CHUNK_LENGTH];
    InStream virtual_channel_stream(virtual_channel_data);

    StaticOutStream<256> out_s;
    Cliprdr::format_list_serialize_with_header(
        out_s, Cliprdr::IsLongFormat(true),
        std::array{Cliprdr::FormatNameRef{RDPECLIP::CF_TEXT, {}}});

    const size_t totalLength = out_s.get_offset();

    clipboard_virtual_channel.process_client_message(
            totalLength,
              CHANNELS::CHANNEL_FLAG_FIRST
            | CHANNELS::CHANNEL_FLAG_LAST
            | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL,
            out_s.get_produced_bytes());
}

RED_AUTO_TEST_CASE(TestCliprdrChannelFailedFormatDataResponsePDU)
{
    NullReportMessage report_message;
    FileValidatorService * ipca_service = nullptr;

    BaseVirtualChannel::Params base_params(report_message, RDPVerbose::cliprdr /*| RDPVerbose::cliprdr_dump*/);

    ClipboardVirtualChannelParams clipboard_virtual_channel_params;
    clipboard_virtual_channel_params.clipboard_down_authorized = true;
    clipboard_virtual_channel_params.clipboard_up_authorized   = true;
    clipboard_virtual_channel_params.clipboard_file_authorized = true;

    NullSender to_client_sender;
    NullSender to_server_sender;

    SessionReactor session_reactor;
    Inifile ini;
    SesmanInterface sesman(ini);

    ClipboardVirtualChannel clipboard_virtual_channel(
        &to_client_sender, &to_server_sender, session_reactor,
        base_params, clipboard_virtual_channel_params, ipca_service, {nullptr, false});

// ClipboardVirtualChannel::process_server_message: total_length=28 flags=0x00000003 chunk_data_length=28
// Recv done on channel (28) n bytes
// /* 0000 */ "\x01\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x1c\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x03\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x1c\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x07\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x0c\x00" // ................
// /* 0010 */ "\x02\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00"                 // ............
// Dump done on channel (28) n bytes
// ClipboardVirtualChannel::process_server_message: Clipboard Capabilities PDU
// ClipboardVirtualChannel::process_server_clipboard_capabilities_pdu: General Capability Set
// RDPECLIP::GeneralCapabilitySet: capabilitySetType=CB_CAPSTYPE_GENERAL(1) lengthCapability=12 version=CB_CAPS_VERSION_2(0x00000002) generalFlags=0x0000001E

    std::unique_ptr<AsynchronousTask> out_asynchronous_task;

    clipboard_virtual_channel.process_server_message(
            28,
              CHANNELS::CHANNEL_FLAG_FIRST
            | CHANNELS::CHANNEL_FLAG_LAST
            | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL,
        /* 0000 */ "\x07\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x0c\x00" // ................
        /* 0010 */ "\x02\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00"                 // ............
                ""_av,
            out_asynchronous_task, sesman);

// ClipboardVirtualChannel::process_client_message: total_length=24 flags=0x00000013 chunk_data_length=24
// Recv done on channel (24) n bytes
// /* 0000 */ "\x00\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x18\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x13\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x18\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x07\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x0c\x00" // ................
// /* 0010 */ "\x02\x00\x00\x00\x1e\x00\x00\x00"                                 // ........
// Dump done on channel (24) n bytes
// ClipboardVirtualChannel::process_client_message: Clipboard Capabilities PDU
// ClipboardVirtualChannel::process_client_clipboard_capabilities_pdu: General Capability Set
// RDPECLIP::GeneralCapabilitySet: capabilitySetType=CB_CAPSTYPE_GENERAL(1) lengthCapability=12 version=CB_CAPS_VERSION_2(0x00000002) generalFlags=0x0000001E

    clipboard_virtual_channel.process_client_message(
            24,
              CHANNELS::CHANNEL_FLAG_FIRST
            | CHANNELS::CHANNEL_FLAG_LAST
            | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL,
    /* 0000 */ "\x07\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x0c\x00" // ................
    /* 0010 */ "\x02\x00\x00\x00\x1e\x00\x00\x00"                                 // ........
                ""_av);

// ClipboardVirtualChannel::process_client_message: total_length=130 flags=0x00000013 chunk_data_length=130
// Recv done on channel (130) n bytes
// /* 0000 */ "\x00\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x82\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x13\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x82\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x02\x00\x00\x00\x7a\x00\x00\x00\x6e\xc0\x00\x00\x46\x00\x69\x00" // ....z...n...F.i.
// /* 0010 */ "\x6c\x00\x65\x00\x47\x00\x72\x00\x6f\x00\x75\x00\x70\x00\x44\x00" // l.e.G.r.o.u.p.D.
// /* 0020 */ "\x65\x00\x73\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x6f\x00" // e.s.c.r.i.p.t.o.
// /* 0030 */ "\x72\x00\x57\x00\x00\x00\x94\xc0\x00\x00\x46\x00\x69\x00\x6c\x00" // r.W.......F.i.l.
// /* 0040 */ "\x65\x00\x43\x00\x6f\x00\x6e\x00\x74\x00\x65\x00\x6e\x00\x74\x00" // e.C.o.n.t.e.n.t.
// /* 0050 */ "\x73\x00\x00\x00\x10\xc1\x00\x00\x50\x00\x72\x00\x65\x00\x66\x00" // s.......P.r.e.f.
// /* 0060 */ "\x65\x00\x72\x00\x72\x00\x65\x00\x64\x00\x20\x00\x44\x00\x72\x00" // e.r.r.e.d. .D.r.
// /* 0070 */ "\x6f\x00\x70\x00\x45\x00\x66\x00\x66\x00\x65\x00\x63\x00\x74\x00" // o.p.E.f.f.e.c.t.
// /* 0080 */ "\x00\x00"                                                         // ..
// Dump done on channel (130) n bytes
// ClipboardVirtualChannel::process_client_message: Format List PDU
// ClipboardVirtualChannel::process_client_format_list_pdu: Long Format Name variant of Format List PDU is used for exchanging updated format names.
// ClipboardVirtualChannel::process_client_format_list_pdu: formatId=<unknown>(49262) wszFormatName="FileGroupDescriptorW"
// ClipboardVirtualChannel::process_client_format_list_pdu: formatId=<unknown>(49300) wszFormatName="FileContents"
// ClipboardVirtualChannel::process_client_format_list_pdu: formatId=<unknown>(49424) wszFormatName="Preferred DropEffect"

    clipboard_virtual_channel.process_client_message(
            130,
              CHANNELS::CHANNEL_FLAG_FIRST
            | CHANNELS::CHANNEL_FLAG_LAST
            | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL,
        /* 0000 */ "\x02\x00\x00\x00\x7a\x00\x00\x00\x6e\xc0\x00\x00\x46\x00\x69\x00" // ....z...n...F.i.
        /* 0010 */ "\x6c\x00\x65\x00\x47\x00\x72\x00\x6f\x00\x75\x00\x70\x00\x44\x00" // l.e.G.r.o.u.p.D.
        /* 0020 */ "\x65\x00\x73\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x6f\x00" // e.s.c.r.i.p.t.o.
        /* 0030 */ "\x72\x00\x57\x00\x00\x00\x94\xc0\x00\x00\x46\x00\x69\x00\x6c\x00" // r.W.......F.i.l.
        /* 0040 */ "\x65\x00\x43\x00\x6f\x00\x6e\x00\x74\x00\x65\x00\x6e\x00\x74\x00" // e.C.o.n.t.e.n.t.
        /* 0050 */ "\x73\x00\x00\x00\x10\xc1\x00\x00\x50\x00\x72\x00\x65\x00\x66\x00" // s.......P.r.e.f.
        /* 0060 */ "\x65\x00\x72\x00\x72\x00\x65\x00\x64\x00\x20\x00\x44\x00\x72\x00" // e.r.r.e.d. .D.r.
        /* 0070 */ "\x6f\x00\x70\x00\x45\x00\x66\x00\x66\x00\x65\x00\x63\x00\x74\x00" // o.p.E.f.f.e.c.t.
        /* 0080 */ "\x00\x00"                                                         // ..
                ""_av);

// ClipboardVirtualChannel::process_server_format_data_request_pdu: requestedFormatId=<unknown>(49262)
// Sending on channel (16) n bytes
// /* 0000 */ "\x00\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x10\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x03\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x10\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00\x00\x00\x00\x00" // ........n.......
// Sent dumped on channel (16) n bytes
// CLIPRDR CB_FORMAT_DATA_RESPONSE format data id = 49262 <unknown>

    clipboard_virtual_channel.process_server_message(
            16,
              CHANNELS::CHANNEL_FLAG_FIRST
            | CHANNELS::CHANNEL_FLAG_LAST
            | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL,
        /* 0000 */ "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00\x00\x00\x00\x00"_av,
            out_asynchronous_task, sesman);

// ClipboardVirtualChannel::process_client_message: total_length=8 flags=0x00000013 chunk_data_length=8
// Recv done on channel (8) n bytes
// /* 0000 */ "\x00\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x08\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x13\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x08\x00\x00\x00"                                                 // ....
// /* 0000 */ "\x05\x00\x02\x00\x00\x00\x00\x00"                                 // ........
// Dump done on channel (8) n bytes
// ClipboardVirtualChannel::process_client_message: Format Data Response PDU

    clipboard_virtual_channel.process_client_message(
            8,
              CHANNELS::CHANNEL_FLAG_FIRST
            | CHANNELS::CHANNEL_FLAG_LAST
            | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL,
        /* 0000 */ "\x05\x00\x02\x00\x00\x00\x00\x00"_av);
}


namespace
{
    struct Msg
    {
        struct Av : ut::flagged_bytes_view
        {
            template<class... Ts>
            Av(Ts&&... xs)
            : ut::flagged_bytes_view{xs...}
            {}
        };

        struct ToMod
        {
            uint32_t total_length;
            uint32_t flags;
            Av av;
        };

        struct ToFront
        {
            uint32_t total_length;
            uint32_t flags;
            Av av;
        };

        struct ToValidator
        {
            Av av;
        };

        struct Log6
        {
            Av av;
        };

        struct Nothing {};
        struct Missing {};

        int type;
        union
        {
            Log6 log6;
            ToMod to_mod;
            ToFront to_front;
            ToValidator to_validator;
        };

        struct OutputData
        {
            std::size_t other_av_len = 0;
            std::size_t mismatch_position = 0;
            ut::PatternView pattern_view = ut::PatternView::deduced;
            bool show_mismatch_position = false;
        };
        mutable OutputData output_data;

        Msg(Log6 log6) : type(0), log6(log6) {}
        Msg(ToMod to_mod) : type(1), to_mod(to_mod) {}
        Msg(ToFront to_front) : type(2), to_front(to_front) {}
        Msg(ToValidator to_validator) : type(3), to_validator(to_validator) {}
        Msg(Nothing) : type(4) {}
        Msg(Missing) : type(5) {}

        bool operator == (Msg const& other) const
        {
            other.output_data.show_mismatch_position = true;

            auto check_av = [&](Av const& lhs, Av const& rhs){
                this->output_data.other_av_len = rhs.size();
                other.output_data.other_av_len = lhs.size();
                this->output_data.pattern_view = rhs.pattern;
                other.output_data.pattern_view = lhs.pattern;
                bool r = ut::compare_bytes(this->output_data.mismatch_position, lhs, rhs);
                other.output_data.mismatch_position = this->output_data.mismatch_position;
                return r;
            };

            if (this->type == other.type)
            {
                auto check_chann = [&](auto& lhs, auto& rhs){
                    return
                        check_av(lhs.av, rhs.av)
                     && lhs.total_length == rhs.total_length
                     && lhs.flags == rhs.flags
                     ;
                };

                switch (other.type)
                {
                    case 0: return check_av(this->log6.av, other.log6.av);
                    case 1: return check_chann(this->to_mod, other.to_mod);
                    case 2: return check_chann(this->to_front, other.to_front);
                    case 3: return check_av(this->to_validator.av, other.to_validator.av);
                }
            }

            auto get_av = [](Msg const& msg){
                switch (msg.type)
                {
                    case 0: return msg.log6.av;
                    case 1: return msg.to_mod.av;
                    case 2: return msg.to_front.av;
                    case 3: return msg.to_validator.av;
                }
                return Av{};
            };

            check_av(get_av(*this), get_av(other));

            return false;
        }

        friend std::ostream& operator<<(std::ostream& out, Msg const& msg)
        {
            char const* names[]{
                "Log6", "ToMod", "ToFront", "ToValidator", "Nothing", "Missing"
            };

            out << names[msg.type] << "{";

            auto const pos = msg.output_data.mismatch_position;
            std::size_t av_len = 0;

            auto put_av = [&](auto av){
                av_len = av.size();

                if (msg.output_data.other_av_len == av_len
                    && msg.output_data.mismatch_position == av_len
                ) {
                    out << "..._av";
                    return ;
                }

                if (av.pattern == ut::PatternView::deduced) {
                    av.pattern = msg.output_data.pattern_view;
                }
                ut::put_view(pos, out, av);
                out << "_av";
            };

            auto put_chann = [&](auto data){
                out << data.total_length << ", " << data.flags << ", ";
                put_av(data.av);
            };

            switch (msg.type)
            {
                case 0: put_av(msg.log6.av); break;
                case 1: put_chann(msg.to_mod); break;
                case 2: put_chann(msg.to_front); break;
                case 3: put_av(msg.to_validator.av); break;
            }

            out << "}";

            if (msg.output_data.other_av_len != av_len
                && msg.output_data.show_mismatch_position
            ) {
                out << "]\nCollections size mismatch: "
                    << av_len << " != " << msg.output_data.other_av_len;
            }

            return out;
        }
    };

    inline auto ininit_msg_comparator_compare = +[](void*, Msg const&)
    {
        // maybe used with dtor of ClipboardVirtualChannel
        RED_REQUIRE(false);
        return true;
    };

    struct MsgComparator
    {
        using func_t = bool(*)(void*, Msg const&);

        template<class Fn, class Process, class... Fns>
        void run(Fn fn, Process&& process, Fns... fns)
        {
            struct Tuple : Fn, Fns... {} t {fn, fns...};
            func_t table[]{
                func_t([](void* data, Msg const& msg){
                    return static_cast<Fn&>(*static_cast<Tuple*>(data))(msg);
                }),
                func_t([](void* data, Msg const& msg){
                    return static_cast<Fns&>(*static_cast<Tuple*>(data))(msg);
                })...
            };
            auto av_table = make_array_view(table);
            this->fn_table = av_table;
            this->index_table = 1;
            this->data = &t;

            int last_index = 1;
            this->last_index_ref = &last_index;

            process();

            // negative = this is deleted
            if (last_index < 0) {
                av_table = av_table.from_offset(-(last_index + 1));
            }
            else {
                av_table = av_table.from_offset(this->index_table);
            }

            for (auto f : av_table) {
                f(&t, Msg::Nothing{});
            }

            if (last_index >= 0) {
                this->fn_table = {&ininit_msg_comparator_compare, 1};
                this->index_table = 1;
            }
        }

        array_view<func_t> fn_table {&ininit_msg_comparator_compare, 1};
        std::size_t index_table = 0;
        void* data;
        int* last_index_ref = nullptr;

        ~MsgComparator()
        {
            if (this->last_index_ref) {
                *this->last_index_ref = -int(this->index_table) - 1;
            }
        }

        void push(Msg const& msg)
        {
            while (1) {
                if (this->index_table < this->fn_table.size()) {
                    bool r = this->fn_table[this->index_table](this->data, msg);
                    ++this->index_table;
                    if (r) {
                        return;
                    }
                }
                else {
                    this->fn_table[0](this->data, msg);
                    return;
                }
            }
        }
    };

#define TEST_PROCESS TEST_BUF(Msg::Missing{}), [&]

#define TEST_BUF(...) [&](Msg const& msg_) { \
    RED_CHECK(Msg(__VA_ARGS__) == msg_);     \
    return true;                             \
}

#define TEST_BUF_IF(cond, ...) [&](Msg const& msg_) { \
    if (cond) {                                       \
        RED_CHECK(Msg(__VA_ARGS__) == msg_);          \
        return true;                                  \
    }                                                 \
    return false;                                     \
}


    class FrontSenderTest : public VirtualChannelDataSender
    {
        MsgComparator& msg_comparator;

    public:
        explicit FrontSenderTest(MsgComparator& msg_comparator)
        : msg_comparator(msg_comparator)
        {}

        void operator()(uint32_t total_length, uint32_t flags, bytes_view chunk_data) override
        {
            msg_comparator.push(Msg::ToFront{total_length, flags, chunk_data});
        }
    };

    class ModSenderTest : public VirtualChannelDataSender
    {
        MsgComparator& msg_comparator;

    public:
        explicit ModSenderTest(MsgComparator& msg_comparator)
        : msg_comparator(msg_comparator)
        {}

        void operator()(uint32_t total_length, uint32_t flags, bytes_view chunk_data) override
        {
            msg_comparator.push(Msg::ToMod{total_length, flags, chunk_data});
        }
    };

    class ReportMessageTest : public NullReportMessage
    {
        MsgComparator& msg_comparator;

    public:
        ReportMessageTest(MsgComparator& msg_comparator)
        : msg_comparator(msg_comparator)
        {}

        void log6(LogId id, const timeval /*time*/, KVList kv_list) override
        {
            std::string s = detail::log_id_string_map[int(id)].data();
            for (auto& kv : kv_list) {
                str_append(s, ' ', kv.key, '=', kv.value);
            }
            this->msg_comparator.push(Msg::Log6{bytes_view(s)});
        }
    };

    class ValidatorTransportTest : public Transport
    {
        MsgComparator& msg_comparator;

    public:
        bytes_view buf_reader {};

        ValidatorTransportTest(MsgComparator& msg_comparator)
        : msg_comparator(msg_comparator)
        {}

        void do_send(const uint8_t * buffer, std::size_t len) override
        {
            this->msg_comparator.push(Msg::ToValidator{bytes_view(buffer, len)});
        }

        size_t do_partial_read(uint8_t* buffer, size_t len) override
        {
            len = std::min(len, this->buf_reader.size());
            memcpy(buffer, this->buf_reader.data(), len);
            this->buf_reader = this->buf_reader.from_offset(len);
            return len;
        }
    };

    struct Buffer
    {
        StaticOutStream<1600> out;

        template<class F>
        bytes_view build(uint16_t msgType, uint16_t msgFlags, F f)
        {
            using namespace RDPECLIP;
            array_view_u8 av = out.out_skip_bytes(CliprdrHeader::size());
            f(this->out);
            OutStream stream_header(av);
            CliprdrHeader(msgType, msgFlags, out.get_offset() - av.size()).emit(stream_header);
            return out.get_produced_bytes();
        }

        template<class F>
        bytes_view build_ok(uint16_t msgType, F f)
        {
            return this->build(msgType, RDPECLIP::CB_RESPONSE_OK, f);
        }
    };


    using namespace std::string_view_literals;

    inline constexpr auto fdx_basename = "sid,blabla.fdx"sv;
    inline constexpr auto sid = "my_session_id"sv;

    struct FdxTestCtx
    {
        FdxTestCtx(char const* name)
        : wd(name)
        {}

        WorkingDirectory wd;
        WorkingDirectory::SubDirectory record_path = wd.create_subdirectory("record");
        WorkingDirectory::SubDirectory hash_path = wd.create_subdirectory("hash");
        WorkingDirectory::SubDirectory fdx_record_path = record_path.create_subdirectory(sid);
        WorkingDirectory::SubDirectory fdx_hash_path = hash_path.create_subdirectory(sid);
        CryptoContext cctx;
        LCGRandom rnd;
        FakeFstat fstat;
        FdxCapture fdx = FdxCapture{
            record_path.dirname().string(),
            hash_path.dirname().string(),
            "sid,blabla", sid, -1, cctx, rnd, fstat,
            ReportError()};
    };

    auto add_file(FdxTestCtx& data_test, std::string_view suffix)
    {
        auto basename = str_concat(sid, suffix);
        auto path = data_test.fdx_record_path.add_file(basename);
        (void)data_test.fdx_hash_path.add_file(basename);
        return path;
    }

    struct ClipDataTest
    {
        bool with_validator;
        bool with_fdx_capture;
        bool always_file_storage;

        friend std::ostream& operator<<(std::ostream& out, ClipDataTest const& d)
        {
            return out <<
                "with validator: " << d.with_validator <<
                "  with fdx: " << d.with_fdx_capture <<
                "  always_file_storage: " << d.always_file_storage
            ;
        }

        ClipboardVirtualChannelParams default_channel_params() const
        {
            ClipboardVirtualChannelParams clipboard_virtual_channel_params {};
            clipboard_virtual_channel_params.clipboard_down_authorized = true;
            clipboard_virtual_channel_params.clipboard_up_authorized   = true;
            clipboard_virtual_channel_params.clipboard_file_authorized = true;
            clipboard_virtual_channel_params.validator_params.down_target_name = "down";
            clipboard_virtual_channel_params.validator_params.up_target_name = "up";
            clipboard_virtual_channel_params.validator_params.log_if_accepted = true;
            clipboard_virtual_channel_params.validator_params.enable_clipboard_text_up = true;
            clipboard_virtual_channel_params.validator_params.enable_clipboard_text_down = true;
            return clipboard_virtual_channel_params;
        }

        std::unique_ptr<FdxTestCtx> make_fdx_ctx() const
        {
            if (this->with_fdx_capture) {
                return std::make_unique<FdxTestCtx>(
                    &"abcdefgh"[this->with_validator * 2 + this->always_file_storage]
                );
            }
            return std::unique_ptr<FdxTestCtx>();
        }

        struct ChannelCtx
        {
            MsgComparator msg_comparator;
            SessionReactor session_reactor;

            ReportMessageTest report_message{msg_comparator};
            ValidatorTransportTest validator_transport{msg_comparator};
            FileValidatorService file_validator_service{validator_transport};

            FrontSenderTest to_client_sender{msg_comparator};
            ModSenderTest to_server_sender{msg_comparator};

            ClipboardVirtualChannel clipboard_virtual_channel;

        public:
            ChannelCtx(timeval time_test,
                FdxTestCtx* fdx_ctx,
                ClipboardVirtualChannelParams clipboard_virtual_channel_params,
                ClipDataTest const& d, RDPVerbose verbose)
            : clipboard_virtual_channel(
                &to_client_sender, &to_server_sender, session_reactor,
                BaseVirtualChannel::Params(report_message, verbose),
                clipboard_virtual_channel_params,
                d.with_validator ? &file_validator_service : nullptr,
                ClipboardVirtualChannel::FileStorage{
                    fdx_ctx ? &fdx_ctx->fdx : nullptr,
                    d.always_file_storage
                }
            )
            {
                session_reactor.set_current_time(time_test);
            }

        private:
            std::unique_ptr<AsynchronousTask> out_asynchronous_task;
            Inifile ini;
            SesmanInterface sesman{ini};

        public:
            void process_server_message(bytes_view av)
            {
                auto flags
                    = CHANNELS::CHANNEL_FLAG_FIRST
                    | CHANNELS::CHANNEL_FLAG_LAST
                    | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL;
                clipboard_virtual_channel.process_server_message(
                    av.size(), flags, av, out_asynchronous_task, sesman);
            }

            void process_client_message(bytes_view av, int flags
                = CHANNELS::CHANNEL_FLAG_FIRST
                | CHANNELS::CHANNEL_FLAG_LAST)
            {
                flags |= CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL;
                clipboard_virtual_channel.process_client_message(av.size(), flags, av);
            }
        };
    };

    constexpr uint32_t first_last_flags
        = CHANNELS::CHANNEL_FLAG_FIRST
        | CHANNELS::CHANNEL_FLAG_LAST
        | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL;

    constexpr uint32_t first_flags
        = CHANNELS::CHANNEL_FLAG_FIRST
        | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL;

    constexpr uint32_t last_flags
        = CHANNELS::CHANNEL_FLAG_LAST
        | CHANNELS::CHANNEL_FLAG_SHOW_PROTOCOL;

    const auto use_long_format = Cliprdr::IsLongFormat(true);
    const auto file_group = Cliprdr::formats::file_group_descriptor_w.ascii_name;
    const auto file_group_id = 49262;
}

#define RED_AUTO_TEST_CLIPRDR(test_name, type_value, iocontext, ...) \
    void test_name##__case(type_value);                              \
    RED_AUTO_TEST_CASE(test_name) {                                  \
        auto l = __VA_ARGS__;                                        \
        auto p = l.begin();                                          \
        RED_TEST_CONTEXT_DATA(type_value, iocontext, l)              \
        {                                                            \
            auto const err_count = RED_ERROR_COUNT();                \
            test_name##__case(*p);                                   \
            if (err_count != RED_ERROR_COUNT()) {                    \
                break;                                               \
            };                                                       \
            ++p;                                                     \
        }                                                            \
    }                                                                \
    void test_name##__case(type_value)

using D = ClipDataTest;

RED_AUTO_TEST_CLIPRDR(TestCliprdrChannelFilterDataFileWithoutLock, D const& d, d, {
    D{true, false, true},
    D{true, true, false},
    D{true, true, true},

    D{false, false, true},
    D{false, true, false},
    D{false, true, true},
}) {
    auto fdx_ctx = d.make_fdx_ctx();
    auto channel_ctx = std::make_unique<D::ChannelCtx>(
        timeval{12345, 54321},
        fdx_ctx.get(),
        d.default_channel_params(),
        d, RDPVerbose::cliprdr /*| RDPVerbose::cliprdr_dump*/);

    MsgComparator& msg_comparator = channel_ctx->msg_comparator;
    ValidatorTransportTest& validator_transport = channel_ctx->validator_transport;
    ClipboardVirtualChannel& clipboard_virtual_channel
        = channel_ctx->clipboard_virtual_channel;

    {
        using namespace RDPECLIP;
        Buffer buf;
        auto av = buf.build(CB_CLIP_CAPS, 0, [&](OutStream& out){
            out.out_uint16_le(CB_CAPSTYPE_GENERAL);
            out.out_clear_bytes(2);
            GeneralCapabilitySet{CB_CAPS_VERSION_1, CB_USE_LONG_FORMAT_NAMES}.emit(out);
        });

        auto capabilities_msg =
            "\x07\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x0c\x00"
            "\x01\x00\x00\x00\x02\x00\x00\x00"
            ""_av;

        msg_comparator.run(
            TEST_PROCESS { channel_ctx->process_server_message(av); },
            TEST_BUF(Msg::ToFront{24, first_last_flags, capabilities_msg})
        );

        msg_comparator.run(
            TEST_PROCESS { channel_ctx->process_client_message(av); },
            TEST_BUF(Msg::ToMod{24, first_last_flags, capabilities_msg})
        );
    }

    msg_comparator.run(
        TEST_PROCESS {
            StaticOutStream<1600> out;
            Cliprdr::format_list_serialize_with_header(
                out,
                use_long_format,
                std::array{Cliprdr::FormatNameRef{file_group_id, file_group}});
            channel_ctx->process_client_message(out.get_produced_bytes());
        },
        TEST_BUF(Msg::ToMod{54, first_last_flags,
            "\x02\x00\x00\x00\x2e\x00\x00\x00\x6e\xc0\x00\x00\x46\x00\x69\x00" //........n...F.i. !
            "\x6c\x00\x65\x00\x47\x00\x72\x00\x6f\x00\x75\x00\x70\x00\x44\x00" //l.e.G.r.o.u.p.D. !
            "\x65\x00\x73\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x6f\x00" //e.s.c.r.i.p.t.o. !
            "\x72\x00\x57\x00\x00\x00" //r.W... !
            ""_av})
    );

    // skip format list response
    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_FORMAT_DATA_REQUEST, 0, [&](OutStream& out){
                out.out_uint32_le(file_group_id);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00"_av})
    );

    auto msg_files =
        "\x05\x00\x01\x00\x54\x02\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00" //....T........... !
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
        ""_av;

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FORMAT_DATA_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(1);    // count item
                out.out_uint32_le(RDPECLIP::FD_FILESIZE);    // flags
                out.out_clear_bytes(32); // reserved1
                out.out_uint32_le(0);    // attributes
                out.out_clear_bytes(16); // reserved2
                out.out_uint64_le(0);    // lastWriteTime
                out.out_uint32_le(0);    // file size high
                out.out_uint32_le(12);   // file size low
                auto filename = "abc"_utf16_le;
                out.out_copy_bytes(filename);
                out.out_clear_bytes(520u - filename.size());
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION"
            " format=FileGroupDescriptorW(49262) size=596"_av}),
        TEST_BUF(Msg::ToMod{604, first_last_flags, msg_files})
    );

    msg_comparator.run(
        TEST_PROCESS {
            using namespace RDPECLIP;
            Buffer buf;
            auto av = buf.build_ok(CB_FILECONTENTS_REQUEST, [&](OutStream& out){
                FileContentsRequestPDU(0, 0, FILECONTENTS_RANGE, 0, 0, 12, 0, true).emit(out);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{36, first_last_flags,
            "\x08\x00\x01\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
            "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00" //................ !
            "\x00\x00\x00\x00"_av})
    );

    // file content

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FILECONTENTS_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(0);
                out.out_copy_bytes("data_abcdefg"_av);
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x07\x00\x00\x00\x19\x00\x00\x00\x01\x00\x02up"
            "\x00\x01\x00\bfilename\x00\x03""abc"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x01\x00\x00\x00\x10\x00\x00\x00\x01"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{"data_abcdefg"_av}),
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_FILE_TO_REMOTE_SESSION"
            " file_name=abc size=12 sha256="
            "d1b9c9db455c70b7c6a70225a00f859931e498f7f5e07f2c962e1078c0359f5e"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x03\x00\x00\x00\x04\x00\x00\x00\x01"_av}),
        TEST_BUF(Msg::ToMod{24, first_last_flags,
            "\t\x00\x01\x00\x10\x00\x00\x00\x00\x00\x00\x00""data_abcdefg"_av})
    );

    if (d.with_validator) {
        StaticOutStream<256> out;
        auto status = "ok"_av;

        using namespace LocalFileValidatorProtocol;
        FileValidatorHeader(MsgType::Result, 0/*len*/).emit(out);
        FileValidatorResultHeader{ValidationResult::IsAccepted, FileValidatorId(1),
            checked_int(status.size())}.emit(out);
        out.out_copy_bytes(status);

        msg_comparator.run(
            TEST_PROCESS {
                validator_transport.buf_reader = out.get_produced_bytes();
                clipboard_virtual_channel.DLP_antivirus_check_channels_files();
                RED_TEST(validator_transport.buf_reader.size() == 0);
            },
            TEST_BUF(Msg::Log6{
                "FILE_VERIFICATION direction=UP file_name=abc status=ok"_av})
        );
    }

    if (fdx_ctx && d.always_file_storage) {
        RED_CHECK_FILE_CONTENTS(add_file(*fdx_ctx, ",000001.tfl"), "data_abcdefg"sv);
    }

    // check TEXT_VALIDATION

    msg_comparator.run(
        TEST_PROCESS {
            StaticOutStream<1600> out;
            Cliprdr::format_list_serialize_with_header(
                out,
                Cliprdr::IsLongFormat(use_long_format),
                std::array{Cliprdr::FormatNameRef{RDPECLIP::CF_TEXT, nullptr}});
            channel_ctx->process_client_message(out.get_produced_bytes());
        },
        TEST_BUF(Msg::ToMod{14, first_last_flags,
            "\x02\x00\x00\x00\x06\x00\x00\x00\x01\x00\x00\x00\x00\x00"
            ""_av})
    );

    // skip format list response

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_FORMAT_DATA_REQUEST, 0, [&](OutStream& out){
                out.out_uint32_le(RDPECLIP::CF_UNICODETEXT);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x04\x00\x00\x00\x04\x00\x00\x00\r\x00\x00\x00"
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FORMAT_DATA_RESPONSE, [&](OutStream& out){
                out.out_copy_bytes("a\0b\0c\0"_av);
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x07\x00\x00\x00\"\x00\x00\x00\x02\x00\x02up"
            "\x00\x01\x00\x13microsoft_locale_id\x00\x01""0"_av
        }),
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION_EX"
            " format=CF_UNICODETEXT(13) size=6 partial_data=abc"_av
        }),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x01\x00\x00\x00\x07\x00\x00\x00\x02"_av
        }),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{"abc"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x03\x00\x00\x00\x04\x00\x00\x00\x02"_av
        }),
        TEST_BUF(Msg::ToMod{14, first_last_flags,
            "\x05\x00\x01\x00\x06\x00\x00\x00""a\x00""b\x00""c\x00"_av
            ""_av})
    );

    if (d.with_validator) {
        StaticOutStream<256> out;
        auto status = "ok"_av;

        using namespace LocalFileValidatorProtocol;
        FileValidatorHeader(MsgType::Result, 0/*len*/).emit(out);
        FileValidatorResultHeader{ValidationResult::IsAccepted, FileValidatorId(2),
            checked_int(status.size())}.emit(out);
        out.out_copy_bytes(status);

        msg_comparator.run(
            TEST_PROCESS {
                validator_transport.buf_reader = out.get_produced_bytes();
                clipboard_virtual_channel.DLP_antivirus_check_channels_files();
                RED_TEST(validator_transport.buf_reader.size() == 0);
            },
            TEST_BUF(Msg::Log6{
                "TEXT_VERIFICATION direction=UP copy_id=2 status=ok"_av})
        );
    }

    msg_comparator.run(TEST_PROCESS {
        channel_ctx.reset();
    });

    if (fdx_ctx) {
        (void)fdx_ctx->hash_path.add_file(fdx_basename);
        auto fdx_path = fdx_ctx->record_path.add_file(fdx_basename);

        OutCryptoTransport::HashArray qhash;
        OutCryptoTransport::HashArray fhash;
        fdx_ctx->fdx.close(qhash, fhash);

        RED_CHECK_WORKSPACE(fdx_ctx->wd);

        if (d.always_file_storage) {
            RED_CHECK_FILE_CONTENTS(fdx_path,
                "v3\n\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00,\x03\x00\x26\x00""abcmy_session_id/my_session_id,000001.tfl\xd1\xb9\xc9"
                "\xdb""E\\p\xb7\xc6\xa7\x02%\xa0\x0f\x85\x99""1\xe4\x98\xf7\xf5\xe0"
                "\x7f,\x96.\x10x\xc0""5\x9f^"_av);
        }
        else {
            RED_CHECK_FILE_CONTENTS(fdx_path, "v3\n"_av);
        }
    }
}

RED_AUTO_TEST_CLIPRDR(TestCliprdrChannelFilterDataMultiFileWithLock, D const& d, d, {
    D{true, false, true},
    D{true, true, false},
    D{true, true, true},
    D{false, false, true},
    D{false, true, false},
    D{false, true, true},
})
{
    auto fdx_ctx = d.make_fdx_ctx();
    auto channel_ctx = std::make_unique<D::ChannelCtx>(
        timeval{12345, 54321},
        fdx_ctx.get(),
        d.default_channel_params(),
        d, RDPVerbose::cliprdr /*| RDPVerbose::cliprdr_dump*/);

    MsgComparator& msg_comparator = channel_ctx->msg_comparator;
    ValidatorTransportTest& validator_transport = channel_ctx->validator_transport;
    ClipboardVirtualChannel& clipboard_virtual_channel
        = channel_ctx->clipboard_virtual_channel;

    {
        using namespace RDPECLIP;
        Buffer buf;
        auto av = buf.build(CB_CLIP_CAPS, 0, [&](OutStream& out){
            out.out_uint16_le(CB_CAPSTYPE_GENERAL);
            out.out_clear_bytes(2);
            GeneralCapabilitySet{CB_CAPS_VERSION_1,
                RDPECLIP::CB_CAN_LOCK_CLIPDATA | CB_USE_LONG_FORMAT_NAMES
            }.emit(out);
        });

        auto capabilities_msg =
            "\x07\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x01\x00\x0c\x00"
            "\x01\x00\x00\x00\x12\x00\x00\x00"
            ""_av;

        msg_comparator.run(
            TEST_PROCESS { channel_ctx->process_server_message(av); },
            TEST_BUF(Msg::ToFront{24, first_last_flags, capabilities_msg})
        );

        msg_comparator.run(
            TEST_PROCESS { channel_ctx->process_client_message(av); },
            TEST_BUF(Msg::ToMod{24, first_last_flags, capabilities_msg})
        );
    }

    msg_comparator.run(
        TEST_PROCESS {
            StaticOutStream<1600> out;
            Cliprdr::format_list_serialize_with_header(
                out,
                use_long_format,
                std::array{Cliprdr::FormatNameRef{file_group_id, file_group}});

            channel_ctx->process_client_message(out.get_produced_bytes());
        },
        TEST_BUF(Msg::ToMod{54, first_last_flags,
            "\x02\x00\x00\x00\x2e\x00\x00\x00\x6e\xc0\x00\x00\x46\x00\x69\x00" //........n...F.i. !
            "\x6c\x00\x65\x00\x47\x00\x72\x00\x6f\x00\x75\x00\x70\x00\x44\x00" //l.e.G.r.o.u.p.D. !
            "\x65\x00\x73\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x6f\x00" //e.s.c.r.i.p.t.o. !
            "\x72\x00\x57\x00\x00\x00" //r.W... !
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_LOCK_CLIPDATA, 0, [&](OutStream& out){
                out.out_uint32_le(0);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x0A\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_FORMAT_DATA_REQUEST, 0, [&](OutStream& out){
                out.out_uint32_le(file_group_id);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00"_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FORMAT_LIST_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(file_group_id);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x03\x00\x01\x00\x04\x00\x00\x00n\xc0\x00\x00"_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_FORMAT_DATA_REQUEST, 0, [&](OutStream& out){
                out.out_uint32_le(file_group_id);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00"_av})
    );

    auto msg_files1 =
        "\x05\x00\x01\x00\x54\x02\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00" //....T........... !
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
        ""_av;

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FORMAT_DATA_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(1);    // count item
                out.out_uint32_le(RDPECLIP::FD_FILESIZE);    // flags
                out.out_clear_bytes(32); // reserved1
                out.out_uint32_le(0);    // attributes
                out.out_clear_bytes(16); // reserved2
                out.out_uint64_le(0);    // lastWriteTime
                out.out_uint32_le(0);    // file size high
                out.out_uint32_le(12);   // file size low
                auto filename = "abc"_utf16_le;
                out.out_copy_bytes(filename);
                out.out_clear_bytes(520u - filename.size());
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION"
            " format=FileGroupDescriptorW(49262) size=596"_av}),
        TEST_BUF(Msg::ToMod{604, first_last_flags, msg_files1})
    );

    msg_comparator.run(
        TEST_PROCESS {
            using namespace RDPECLIP;
            Buffer buf;
            auto av = buf.build_ok(CB_FILECONTENTS_REQUEST, [&](OutStream& out){
                FileContentsRequestPDU(0, 0, FILECONTENTS_RANGE, 0, 0, 5, 0, true).emit(out);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{36, first_last_flags,
            "\x08\x00\x01\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
            "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00" //................ !
            "\x00\x00\x00\x00"_av})
    );

    // (partial) file content (2 packets)

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FILECONTENTS_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(0);
                out.out_copy_bytes("da"_av);
            });
            channel_ctx->process_client_message(av, CHANNELS::CHANNEL_FLAG_FIRST);
        },
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x07\x00\x00\x00\x19\x00\x00\x00\x01\x00\x02up\x00\x01\x00\b"
            "filename\x00\x03""abc"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x01\x00\x00\x00\x06\x00\x00\x00\x01"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{"da"_av}),
        TEST_BUF(Msg::ToMod{14, first_flags,
            "\x09\x00\x01\x00\x06\x00\x00\x00\x00\x00\x00\x00""da"_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            channel_ctx->process_client_message("ta_"_av, CHANNELS::CHANNEL_FLAG_LAST);
        },
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x01\x00\x00\x00\x07\x00\x00\x00\x01"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{"ta_"_av}),
        TEST_BUF(Msg::ToMod{3, last_flags, "ta_"_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            StaticOutStream<1600> out;
            Cliprdr::format_list_serialize_with_header(
                out,
                use_long_format,
                std::array{Cliprdr::FormatNameRef{file_group_id, file_group}});
            channel_ctx->process_client_message(out.get_produced_bytes());
        },
        TEST_BUF(Msg::ToMod{54, first_last_flags,
            "\x02\x00\x00\x00\x2e\x00\x00\x00\x6e\xc0\x00\x00\x46\x00\x69\x00" //........n...F.i. !
            "\x6c\x00\x65\x00\x47\x00\x72\x00\x6f\x00\x75\x00\x70\x00\x44\x00" //l.e.G.r.o.u.p.D. !
            "\x65\x00\x73\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x6f\x00" //e.s.c.r.i.p.t.o. !
            "\x72\x00\x57\x00\x00\x00" //r.W... !
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_LOCK_CLIPDATA, 0, [&](OutStream& out){
                out.out_uint32_le(1);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x0A\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00"
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_FORMAT_DATA_REQUEST, 0, [&](OutStream& out){
                out.out_uint32_le(file_group_id);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00"
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(
                RDPECLIP::CB_FORMAT_LIST_RESPONSE,
                RDPECLIP::CB_RESPONSE_OK, [&](OutStream& out){
                    out.out_uint32_le(file_group_id);
                });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x03\x00\x01\x00\x04\x00\x00\x00n\xc0\x00\x00"
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_FORMAT_DATA_REQUEST, 0, [&](OutStream& out){
                out.out_uint32_le(file_group_id);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x04\x00\x00\x00\x04\x00\x00\x00\x6e\xc0\x00\x00"
            ""_av})
    );

    auto msg_files2 =
        "\x05\x00\x01\x00\x54\x02\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00" //....T........... !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" //................ !
        "\x0a\x00\x00\x00\x64\x00\x65\x00\x66\x00\x00\x00\x00\x00\x00\x00" //....d.e.f....... !
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
        ""_av;

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FORMAT_DATA_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(1);    // count item
                out.out_uint32_le(RDPECLIP::FD_FILESIZE);    // flags
                out.out_clear_bytes(32); // reserved1
                out.out_uint32_le(0);    // attributes
                out.out_clear_bytes(16); // reserved2
                out.out_uint64_le(0);    // lastWriteTime
                out.out_uint32_le(0);    // file size high
                out.out_uint32_le(10);   // file size low
                auto filename = "def"_utf16_le;
                out.out_copy_bytes(filename);
                out.out_clear_bytes(520u - filename.size());
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION"
            " format=FileGroupDescriptorW(49262) size=596"_av}),
        TEST_BUF(Msg::ToMod{604, first_last_flags, msg_files2})
    );

    msg_comparator.run(
        TEST_PROCESS {
            using namespace RDPECLIP;
            Buffer buf;
            auto av = buf.build_ok(CB_FILECONTENTS_REQUEST, [&](OutStream& out){
                FileContentsRequestPDU(1, 0, FILECONTENTS_RANGE, 0, 0, 99, 1, true).emit(out);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{36, first_last_flags,
            "\x08\x00\x01\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" //................ !
            "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x00\x00\x00" //................ !
            "\x01\x00\x00\x00"_av})
    );

    // file content

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FILECONTENTS_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(1);
                out.out_copy_bytes("plopploppl"_av);
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x07\x00\x00\x00\x19\x00\x00\x00\x02\x00\x02up\x00\x01\x00\b"
            "filename\x00\x03""def"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x01\x00\x00\x00\x0e\x00\x00\x00\x02"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{"plopploppl"_av}),
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_FILE_TO_REMOTE_SESSION file_name=def size=10"
            " sha256=dda098fc2804923ceeef1b65f26b78be8789535b7b9dddb6fda8de6a2dacf190"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x03\x00\x00\x00\x04\x00\x00\x00\x02"_av}),
        TEST_BUF(Msg::ToMod{22, first_last_flags,
            "\t\x00\x01\x00\x0e\x00\x00\x00\x01\x00\x00\x00""plopploppl"
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            Buffer buf;
            auto av = buf.build(RDPECLIP::CB_UNLOCK_CLIPDATA, 0, [&](OutStream& out){
                out.out_uint32_le(1);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{12, first_last_flags,
            "\x0B\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00"
            ""_av})
    );

    msg_comparator.run(
        TEST_PROCESS {
            using namespace RDPECLIP;
            Buffer buf;
            auto av = buf.build_ok(CB_FILECONTENTS_REQUEST, [&](OutStream& out){
                FileContentsRequestPDU(0, 0, FILECONTENTS_RANGE, 5, 0, 99, 0, true).emit(out);
            });
            channel_ctx->process_server_message(av);
        },
        TEST_BUF(Msg::ToFront{36, first_last_flags,
            "\x08\x00\x01\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x02\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x63\x00\x00\x00"
            "\x00\x00\x00\x00"_av})
    );

    // (last partial) file content

    msg_comparator.run(
        TEST_PROCESS {
            using namespace Cliprdr;
            Buffer buf;
            auto av = buf.build_ok(RDPECLIP::CB_FILECONTENTS_RESPONSE, [&](OutStream& out){
                out.out_uint32_le(0);
                out.out_copy_bytes("abcdefg"_av);
            });
            channel_ctx->process_client_message(av);
        },
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x01\x00\x00\x00\x0b\x00\x00\x00\x01"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{"abcdefg"_av}),
        TEST_BUF(Msg::Log6{
            "CB_COPYING_PASTING_FILE_TO_REMOTE_SESSION file_name=abc size=12"
            " sha256=d1b9c9db455c70b7c6a70225a00f859931e498f7f5e07f2c962e1078c0359f5e"_av}),
        TEST_BUF_IF(d.with_validator, Msg::ToValidator{
            "\x03\x00\x00\x00\x04\x00\x00\x00\x01"_av}),
        TEST_BUF(Msg::ToMod{19, first_last_flags,
            "\t\x00\x01\x00\x0b\x00\x00\x00\x00\x00\x00\x00""abcdefg"_av})
    );

    if (d.with_validator) {
        StaticOutStream<256> out;
        auto status = "ok"_av;

        using namespace LocalFileValidatorProtocol;
        FileValidatorHeader(MsgType::Result, 0/*len*/).emit(out);
        FileValidatorResultHeader{ValidationResult::IsAccepted, FileValidatorId(1),
            checked_int(status.size())}.emit(out);
        out.out_copy_bytes(status);

        msg_comparator.run(
            TEST_PROCESS {
                validator_transport.buf_reader = out.get_produced_bytes().as_chars();
                clipboard_virtual_channel.DLP_antivirus_check_channels_files();
                RED_TEST(validator_transport.buf_reader.size() == 0);
            },
            TEST_BUF(Msg::Log6{"FILE_VERIFICATION direction=UP file_name=abc status=ok"_av})
        );
    }

    msg_comparator.run(
        TEST_PROCESS {channel_ctx.reset();},
        TEST_BUF_IF(d.with_validator, Msg::Log6{
            "FILE_VERIFICATION direction=UP file_name=def status=Connexion closed"_av})
    );

    if (fdx_ctx) {
        if (d.always_file_storage) {
            RED_CHECK_FILE_CONTENTS(add_file(*fdx_ctx, ",000001.tfl"), "data_abcdefg"sv);
        }

        if (d.with_validator || (d.with_fdx_capture && d.always_file_storage)) {
            RED_CHECK_FILE_CONTENTS(add_file(*fdx_ctx, ",000002.tfl"), "plopploppl"sv);
        }

        (void)fdx_ctx->hash_path.add_file(fdx_basename);
        auto fdx_path = fdx_ctx->record_path.add_file(fdx_basename);

        OutCryptoTransport::HashArray qhash;
        OutCryptoTransport::HashArray fhash;
        fdx_ctx->fdx.close(qhash, fhash);

        if (d.with_validator && d.always_file_storage) {
            RED_CHECK_FILE_CONTENTS(fdx_path,
                "v3\n\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00,\x03\x00\x26\x00"
                "abcmy_session_id/my_session_id,000001.tfl\xd1\xb9\xc9"
                "\xdb""E\\p\xb7\xc6\xa7\x02%\xa0\x0f\x85\x99""1\xe4\x98"
                "\xf7\xf5\xe0\x7f,\x96.\x10x\xc0""5\x9f^\x04\x00\x02\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "L\x03\x00&\x00""defmy_session_id/my_session_id,000002.tfl"
                "\xdd\xa0\x98\xfc(\x04\x92<\xee\xef\x1b""e\xf2kx\xbe\x87"
                "\x89S[{\x9d\xdd\xb6\xfd\xa8\xdej-\xac\xf1\x90"_av);
        }
        else if (d.always_file_storage) {
            RED_CHECK_FILE_CONTENTS(fdx_path,
                "v3\n\x04\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00,\x03\x00&\x00""defmy_session_id/my_session_id,000002.tfl"
                "\xdd\xa0\x98\xfc(\x04\x92<\xee\xef\x1b""e\xf2kx\xbe\x87\x89S[{\x9d"
                "\xdd\xb6\xfd\xa8\xdej-\xac\xf1\x90\x04\x00\x01\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,\x03\x00&\x00"
                "abcmy_session_id/my_session_id,000001.tfl\xd1\xb9\xc9\xdb""E\\p\xb7"
                "\xc6\xa7\x02%\xa0\x0f\x85\x99""1\xe4\x98\xf7\xf5\xe0\x7f,\x96.\x10"
                "x\xc0""5\x9f^"_av);
        }
        else if (d.with_validator && d.with_fdx_capture) {
            RED_CHECK_FILE_CONTENTS(fdx_path,
                "v3\n\x04\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00L\x03\x00&\x00""defmy_session_id/my_session_id,000002.tfl"
                "\xdd\xa0\x98\xfc(\x04\x92<\xee\xef\x1b""e\xf2kx\xbe\x87\x89S[{"
                "\x9d\xdd\xb6\xfd\xa8\xdej-\xac\xf1\x90"_av);
        }
        else {
            RED_CHECK_FILE_CONTENTS(fdx_path, "v3\n"_av);
        }

        RED_CHECK_WORKSPACE(fdx_ctx->wd);
    }
}
