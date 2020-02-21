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
    Author(s): Christophe Grosjean, Raphael Zhou, Clément Moroldo
*/

#include "mod/rdp/channels/cliprdr_channel.hpp"
#include "utils/sugar/not_null_ptr.hpp"


namespace
{
    enum LockId : uint32_t;

    template<class T>
    void vector_fast_erase(std::vector<T>& v, T* p)
    {
        if (p != &v.back()) {
            auto n = std::distance(&v.front(), p);
            v[n] = std::move(v.back());
        }
        v.pop_back();
    }

    struct ClipCtx
    {
        struct Sig
        {
            void update(bytes_view data)
            {
                this->sha256.update(data);
            }

            void final()
            {
                assert(this->status == Status::Update);
                this->sha256.final(this->array);
                this->status = Status::Final;
            }

            void broken()
            {
                assert(this->status == Status::Update);
                this->sha256.final(this->array);
                this->status = Status::Broken;
            }

            bool has_digest() const noexcept
            {
                return this->status != Status::Update;
            }

            static const std::size_t digest_len = SslSha256::DIGEST_LENGTH;

            auto& digest() const noexcept
            {
                assert(this->has_digest());
                return this->array;
            }

            bytes_view digest_as_av() const noexcept
            {
                return make_array_view(this->digest());
            }

        private:
            enum class Status : uint8_t {
                Update,
                Broken,
                Final,
            };

            SslSha256 sha256;
            uint8_t array[digest_len];
            Status status = Status::Update;
        };

        using StreamId = ClipboardSideData::StreamId;
        using FileGroupId = ClipboardSideData::FileGroupId;

        struct FileContentsSize
        {
            StreamId stream_id;
            FileGroupId lindex;
        };

        struct FileContentsRange
        {
            StreamId stream_id;
            FileGroupId lindex;
            uint64_t file_offset;
            uint64_t file_size_requested;
            uint64_t file_size;

            FileValidatorId file_validator_id;

            std::unique_ptr<FdxCapture::TflFile> tfl_file;

            Sig sig = Sig();

            bool on_failure = false;
        };

        bool use_long_format_names;
        bool has_current_lock = false;
        // if true, current_lock_id id pushed to lock_list (avoid duplication)
        // TODO enum with has_current_lock
        bool current_lock_id_is_used;
        uint32_t current_lock_id;


        uint32_t current_file_list_format_id;
        Cliprdr::FormatNameInventory current_format_list;

        std::vector<FileValidatorId> clip_text_validator_id_list;
        uint32_t clip_text_locale_identifier = 0;

        std::string validator_target_name;

        StreamId current_file_contents_stream_id;
        bool has_current_file_contents_stream_id;

        StaticOutStream<RDPECLIP::FileDescriptor::size()> file_descriptor_stream;

        std::vector<CliprdFileInfo> files;

        uint32_t requested_format_id;

        enum class TransferState :  uint8_t {
            Empty,
            Size,
            Range,
            WaitingContinuationRange,
            Text,
        };

        TransferState transfer_state = TransferState::Empty;

        struct TextData
        {
            FileValidatorId file_validator_id;
            bool is_unicode;
        };

        union FileContentsData
        {
            char dummy;
            FileContentsSize size;
            FileContentsRange range;
            TextData text;

            FileContentsData() {}
            ~FileContentsData() {}
        };

        FileContentsData file_contents_data;

        struct LockedFileContentsSize
        {
            LockId lock_id;
            FileContentsSize file_contents_size;
        };

        enum LockedTransferState : bool { WaitingResponse, WaitingRequest, };

        struct LockedFileContentsRange
        {
            LockId lock_id;
            LockedTransferState state;
            FileContentsRange file_contents_range;
        };

        std::vector<LockedFileContentsSize> locked_file_contents_sizes;
        std::vector<LockedFileContentsRange> locked_file_contents_ranges;

        struct LockData
        {
            uint32_t lock_id;
            int count_ref;

            std::vector<CliprdFileInfo> files;
        };

        std::vector<LockData> lock_list;

        LockData* search_lock_by_id(LockId lock_id)
        {
            for (auto& r : this->lock_list) {
                if (r.lock_id == lock_id) {
                    return &r;
                }
            }
            return nullptr;
        }

        LockedFileContentsRange* search_range_by_id(StreamId stream_id)
        {
            for (auto& r : this->locked_file_contents_ranges) {
                if (r.file_contents_range.stream_id == stream_id
                 && r.state == LockedTransferState::WaitingResponse) {
                    return &r;
                }
            }
            return nullptr;
        }

        LockedFileContentsRange* search_range_by_validator_id(FileValidatorId id)
        {
            for (auto& r : this->locked_file_contents_ranges) {
                if (r.file_contents_range.file_validator_id == id) {
                    return &r;
                }
            }
            return nullptr;
        }

        void remove_locked_file_contents_range(LockedFileContentsRange* p)
        {
            vector_fast_erase(this->locked_file_contents_ranges, p);
        }

        LockedFileContentsRange* search_range_by_offset(LockId lock_id, uint64_t offset)
        {
            for (auto& r : this->locked_file_contents_ranges) {
                if (r.lock_id == lock_id
                 && r.state == LockedTransferState::WaitingRequest
                 && r.file_contents_range.file_offset == offset
                ) {
                    return &r;
                }
            }
            return nullptr;
        }

        LockedFileContentsSize* search_size_by_id(StreamId stream_id)
        {
            for (auto& r : this->locked_file_contents_sizes) {
                if (r.file_contents_size.stream_id == stream_id) {
                    return &r;
                }
            }
            return nullptr;
        }

        void remove_locked_file_contents_size(LockedFileContentsSize* p)
        {
            vector_fast_erase(this->locked_file_contents_sizes, p);
        }

        bool contains_stream_id(StreamId stream_id)
        {
            return this->search_range_by_id(stream_id)
                || this->search_size_by_id(stream_id);
        }
    };

    struct ClientCtx : ClipCtx {};
    struct ServerCtx : ClipCtx {};
}

struct ClipboardVirtualChannel::D
{
    ClientCtx client;
    ServerCtx server;
    ClipboardVirtualChannel& self;
    // boost::sml::sm<cliprdr_tt> sm{DataCtxRef{data_ctx}};

    struct FileValidatorDataList
    {
        FileValidatorId file_validator_id;
        Direction direction;
        bool on_failure;
        std::unique_ptr<FdxCapture::TflFile> tfl_file;
        std::string file_name;
        ClipCtx::Sig sig;
    };

    std::vector<FileValidatorDataList> file_validator_list;

    struct TextValidatorDataList
    {
        FileValidatorId file_validator_id;
        Direction direction;
    };

    std::vector<TextValidatorDataList> text_validator_list {};

    FileValidatorDataList* search_file_validator_by_id(FileValidatorId id)
    {
        for (auto& r : this->file_validator_list) {
            if (r.file_validator_id == id) {
                return &r;
            }
        }
        return nullptr;
    }

    void remove_file_validator(FileValidatorDataList* p)
    {
        vector_fast_erase(this->file_validator_list, p);
    }

    TextValidatorDataList* search_text_validator_by_id(FileValidatorId id)
    {
        for (auto& r : this->text_validator_list) {
            if (r.file_validator_id == id) {
                return &r;
            }
        }
        return nullptr;
    }

    void remove_text_validator(TextValidatorDataList* p)
    {
        vector_fast_erase(this->text_validator_list, p);
    }

    D(ClipboardVirtualChannel& self)
    : self(self)
    {}

    // ~D()
    // {
    //     TODO remove {client, server}.file_contents_data
    //     and other lists
    // }

    bool format_list(
        uint32_t flags, RDPECLIP::CliprdrHeader const& in_header,
        VirtualChannelDataSender* sender, bool clip_enabled,
        ClipCtx& clip, bytes_view chunk_data)
    {
        // TODO fix that
        if (!(flags & CHANNELS::CHANNEL_FLAG_LAST)) {
            LOG(LOG_ERR, "Format List PDU is not yet supported!");
            FormatListSendBack pdu(sender);
            return false;
        }

        clip.current_format_list.clear();

        // TODO
        if (!clip_enabled || clip.transfer_state != ClipCtx::TransferState::Empty) {
            LOG(LOG_WARNING, "Clipboard is fully disabled.");
            FormatListSendBack pdu(sender);
            return false;
        }

        InStream in_stream(chunk_data);
        FormatListReceive receiver(
            clip.use_long_format_names,
            in_header,
            in_stream,
            clip.current_format_list,
            self.verbose);

        clip.current_file_list_format_id = receiver.file_list_format_id;
        clip.has_current_lock = false;
        clip.files.clear();
        // clip.transfer_state = ClipCtx::TransferState::Empty;

        return true;
    }

    void format_list_response(ClipCtx& /*clip*/)
    {
        // TODO check error
    }

    void lock(ClipCtx& clip, bytes_view chunk_data)
    {
        RDPECLIP::LockClipboardDataPDU pdu;
        InStream in_stream(chunk_data);
        pdu.recv(in_stream);

        if (bool(this->self.verbose & RDPVerbose::cliprdr)) {
            pdu.log();
        }

        clip.has_current_lock = true;
        clip.current_lock_id = pdu.clipDataId;
        clip.current_lock_id_is_used = false;
    }

    void unlock(ClipCtx& clip, bytes_view chunk_data)
    {
        RDPECLIP::UnlockClipboardDataPDU pdu;
        InStream in_stream(chunk_data);
        pdu.recv(in_stream);

        if (bool(this->self.verbose & RDPVerbose::cliprdr)) {
            pdu.log();
        }

        if (clip.has_current_lock && clip.current_lock_id == pdu.clipDataId) {
            clip.has_current_lock = false;
        }
        else {
            auto p = std::find_if(
                clip.lock_list.begin(), clip.lock_list.end(),
                [&](ClipCtx::LockData const& l){ return l.lock_id == pdu.clipDataId; });

            if (p == clip.lock_list.end()) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_unlock_pdu:"
                    " unknown clipDataId (%u)", pdu.clipDataId);
                throw Error(ERR_RDP_PROTOCOL);
            }

            if (p->count_ref != 1) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_unlock_pdu:"
                    " Unsupported unlock with transfer");
                throw Error(ERR_RDP_UNSUPPORTED);
            }

            *p = std::move(clip.lock_list.back());
            clip.lock_list.pop_back();
        }
    }

    void format_data_request(ClipCtx& clip, bytes_view chunk_data)
    {
        RDPECLIP::FormatDataRequestPDU pdu;
        InStream in_stream(chunk_data);
        pdu.recv(in_stream);
        clip.requested_format_id = pdu.requestedFormatId;

        if (bool(this->self.verbose & RDPVerbose::cliprdr)) {
            pdu.log();
        }
    }

    void format_data_response(
        RDPECLIP::CliprdrHeader const& in_header,
        ClipCtx& clip, uint32_t flags, bytes_view chunk_data)
    {
        // TODO reset other fields

        // TODO check flags: start / done / wait, exception file_contents_* ?

        bool is_client_to_server = (&clip == &this->server);

        auto& current_format_list = is_client_to_server
            ? this->client.current_format_list
            : this->server.current_format_list;

        if (flags & CHANNELS::CHANNEL_FLAG_FIRST) {
            clip.files.clear();
        }

        if (clip.current_file_list_format_id
         && clip.current_file_list_format_id == clip.requested_format_id
        ) {
            InStream in_stream(chunk_data);
            FormatDataResponseReceiveFileList receiver(
                clip.files,
                in_stream,
                in_header,
                this->self.params.dont_log_data_into_syslog,
                clip.current_file_list_format_id,
                flags,
                clip.file_descriptor_stream,
                this->self.verbose,
                is_client_to_server ? "client" : "server"
            );

            if (bool(flags & CHANNELS::CHANNEL_FLAG_LAST)
             && clip.has_current_lock
             && not clip.current_lock_id_is_used
            ) {
                clip.lock_list.push_back(ClipCtx::LockData{
                    clip.lock_list.back().lock_id, 1, std::move(clip.files)});
                clip.current_lock_id_is_used = true;
            }

            this->log_siem_info(
                current_format_list, flags, in_header, true, clip.requested_format_id,
                LogSiemDataType::NoData, bytes_view{}, is_client_to_server);
        }
        else {
            std::string const& target_name = is_client_to_server
                ? this->self.params.validator_params.up_target_name
                : this->self.params.validator_params.down_target_name;

            if (!target_name.empty()) {
                switch (clip.requested_format_id) {
                    case RDPECLIP::CF_TEXT:
                    case RDPECLIP::CF_UNICODETEXT: {
                        if (flags & CHANNELS::CHANNEL_FLAG_FIRST) {
                            switch (clip.transfer_state)
                            {
                                case ClipCtx::TransferState::WaitingContinuationRange:
                                    // TODO move to file_validator_list
                                    clip.file_contents_data.range.~FileContentsRange();
                                    clip.transfer_state = ClipCtx::TransferState::Empty;
                                    [[fallthrough]];
                                case ClipCtx::TransferState::Empty:
                                    new (&clip.file_contents_data.text) ClipCtx::TextData{
                                        this->self.file_validator->open_text(
                                            RDPECLIP::CF_TEXT == clip.requested_format_id
                                                ? 0u : clip.clip_text_locale_identifier,
                                            target_name),
                                        RDPECLIP::CF_UNICODETEXT == clip.requested_format_id
                                    };
                                    clip.transfer_state = ClipCtx::TransferState::Text;
                                    break;
                                case ClipCtx::TransferState::Size:
                                case ClipCtx::TransferState::Range:
                                case ClipCtx::TransferState::Text:
                                    LOG(LOG_ERR, "ClipboardVirtualChannel::process_format_data_response_pdu:"
                                        " invalid state");
                                    throw Error(ERR_RDP_PROTOCOL);
                            }
                        }
                        InStream in_stream(chunk_data);
                        uint8_t utf8_buf[32*1024];
                        auto utf8_av = UTF16toUTF8_buf(
                            in_stream.remaining_bytes(), make_array_view(utf8_buf));

                        if (flags & CHANNELS::CHANNEL_FLAG_LAST) {
                            if (not utf8_av.empty() && utf8_av.back() == '\0') {
                                utf8_av = utf8_av.drop_back(1);
                            }
                        }

                        if (clip.requested_format_id == RDPECLIP::CF_UNICODETEXT) {
                            this->log_siem_info(
                                current_format_list, flags, in_header, false, clip.requested_format_id,
                                LogSiemDataType::Utf8, utf8_av, not is_client_to_server);
                        }

                        if (clip.transfer_state == ClipCtx::TransferState::Text) {
                            this->self.file_validator->send_data(
                                clip.file_contents_data.text.file_validator_id, utf8_av);

                            if (flags & CHANNELS::CHANNEL_FLAG_LAST) {
                                this->self.file_validator->send_eof(
                                    clip.file_contents_data.text.file_validator_id);
                                this->text_validator_list.push_back({
                                    clip.file_contents_data.text.file_validator_id,
                                    (&clip == &this->server)
                                        ? Direction::FileFromClient
                                        : Direction::FileFromServer,
                                });
                                clip.file_contents_data.text.~TextData();
                                clip.transfer_state = ClipCtx::TransferState::Empty;
                            }
                        }

                        break;
                    }
                    case RDPECLIP::CF_LOCALE: {
                        if (flags & CHANNELS::CHANNEL_FLAG_LAST && chunk_data.size() >= 4) {
                            this->log_siem_info(
                                current_format_list, flags, in_header, false, clip.requested_format_id,
                                LogSiemDataType::FormatData, chunk_data,
                                not is_client_to_server);
                            InStream in_stream(chunk_data);
                            clip.clip_text_locale_identifier = in_stream.in_uint32_le();
                        }
                        else {
                            LOG(LOG_ERR, "ClipboardVirtualChannel::format_data_response:"
                                " CF_LOCALE invalid format");
                            throw Error(ERR_RDP_PROTOCOL);
                        }
                        break;
                    }
                    default:
                        this->log_siem_info(
                            current_format_list, flags, in_header, false, clip.requested_format_id,
                            LogSiemDataType::NoData, {}, not is_client_to_server);
                        break;
                }
            }
            else {
                this->log_siem_info(
                    current_format_list, flags, in_header, false, clip.requested_format_id,
                    LogSiemDataType::FormatData, chunk_data, not is_client_to_server);
            }
        }

        if (flags & CHANNELS::CHANNEL_FLAG_LAST) {
            clip.requested_format_id = 0;
        }
    }

    bool filecontents_request(
        ClipCtx& clip, uint32_t flags, bytes_view chunk_data,
        VirtualChannelDataSender* sender)
    {
        InStream in_stream(chunk_data);
        RDPECLIP::FileContentsRequestPDU file_contents_request_pdu;
        file_contents_request_pdu.receive(in_stream);

        if (bool(self.verbose & RDPVerbose::cliprdr)) {
            file_contents_request_pdu.log(LOG_INFO);
        }

        auto const first_and_last = CHANNELS::CHANNEL_FLAG_FIRST | CHANNELS::CHANNEL_FLAG_LAST;

        if ((flags & first_and_last) != first_and_last) {
            LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu: Unsupported partial packet");
            throw Error(ERR_RDP_UNSUPPORTED);
        }

        if (!this->self.params.clipboard_file_authorized) {
            FilecontentsRequestSendBack(
                file_contents_request_pdu.dwFlags(),
                file_contents_request_pdu.streamId(),
                sender);
            return false;
        }

        const auto lindex = file_contents_request_pdu.lindex();
        const auto stream_id = StreamId(file_contents_request_pdu.streamId());
        const auto ifile = FileGroupId(lindex);

        auto update_continuation_range = [&](ClipCtx::FileContentsRange& rng){
            if (rng.file_offset != file_contents_request_pdu.position()) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                    " Unsupported random access for a FILECONTENTS_RANGE");
                throw Error(ERR_RDP_UNSUPPORTED);
            }
            rng.stream_id = stream_id;
            rng.file_size_requested = file_contents_request_pdu.cbRequested();
        };

        auto new_range = [&](std::vector<CliprdFileInfo> const& files){
            FileValidatorId file_validator_id{};
            if (!clip.validator_target_name.empty()) {
                LOG_IF(bool(this->self.verbose & RDPVerbose::cliprdr), LOG_INFO,
                    "ClipboardVirtualChannel::Validator::open_file");
                file_validator_id = this->self.file_validator->open_file(
                    files[lindex].file_name, clip.validator_target_name);
            }

            return ClipCtx::FileContentsRange{
                stream_id,
                ifile,
                0,
                file_contents_request_pdu.cbRequested(),
                files[lindex].file_size,
                file_validator_id,
                this->self.fdx_capture
                    ? std::unique_ptr<FdxCapture::TflFile>(new FdxCapture::TflFile(
                        this->self.fdx_capture->new_tfl((&clip == &this->server)
                            ? Mwrm3::Direction::ServerToClient
                            : Mwrm3::Direction::ClientToServer
                    )))
                    : std::unique_ptr<FdxCapture::TflFile>()
            };
        };

        if (not file_contents_request_pdu.has_optional_clipDataId()) {
            if (lindex >= clip.files.size()) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                    " Invalid lindex %u", lindex);
                throw Error(ERR_RDP_PROTOCOL);
            }

            switch (clip.transfer_state)
            {
                case ClipCtx::TransferState::WaitingContinuationRange:
                    if (file_contents_request_pdu.dwFlags() == RDPECLIP::FILECONTENTS_RANGE
                     && file_contents_request_pdu.position() != 0
                    ) {
                        update_continuation_range(clip.file_contents_data.range);
                        break;
                    }
                    else {
                        clip.file_contents_data.range.~FileContentsRange();
                        clip.transfer_state = ClipCtx::TransferState::Empty;
                        [[fallthrough]];
                    }
                case ClipCtx::TransferState::Empty:
                    if (file_contents_request_pdu.dwFlags() == RDPECLIP::FILECONTENTS_RANGE) {
                        if (file_contents_request_pdu.position() != 0) {
                            LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                                " Unsupported random access for a FILECONTENTS_RANGE");
                            throw Error(ERR_RDP_UNSUPPORTED);
                        }
                        new (&clip.file_contents_data.range) ClipCtx::FileContentsRange{
                            new_range(clip.files)};
                        clip.transfer_state = ClipCtx::TransferState::Range;
                    }
                    else {
                        new (&clip.file_contents_data.size) ClipCtx::FileContentsSize{
                            stream_id, ifile
                        };
                        clip.transfer_state = ClipCtx::TransferState::Size;
                    }
                    break;
                case ClipCtx::TransferState::Size:
                case ClipCtx::TransferState::Range:
                case ClipCtx::TransferState::Text:
                    LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                        " double request");
                    throw Error(ERR_RDP_PROTOCOL);
            }
        }
        else {
            const auto lock_id = LockId(file_contents_request_pdu.clipDataId());

            auto* lock_data = clip.search_lock_by_id(lock_id);

            if (not lock_data) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                    " unknown clipDataId (%u)", lock_id);
                throw Error(ERR_RDP_PROTOCOL);
            }

            if (lindex >= lock_data->files.size()) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                    " Invalid lindex %u", lindex);
                throw Error(ERR_RDP_PROTOCOL);
            }

            if (clip.contains_stream_id(stream_id)) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_request_pdu:"
                    " streamId already used (%u)", stream_id);
                throw Error(ERR_RDP_PROTOCOL);
            }

            if (file_contents_request_pdu.dwFlags() == RDPECLIP::FILECONTENTS_RANGE) {
                auto* r = clip.search_range_by_offset(
                    lock_id, file_contents_request_pdu.position());
                if (r) {
                    update_continuation_range(r->file_contents_range);
                }
                else {
                    clip.locked_file_contents_ranges.emplace_back(
                        ClipCtx::LockedFileContentsRange{
                            lock_id, ClipCtx::LockedTransferState::WaitingResponse,
                            new_range(lock_data->files)});
                    ++lock_data->count_ref;
                }
            }
            else {
                clip.locked_file_contents_sizes.push_back(
                    {lock_id, {stream_id, ifile}});
                ++lock_data->count_ref;
            }
        }

        return true;
    }

    void filecontents_response(
        RDPECLIP::CliprdrHeader const& in_header,
        ClipCtx& clip, uint32_t flags, bytes_view chunk_data)
    {
        InStream in_stream(chunk_data);

        // TODO check first / cont / last status (otherwise, invalid current_file_contents_stream_id)

        if (flags & CHANNELS::CHANNEL_FLAG_FIRST) {
            ::check_throw(in_stream, 4, "FileContentsResponse::receive", ERR_RDP_DATA_TRUNCATED);
            if (clip.has_current_file_contents_stream_id) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_response_pdu:"
                    " streamId already defined");
                throw Error(ERR_RDP_PROTOCOL);
            }
            clip.current_file_contents_stream_id = safe_int(in_stream.in_uint32_le());
            clip.has_current_file_contents_stream_id = true;
            LOG_IF(bool(this->self.verbose & RDPVerbose::cliprdr), LOG_INFO,
                "File Contents Response: streamId=%u", clip.current_file_contents_stream_id);
        }
        else if (not clip.has_current_file_contents_stream_id) {
            LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_response_pdu:"
                " unknown streamId");
            throw Error(ERR_RDP_PROTOCOL);
        }

        auto const stream_id = clip.current_file_contents_stream_id;

        auto update_file_size_or_throw = [&in_header](
            std::vector<CliprdFileInfo>& files,
            ClipCtx::FileContentsSize& file_contents_size,
            uint32_t flags, bytes_view chunk_data
        ){
            if (!(flags & CHANNELS::CHANNEL_FLAG_LAST)) {
                LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_response_pdu:"
                    " Unsupported partial FILECONTENTS_SIZE packet");
                throw Error(ERR_RDP_UNSUPPORTED);
            }

            if (in_header.msgFlags() != RDPECLIP::CB_RESPONSE_OK) {
                return false;
            }

            InStream in_stream(chunk_data);
            check_throw(in_stream, 8, "process_filecontents_response_pdu", ERR_RDP_DATA_TRUNCATED);
            files[size_t(file_contents_size.lindex)].file_size = in_stream.in_uint64_le();

            return true;
        };

        auto update_file_range_data = [](
            ClipCtx::FileContentsRange& file_contents_range,
            bytes_view data
        ){
            if (data.size() >= file_contents_range.file_size_requested) {
                data = data.first(file_contents_range.file_size_requested);
            }

            file_contents_range.sig.update(data);
            file_contents_range.file_offset += data.size();
            file_contents_range.file_size_requested -= data.size();

            if (bool(file_contents_range.tfl_file)) {
                file_contents_range.tfl_file->trans.send(data);
            }
        };

        auto finalize_transfer = [this, &clip](
            std::vector<CliprdFileInfo>& files,
            ClipCtx::FileContentsRange& file_contents_range
        ){
            clip.has_current_file_contents_stream_id = false;

            if (file_contents_range.file_offset < file_contents_range.file_size) {
                // TODO disable file_contents_range
                return false;
            }

            this->log_file_info(files, file_contents_range, (&clip == &this->server));

            if (bool(file_contents_range.file_validator_id)) {
                file_contents_range.sig.final();
                this->self.file_validator->send_eof(file_contents_range.file_validator_id);
                this->file_validator_list.push_back({
                    file_contents_range.file_validator_id,
                    (&clip == &this->server)
                        ? Direction::FileFromClient
                        : Direction::FileFromServer,
                    file_contents_range.on_failure,
                    std::move(file_contents_range.tfl_file),
                    files[size_t(file_contents_range.lindex)].file_name,
                    file_contents_range.sig
                });
            }
            else if (file_contents_range.tfl_file) {
                file_contents_range.sig.final();
                if (this->self.always_file_storage || file_contents_range.on_failure) {
                    this->self.fdx_capture->close_tfl(
                        *file_contents_range.tfl_file,
                        files[size_t(file_contents_range.lindex)].file_name,
                        Mwrm3::TransferedStatus::Completed,
                        Mwrm3::Sha256Signature{file_contents_range.sig.digest_as_av()});
                }
                else {
                    this->self.fdx_capture->cancel_tfl(*file_contents_range.tfl_file);
                }
                file_contents_range.tfl_file.reset();
            }

            return true;
        };

        switch (clip.transfer_state)
        {
        case ClipCtx::TransferState::Text:
        case ClipCtx::TransferState::Empty:
            LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_response_pdu:"
                " invalid state");
            throw Error(ERR_RDP_PROTOCOL);
        case ClipCtx::TransferState::Size:
            // TODO check flag = last
            if (clip.file_contents_data.size.stream_id == stream_id) {
                update_file_size_or_throw(
                    clip.files, clip.file_contents_data.size, flags, chunk_data);
                clip.transfer_state = ClipCtx::TransferState::Empty;
                clip.file_contents_data.size.~FileContentsSize();
                clip.has_current_file_contents_stream_id = false;
                return ;
            }
            break;
        case ClipCtx::TransferState::Range:
            if (clip.file_contents_data.range.stream_id == stream_id) {
                if (in_header.msgFlags() == RDPECLIP::CB_RESPONSE_OK) {
                    auto& rng = clip.file_contents_data.range;
                    update_file_range_data(rng, chunk_data);
                    if (bool(flags & CHANNELS::CHANNEL_FLAG_LAST)) {
                        finalize_transfer(clip.files, rng);
                        clip.transfer_state = ClipCtx::TransferState::Empty;
                        clip.file_contents_data.range.~FileContentsRange();
                    }
                }
                else {
                    auto& rng = clip.file_contents_data.range;
                    clip.has_current_file_contents_stream_id = false;
                    rng.sig.final();
                    if (finalize_transfer(clip.files, rng)) {
                        clip.file_contents_data.range.~FileContentsRange();
                        clip.transfer_state = ClipCtx::TransferState::Empty;
                    }
                    else {
                        clip.transfer_state = ClipCtx::TransferState::WaitingContinuationRange;
                    }
                }
                return ;
            }
            break;
        case ClipCtx::TransferState::WaitingContinuationRange:
            if (clip.file_contents_data.range.stream_id == stream_id) {
                auto& rng = clip.file_contents_data.range;
                update_file_range_data(rng, chunk_data);
                if (bool(flags & CHANNELS::CHANNEL_FLAG_LAST)) {
                    finalize_transfer(clip.files, rng);
                    clip.transfer_state = ClipCtx::TransferState::Empty;
                    clip.file_contents_data.range.~FileContentsRange();
                }
            }
            break;
        }

        if (auto* locked_contents_range = clip.search_range_by_id(stream_id)) {
            auto& rng = locked_contents_range->file_contents_range;

            if (in_header.msgFlags() == RDPECLIP::CB_RESPONSE_FAIL) {
                not_null_ptr lock_data = clip.search_lock_by_id(locked_contents_range->lock_id);
                --lock_data->count_ref;
                clip.has_current_file_contents_stream_id = false;
                rng.sig.final();
                finalize_transfer(lock_data->files, rng);
                clip.remove_locked_file_contents_range(locked_contents_range);
            }
            else {
                update_file_range_data(rng, chunk_data);

                if (flags & CHANNELS::CHANNEL_FLAG_LAST) {
                    not_null_ptr lock_data = clip.search_lock_by_id(locked_contents_range->lock_id);
                    clip.has_current_file_contents_stream_id = false;

                    finalize_transfer(lock_data->files, rng);
                    clip.remove_locked_file_contents_range(locked_contents_range);

                    --lock_data->count_ref;
                }
            }
        }
        else if (auto* locked_contents_size = clip.search_size_by_id(stream_id)) {
            not_null_ptr lock_data = clip.search_lock_by_id(locked_contents_size->lock_id);
            update_file_size_or_throw(
                lock_data->files, locked_contents_size->file_contents_size,
                flags, chunk_data);
            clip.remove_locked_file_contents_size(locked_contents_size);
            --lock_data->count_ref;
        }
        else {
            LOG(LOG_ERR, "ClipboardVirtualChannel::process_filecontents_response_pdu:"
                " streamId not found");
            throw Error(ERR_RDP_PROTOCOL);
        }
    }

    void log_file_info(
        std::vector<CliprdFileInfo>& files,
        ClipCtx::FileContentsRange& file_contents_range,
        bool from_remote_session)
    {
        const char* type = (
            from_remote_session
                ? "CB_COPYING_PASTING_FILE_FROM_REMOTE_SESSION"
                : "CB_COPYING_PASTING_FILE_TO_REMOTE_SESSION"
        );

        if (!file_contents_range.sig.has_digest()) {
            file_contents_range.sig.broken();
        }

        static_assert(SslSha256::DIGEST_LENGTH == decltype(file_contents_range.sig)::digest_len);
        auto& digest = file_contents_range.sig.digest();
        char digest_s[128];
        size_t digest_s_len = snprintf(digest_s, sizeof(digest_s),
            "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
            "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            digest[ 0], digest[ 1], digest[ 2], digest[ 3], digest[ 4], digest[ 5], digest[ 6], digest[ 7],
            digest[ 8], digest[ 9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15],
            digest[16], digest[17], digest[18], digest[19], digest[20], digest[21], digest[22], digest[23],
            digest[24], digest[25], digest[26], digest[27], digest[28], digest[29], digest[30], digest[31]);

        char file_size[128];
        size_t file_size_len = std::snprintf(file_size, std::size(file_size), "%lu", file_contents_range.file_size);

        std::string_view file_name = files[size_t(file_contents_range.lindex)].file_name;
        this->self.report_message.log6(
            from_remote_session
                ? LogId::CB_COPYING_PASTING_FILE_FROM_REMOTE_SESSION
                : LogId::CB_COPYING_PASTING_FILE_TO_REMOTE_SESSION,
            this->self.session_reactor.get_current_time(), {
            KVLog("file_name"_av, file_name),
            KVLog("size"_av, {file_size, file_size_len}),
            KVLog("sha256"_av, {digest_s, digest_s_len}),
        });

        LOG_IF(!this->self.params.dont_log_data_into_syslog, LOG_INFO,
            "type=%s file_name=%.*s size=%s sha256=%s",
            type, int(file_name.size()), file_name.data(), file_size, digest_s);
    }

    enum class LogSiemDataType : int8_t { NoData, FormatData, Utf8, };

    void log_siem_info(
        Cliprdr::FormatNameInventory const& current_format_list, uint32_t flags, const RDPECLIP::CliprdrHeader & in_header, bool is_file_group_id,
        const uint32_t requestedFormatId, LogSiemDataType data_type, bytes_view data_to_dump,
        const bool is_from_remote_session
    ) {
        if (bool(flags & CHANNELS::CHANNEL_FLAG_FIRST)
         && in_header.msgFlags() & RDPECLIP::CB_RESPONSE_OK
        ) {
            auto* format_name = current_format_list.find(requestedFormatId);
            auto utf8_format = (format_name && !format_name->utf8_name().empty())
                ? format_name->utf8_name()
                : RDPECLIP::get_FormatId_name_av(requestedFormatId);

            bool const log_current_activity = (
                !this->self.params.log_only_relevant_clipboard_activities
                || !format_name
                || (!is_file_group_id
                && !ranges_equal(utf8_format,
                    Cliprdr::formats::preferred_drop_effect.ascii_name)
            ));

            if (this->self.params.dont_log_data_into_syslog && not log_current_activity) {
                return ;
            }

            char format_buf[255];
            int format_len = std::sprintf(format_buf, "%.*s(%u)",
                int(utf8_format.size()), utf8_format.as_charp(), requestedFormatId);
            array_view format_av{format_buf, checked_cast<std::size_t>(format_len)};

            char size_buf[32];
            int size_len = std::sprintf(size_buf, "%u", in_header.dataLen());
            array_view size_av{size_buf, checked_cast<std::size_t>(size_len)};

            constexpr size_t max_length_of_data_to_dump = 256;
            char data_to_dump_buf[
                max_length_of_data_to_dump * maximum_length_of_utf8_character_in_bytes];
            std::string_view utf8_string{};
            switch (data_type)
            {
                case LogSiemDataType::NoData:
                    break;
                case LogSiemDataType::FormatData:
                    switch (requestedFormatId) {
                        /*
                        case RDPECLIP::CF_TEXT:
                        {
                            const size_t length_of_data_to_dump = std::min(
                                chunk.in_remain(), max_length_of_data_to_dump);
                            data_to_dump.assign(
                                ::char_ptr_cast(chunk.get_current()),
                                length_of_data_to_dump);
                        }
                        break;
                        */
                        case RDPECLIP::CF_UNICODETEXT:
                        {
                            assert(!(data_to_dump.size() & 1));

                            const size_t length_of_data_to_dump = std::min(
                                data_to_dump.size(), max_length_of_data_to_dump * 2);

                            auto av = ::UTF16toUTF8_buf(
                                {data_to_dump.data(), length_of_data_to_dump / 2u},
                                make_array_view(data_to_dump_buf));
                            utf8_string = {av.as_charp(), av.size()};
                            if (not utf8_string.empty() && not utf8_string.back()) {
                                utf8_string.remove_suffix(1);
                            }
                        }
                        break;

                        case RDPECLIP::CF_LOCALE:
                            if (data_to_dump.size() >= 4) {
                                InStream in_stream(data_to_dump);
                                int len = std::sprintf(data_to_dump_buf,
                                    "%u", in_stream.in_uint32_le());
                                utf8_string = {data_to_dump_buf, checked_cast<std::size_t>(len)};
                            }
                        break;
                    }
                    break;
                case LogSiemDataType::Utf8:
                    utf8_string = {
                        data_to_dump.as_charp(),
                        std::min(data_to_dump.size(), max_length_of_data_to_dump)
                    };
                    break;
            }

            if (log_current_activity) {
                if (utf8_string.empty()) {
                    this->self.report_message.log6(is_from_remote_session
                        ? LogId::CB_COPYING_PASTING_DATA_FROM_REMOTE_SESSION
                        : LogId::CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION,
                        this->self.session_reactor.get_current_time(), {
                        KVLog("format"_av, format_av),
                        KVLog("size"_av, size_av),
                    });
                }
                else {
                    this->self.report_message.log6(is_from_remote_session
                        ? LogId::CB_COPYING_PASTING_DATA_FROM_REMOTE_SESSION_EX
                        : LogId::CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION_EX,
                        this->self.session_reactor.get_current_time(), {
                        KVLog("format"_av, format_av),
                        KVLog("size"_av, size_av),
                        KVLog("partial_data"_av, utf8_string),
                    });
                }
            }

            if (not this->self.params.dont_log_data_into_syslog) {
                const auto type = (is_from_remote_session)
                    ? (utf8_string.empty()
                        ? "CB_COPYING_PASTING_DATA_FROM_REMOTE_SESSION"_av
                        : "CB_COPYING_PASTING_DATA_FROM_REMOTE_SESSION_EX"_av)
                    : (utf8_string.empty()
                        ? "CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION"_av
                        : "CB_COPYING_PASTING_DATA_TO_REMOTE_SESSION_EX"_av);

                LOG(LOG_INFO,
                    "type=%s format=%.*s size=%.*s %s%.*s",
                    type.data(),
                    int(format_av.size()), format_av.data(),
                    int(size_av.size()), size_av.data(),
                    utf8_string.empty() ? "" : " partial_data",
                    int(utf8_string.size()), utf8_string.data());
            }
        }
    }

    void DLP_antivirus_check_channels_files()
    {
        if (!this->self.file_validator) {
            return ;
        }

        auto receive_data = [this]{
            for (;;) {
                switch (this->self.file_validator->receive_response()) {
                    case FileValidatorService::ResponseType::WaitingData:
                        return false;
                    case FileValidatorService::ResponseType::HasContent:
                        return true;
                    case FileValidatorService::ResponseType::Error:
                        ;
                }
            }
        };

        using ValidationResult = LocalFileValidatorProtocol::ValidationResult;

        while (receive_data()){
            bool is_accepted = false;
            switch (this->self.file_validator->last_result_flag()) {
                case ValidationResult::Wait:
                    return;
                case ValidationResult::IsAccepted:
                    is_accepted = true;
                    [[fallthrough]];
                case ValidationResult::IsRejected:
                case ValidationResult::Error:
                    ;
            }

            auto file_validator_id = this->self.file_validator->last_file_id();
            auto& result_content = this->self.file_validator->get_content();

            auto process_text = [&](Direction direction){
                auto str_direction = (direction == Direction::FileFromClient)
                    ? "UP"_av
                    : "DOWN"_av;

                if (!is_accepted || this->self.params.validator_params.log_if_accepted) {
                    char buf[24];
                    unsigned n = std::snprintf(buf, std::size(buf), "%" PRIu32,
                        underlying_cast(file_validator_id));
                    this->self.report_message.log6(LogId::TEXT_VERIFICATION,
                        this->self.session_reactor.get_current_time(), {
                        KVLog("direction"_av, str_direction),
                        KVLog("copy_id"_av, {buf, n}),
                        KVLog("status"_av, result_content),
                    });
                }
            };

            auto process_file = [&](Direction direction, std::string_view file_name){
                auto str_direction = (direction == Direction::FileFromClient)
                    ? "UP"_av
                    : "DOWN"_av;

                if (!is_accepted || this->self.params.validator_params.log_if_accepted) {
                    this->self.report_message.log6(LogId::FILE_VERIFICATION,
                        this->self.session_reactor.get_current_time(), {
                        KVLog("direction"_av, str_direction),
                        KVLog("file_name"_av, file_name),
                        KVLog("status"_av, result_content),
                    });
                }
            };

            if (auto* text_validator_data = this->search_text_validator_by_id(file_validator_id)) {
                process_text(text_validator_data->direction);
                text_validator_data->file_validator_id = FileValidatorId();
                this->remove_text_validator(text_validator_data);
            }
            else if (auto* file_validator_data = this->search_file_validator_by_id(file_validator_id)) {
                process_file(file_validator_data->direction, file_validator_data->file_name);

                if (file_validator_data->tfl_file) {
                    if (this->self.always_file_storage
                     || this->self.file_validator->last_result_flag() != ValidationResult::IsAccepted
                    ) {
                        auto status = Mwrm3::TransferedStatus::Completed;
                        if (!file_validator_data->sig.has_digest()) {
                            file_validator_data->sig.broken();
                            status = Mwrm3::TransferedStatus::Broken;
                        }
                        this->self.fdx_capture->close_tfl(
                            *file_validator_data->tfl_file,
                            file_validator_data->file_name,
                            status, Mwrm3::Sha256Signature{
                                file_validator_data->sig.digest_as_av()
                            });
                    }
                    else {
                        this->self.fdx_capture->cancel_tfl(*file_validator_data->tfl_file);
                    }
                    file_validator_data->tfl_file.reset();
                }

                this->remove_file_validator(file_validator_data);
            }
            else {
                auto process_clip = [&](ClipCtx& clip){
                    switch (clip.transfer_state)
                    {
                    case ClipCtx::TransferState::Empty:
                    case ClipCtx::TransferState::Size:
                        break;

                    case ClipCtx::TransferState::Text:
                        if (clip.file_contents_data.text.file_validator_id == file_validator_id) {
                            process_text((&clip == &this->server)
                                ? Direction::FileFromClient
                                : Direction::FileFromServer);
                            clip.file_contents_data.text.~TextData();
                            clip.transfer_state = ClipCtx::TransferState::Empty;
                            return true;
                        }
                        break;

                    case ClipCtx::TransferState::Range:
                    case ClipCtx::TransferState::WaitingContinuationRange:
                        if (clip.file_contents_data.range.file_validator_id == file_validator_id) {
                            auto& rng = clip.file_contents_data.range;
                            process_file(
                                (&clip == &this->server)
                                    ? Direction::FileFromClient
                                    : Direction::FileFromServer,
                                clip.files[size_t(rng.lindex)].file_name);
                            rng.on_failure
                                = this->self.file_validator->last_result_flag() != ValidationResult::IsAccepted;
                            rng.file_validator_id = FileValidatorId();
                            return true;
                        }
                        break;
                    }

                    if (auto* r = clip.search_range_by_validator_id(file_validator_id)) {
                        not_null_ptr lock_data = clip.search_lock_by_id(r->lock_id);
                        process_file(
                            Direction::FileFromServer,
                            lock_data->files[size_t(r->file_contents_range.lindex)].file_name);
                        r->file_contents_range.file_validator_id = FileValidatorId();
                        return true;
                    }

                    return false;
                };

                if (not process_clip(this->client) && not process_clip(this->server)) {
                    LOG(LOG_ERR, "ClipboardVirtualChannel::DLP_antivirus_check_channels_files:"
                        " unknown validatorId(%u)", file_validator_id);
                }
            }
        }
    }
};

ClipboardVirtualChannel::ClipboardVirtualChannel(
    VirtualChannelDataSender* to_client_sender_,
    VirtualChannelDataSender* to_server_sender_,
    SessionReactor& session_reactor,
    const BaseVirtualChannel::Params & base_params,
    const ClipboardVirtualChannelParams & params,
    FileValidatorService * file_validator_service,
    FileStorage file_storage)
: BaseVirtualChannel(to_client_sender_,
                        to_server_sender_,
                        base_params)
, params([&]{
    auto p = params;
    if (!file_validator_service) {
        p.validator_params.up_target_name.clear();
        p.validator_params.down_target_name.clear();
    }
    return p;
}())
, proxy_managed(to_client_sender_ == nullptr)
, session_reactor(session_reactor)
, file_validator(file_validator_service)
, fdx_capture(file_storage.fdx_capture)
, always_file_storage(file_storage.always_file_storage)
{
    this->d.reset(new D{*this});
}

ClipboardVirtualChannel::~ClipboardVirtualChannel()
{
    // TODO close tfl
    try {
        for (ClipboardSideData* side_data : {
            &this->clip_data.client_data,
            &this->clip_data.server_data
        }) {
            for (auto& file : side_data->get_file_contents_list()) {
                auto& file_data = file.file_data;
                if (file_data.tfl_file) {
                    if (file_data.tfl_file->trans.is_open()) {
                        // TODO close tfl
                        // this->_close_tfl(file_data);
                    }
                }
            }
        }
    }
    catch (Error const& err) {
        LOG(LOG_ERR, "ClipboardVirtualChannel: error on close tfls: %s", err.errmsg());
    }
}

void ClipboardVirtualChannel::process_server_message(
    uint32_t total_length, uint32_t flags, bytes_view chunk_data,
    std::unique_ptr<AsynchronousTask> & out_asynchronous_task)
{
    (void)out_asynchronous_task;

    this->log_process_message(total_length, flags, chunk_data, Direction::FileFromServer);

    InStream chunk(chunk_data);
    RDPECLIP::CliprdrHeader header;
    bool send_message_to_client = true;

    switch (this->process_header_message(
        this->clip_data.server_data, flags, chunk, header, Direction::FileFromServer
    ))
    {
        case RDPECLIP::CB_MONITOR_READY: {
            // TODO reset clip
            if (this->proxy_managed) {
                this->clip_data.server_data.use_long_format_names = true;
                ServerMonitorReadySendBack sender(this->verbose, this->use_long_format_names(), this->to_server_sender_ptr());
            }

            if (this->clipboard_monitor_ready_notifier) {
                if (!this->clipboard_monitor_ready_notifier->on_clipboard_monitor_ready()) {
                    this->clipboard_monitor_ready_notifier = nullptr;
                }
            }

            send_message_to_client = !this->proxy_managed;
        }
        break;

        case RDPECLIP::CB_FORMAT_LIST: {
            auto pkt_data = chunk.remaining_bytes();
            send_message_to_client = this->d->format_list(
                flags, header, this->to_server_sender_ptr(),
                this->params.clipboard_down_authorized || this->params.clipboard_up_authorized,
                this->d->server,
                pkt_data);

            if (this->format_list_notifier) {
                if (!this->format_list_notifier->on_server_format_list()) {
                    this->format_list_notifier = nullptr;
                }
            }
        }
        break;

        case RDPECLIP::CB_FORMAT_LIST_RESPONSE:
            if (this->clipboard_initialize_notifier) {
                if (!this->clipboard_initialize_notifier->on_clipboard_initialize()) {
                    this->clipboard_initialize_notifier = nullptr;
                }
            }
            else if (this->format_list_response_notifier) {
                if (!this->format_list_response_notifier->on_server_format_list_response()) {
                    this->format_list_response_notifier = nullptr;
                }
            }
            this->d->format_list_response(this->d->client);
        break;

        case RDPECLIP::CB_FORMAT_DATA_REQUEST: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->format_data_request(this->d->server, pkt_data);

            if (this->format_data_request_notifier
             && this->clip_data.requestedFormatId == RDPECLIP::CF_TEXT
            ) {
                if (!this->format_data_request_notifier->on_server_format_data_request()) {
                    this->format_data_request_notifier = nullptr;
                }

                send_message_to_client = false;
            }
            else if (!this->params.clipboard_up_authorized) {
                LOG_IF(bool(this->verbose & RDPVerbose::cliprdr), LOG_INFO,
                    "ClipboardVirtualChannel::process_server_format_data_request_pdu: "
                        "Client to server Clipboard operation is not allowed.");

                FormatDataRequestSendBack sender(this->to_server_sender_ptr());

                send_message_to_client = false;
            }
        }
        break;

        case RDPECLIP::CB_FORMAT_DATA_RESPONSE: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->format_data_response(header, this->d->client, flags, pkt_data);
        }
        break;

        case RDPECLIP::CB_CLIP_CAPS: {
            ClipboardCapabilitiesReceive(this->clip_data.server_data, chunk, this->verbose);
            send_message_to_client = !this->proxy_managed;
            // TODO reset clip
        }
        break;

        case RDPECLIP::CB_FILECONTENTS_REQUEST: {
            auto pkt_data = chunk.remaining_bytes();
            send_message_to_client = this->d->filecontents_request(this->d->server, flags, pkt_data, this->to_server_sender_ptr());
        }
        break;

        case RDPECLIP::CB_FILECONTENTS_RESPONSE: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->filecontents_response(header, this->d->client, flags, pkt_data);
        }
        break;

        case RDPECLIP::CB_LOCK_CLIPDATA: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->lock(this->d->server, pkt_data);
        }
        break;

        case RDPECLIP::CB_UNLOCK_CLIPDATA: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->unlock(this->d->server, pkt_data);
        }
    }   // switch (this->server_message_type)

    if (send_message_to_client) {
        this->send_message_to_client(total_length, flags, chunk_data);
    }   // switch (this->server_message_type)
}

void ClipboardVirtualChannel::process_client_message(
    uint32_t total_length, uint32_t flags, bytes_view chunk_data)
{
    this->log_process_message(total_length, flags, chunk_data, Direction::FileFromClient);

    InStream chunk(chunk_data);
    RDPECLIP::CliprdrHeader header;
    bool send_message_to_server = true;

    switch (this->process_header_message(
        this->clip_data.client_data, flags, chunk, header, Direction::FileFromClient
    ))
    {
        // case RDPECLIP::CB_MONITOR_READY: {
        //     // TODO reset clip
        // }
        case RDPECLIP::CB_FORMAT_LIST: {
            auto pkt_data = chunk.remaining_bytes();
            send_message_to_server = this->d->format_list(
                flags, header, this->to_client_sender_ptr(),
                this->params.clipboard_down_authorized
                || this->params.clipboard_up_authorized
                || this->format_list_response_notifier,
                this->d->client,
                pkt_data);
        }
        break;
        case RDPECLIP::CB_FORMAT_LIST_RESPONSE:
            this->d->format_list_response(this->d->server);
        break;

        case RDPECLIP::CB_FORMAT_DATA_REQUEST: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->format_data_request(this->d->client, pkt_data);
            send_message_to_server = this->params.clipboard_down_authorized;
            if (!this->params.clipboard_down_authorized) {
                LOG_IF(bool(this->verbose & RDPVerbose::cliprdr), LOG_INFO,
                    "ClipboardVirtualChannel::process_client_format_data_request_pdu: "
                        "Server to client Clipboard operation is not allowed.");

                FormatDataRequestSendBack sender(this->to_client_sender_ptr());
            }
        }
        break;

        case RDPECLIP::CB_FORMAT_DATA_RESPONSE: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->format_data_response(header, this->d->server, flags, pkt_data);
        }
        break;

        case RDPECLIP::CB_CLIP_CAPS: {
            ClipboardCapabilitiesReceive(this->clip_data.client_data, chunk, this->verbose);
            send_message_to_server = true;
            // TODO reset clip
        }
        break;

        case RDPECLIP::CB_FILECONTENTS_REQUEST: {
            auto pkt_data = chunk.remaining_bytes();
            send_message_to_server = this->d->filecontents_request(this->d->client, flags, pkt_data, this->to_client_sender_ptr());
        }
        break;

        case RDPECLIP::CB_FILECONTENTS_RESPONSE: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->filecontents_response(header, this->d->server, flags, pkt_data);
        }
        break;

        case RDPECLIP::CB_LOCK_CLIPDATA: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->lock(this->d->client, pkt_data);
        }
        break;

        case RDPECLIP::CB_UNLOCK_CLIPDATA: {
            auto pkt_data = chunk.remaining_bytes();
            this->d->unlock(this->d->client, pkt_data);
        }
        break;
    }   // switch (this->client_message_type)

    if (send_message_to_server) {
        this->send_message_to_server(total_length, flags, chunk_data);
    }
}

void ClipboardVirtualChannel::DLP_antivirus_check_channels_files()
{
    this->d->DLP_antivirus_check_channels_files();
}
