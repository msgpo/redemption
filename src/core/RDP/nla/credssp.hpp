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
    Copyright (C) Wallix 2013
    Author(s): Christophe Grosjean, Raphael Zhou, Meng Tan
*/


#pragma once

#include <cstring>

#include "core/error.hpp"
#include "utils/utf.hpp"
#include "utils/sugar/buf_maker.hpp"
#include "utils/sugar/cast.hpp"
#include "core/RDP/nla/asn1/ber.hpp"
#include "core/RDP/nla/ntlm/ntlm_message.hpp"

enum class PasswordCallback
{
    Error, Ok, Wait
};

namespace credssp {
    enum class State { Err, Cont, Finish, };
}


enum SecIdFlag {
    SEC_WINNT_AUTH_IDENTITY_ANSI = 0x1,
    SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2
};


enum SEC_STATUS {
    SEC_E_OK                   = 0x00000000,
    SEC_E_INSUFFICIENT_MEMORY  = 0x80090300,
    SEC_E_INVALID_HANDLE       = 0x80090301,
    SEC_E_UNSUPPORTED_FUNCTION = 0x80090302,
    SEC_E_TARGET_UNKNOWN       = 0x80090303,
    SEC_E_INTERNAL_ERROR       = 0x80090304,
    SEC_E_SECPKG_NOT_FOUND     = 0x80090305,
    SEC_E_NOT_OWNER            = 0x80090306,
    SEC_E_CANNOT_INSTALL       = 0x80090307,
    SEC_E_INVALID_TOKEN        = 0x80090308,
    SEC_E_CANNOT_PACK          = 0x80090309,
    SEC_E_QOP_NOT_SUPPORTED    = 0x8009030A,
    SEC_E_NO_IMPERSONATION     = 0x8009030B,
    SEC_E_LOGON_DENIED         = 0x8009030C,
    SEC_E_UNKNOWN_CREDENTIALS  = 0x8009030D,
    SEC_E_NO_CREDENTIALS       = 0x8009030E,
    SEC_E_MESSAGE_ALTERED      = 0x8009030F,
    SEC_E_OUT_OF_SEQUENCE      = 0x80090310,
    SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311,
    SEC_E_BAD_PKGID            = 0x80090316,
    SEC_E_CONTEXT_EXPIRED      = 0x80090317,
    SEC_E_INCOMPLETE_MESSAGE   = 0x80090318,
    SEC_E_INCOMPLETE_CREDENTIALS = 0x80090320,
    SEC_E_BUFFER_TOO_SMALL     = 0x80090321,
    SEC_E_WRONG_PRINCIPAL      = 0x80090322,
    SEC_E_TIME_SKEW            = 0x80090324,
    SEC_E_UNTRUSTED_ROOT       = 0x80090325,
    SEC_E_ILLEGAL_MESSAGE      = 0x80090326,
    SEC_E_CERT_UNKNOWN         = 0x80090327,
    SEC_E_CERT_EXPIRED         = 0x80090328,
    SEC_E_ENCRYPT_FAILURE      = 0x80090329,
    SEC_E_DECRYPT_FAILURE      = 0x80090330,
    SEC_E_ALGORITHM_MISMATCH   = 0x80090331,
    SEC_E_SECURITY_QOS_FAILED  = 0x80090332,
    SEC_E_UNFINISHED_CONTEXT_DELETED = 0x80090333,
    SEC_E_NO_TGT_REPLY         = 0x80090334,
    SEC_E_NO_IP_ADDRESSES      = 0x80090335,
    SEC_E_WRONG_CREDENTIAL_HANDLE = 0x80090336,
    SEC_E_CRYPTO_SYSTEM_INVALID   = 0x80090337,
    SEC_E_MAX_REFERRALS_EXCEEDED  = 0x80090338,
    SEC_E_MUST_BE_KDC          = 0x80090339,
    SEC_E_STRONG_CRYPTO_NOT_SUPPORTED = 0x8009033A,
    SEC_E_TOO_MANY_PRINCIPALS  = 0x8009033B,
    SEC_E_NO_PA_DATA           = 0x8009033C,
    SEC_E_PKINIT_NAME_MISMATCH = 0x8009033D,
    SEC_E_SMARTCARD_LOGON_REQUIRED = 0x8009033E,
    SEC_E_SHUTDOWN_IN_PROGRESS = 0x8009033F,
    SEC_E_KDC_INVALID_REQUEST  = 0x80090340,
    SEC_E_KDC_UNABLE_TO_REFER  = 0x80090341,
    SEC_E_KDC_UNKNOWN_ETYPE    = 0x80090342,
    SEC_E_UNSUPPORTED_PREAUTH  = 0x80090343,
    SEC_E_DELEGATION_REQUIRED  = 0x80090345,
    SEC_E_BAD_BINDINGS         = 0x80090346,
    SEC_E_MULTIPLE_ACCOUNTS    = 0x80090347,
    SEC_E_NO_KERB_KEY          = 0x80090348,
    SEC_E_CERT_WRONG_USAGE     = 0x80090349,
    SEC_E_DOWNGRADE_DETECTED   = 0x80090350,
    SEC_E_SMARTCARD_CERT_REVOKED = 0x80090351,
    SEC_E_ISSUING_CA_UNTRUSTED = 0x80090352,
    SEC_E_REVOCATION_OFFLINE_C = 0x80090353,
    SEC_E_PKINIT_CLIENT_FAILURE = 0x80090354,
    SEC_E_SMARTCARD_CERT_EXPIRED = 0x80090355,
    SEC_E_NO_S4U_PROT_SUPPORT  = 0x80090356,
    SEC_E_CROSSREALM_DELEGATION_FAILURE = 0x80090357,
    SEC_E_REVOCATION_OFFLINE_KDC = 0x80090358,
    SEC_E_ISSUING_CA_UNTRUSTED_KDC = 0x80090359,
    SEC_E_KDC_CERT_EXPIRED     = 0x8009035A,
    SEC_E_KDC_CERT_REVOKED     = 0x8009035B,
    SEC_E_INVALID_PARAMETER    = 0x8009035D,
    SEC_E_DELEGATION_POLICY    = 0x8009035E,
    SEC_E_POLICY_NLTM_ONLY     = 0x8009035F,
    SEC_E_NO_CONTEXT           = 0x80090361,
    SEC_E_PKU2U_CERT_FAILURE   = 0x80090362,
    SEC_E_MUTUAL_AUTH_FAILED   = 0x80090363,

    SEC_I_CONTINUE_NEEDED      = 0x00090312,
    SEC_I_COMPLETE_NEEDED      = 0x00090313,
    SEC_I_COMPLETE_AND_CONTINUE = 0x00090314,
    SEC_I_LOCAL_LOGON          = 0x00090315,
    SEC_I_CONTEXT_EXPIRED      = 0x00090317,
    SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320,
    SEC_I_RENEGOTIATE          = 0x00090321,
    SEC_I_NO_LSA_CONTEXT       = 0x00090323,
    SEC_I_SIGNATURE_NEEDED     = 0x0009035C,
    SEC_I_NO_RENEGOTIATION     = 0x00090360
};

/* InitializeSecurityContext Flags */
enum ISC_REQ {
    ISC_REQ_DELEGATE = 0x00000001,
    ISC_REQ_MUTUAL_AUTH = 0x00000002,
    ISC_REQ_REPLAY_DETECT = 0x00000004,
    ISC_REQ_SEQUENCE_DETECT = 0x00000008,
    ISC_REQ_CONFIDENTIALITY = 0x00000010,
    ISC_REQ_USE_SESSION_KEY = 0x00000020,
    ISC_REQ_PROMPT_FOR_CREDS = 0x00000040,
    ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080,
    ISC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ISC_REQ_USE_DCE_STYLE = 0x00000200,
    ISC_REQ_DATAGRAM = 0x00000400,
    ISC_REQ_CONNECTION = 0x00000800,
    ISC_REQ_CALL_LEVEL = 0x00001000,
    ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ISC_REQ_EXTENDED_ERROR = 0x00004000,
    ISC_REQ_STREAM = 0x00008000,
    ISC_REQ_INTEGRITY = 0x00010000,
    ISC_REQ_IDENTIFY = 0x00020000,
    ISC_REQ_NULL_SESSION = 0x00040000,
    ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_REQ_RESERVED1 = 0x00100000,
    ISC_REQ_FRAGMENT_TO_FIT = 0x00200000,
    ISC_REQ_FORWARD_CREDENTIALS = 0x00400000,
    ISC_REQ_NO_INTEGRITY = 0x00800000,
    ISC_REQ_USE_HTTP_STYLE = 0x01000000
};

/* AcceptSecurityContext Flags */
enum ASC_REQ {
    ASC_REQ_DELEGATE = 0x00000001,
    ASC_REQ_MUTUAL_AUTH = 0x00000002,
    ASC_REQ_REPLAY_DETECT = 0x00000004,
    ASC_REQ_SEQUENCE_DETECT = 0x00000008,
    ASC_REQ_CONFIDENTIALITY = 0x00000010,
    ASC_REQ_USE_SESSION_KEY = 0x00000020,
    ASC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ASC_REQ_USE_DCE_STYLE = 0x00000200,
    ASC_REQ_DATAGRAM = 0x00000400,
    ASC_REQ_CONNECTION = 0x00000800,
    ASC_REQ_CALL_LEVEL = 0x00001000,
    ASC_REQ_EXTENDED_ERROR = 0x00008000,
    ASC_REQ_STREAM = 0x00010000,
    ASC_REQ_INTEGRITY = 0x00020000,
    ASC_REQ_LICENSING = 0x00040000,
    ASC_REQ_IDENTIFY = 0x00080000,
    ASC_REQ_ALLOW_NULL_SESSION = 0x00100000,
    ASC_REQ_ALLOW_NON_USER_LOGONS = 0x00200000,
    ASC_REQ_ALLOW_CONTEXT_REPLAY = 0x00400000,
    ASC_REQ_FRAGMENT_TO_FIT = 0x00800000,
    ASC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ASC_REQ_NO_TOKEN = 0x01000000,
    ASC_REQ_PROXY_BINDINGS = 0x04000000,
    ASC_REQ_ALLOW_MISSING_BINDINGS = 0x10000000
};

enum ASC_RET {
    ASC_RET_DELEGATE = 0x00000001,
    ASC_RET_MUTUAL_AUTH = 0x00000002,
    ASC_RET_REPLAY_DETECT = 0x00000004,
    ASC_RET_SEQUENCE_DETECT = 0x00000008,
    ASC_RET_CONFIDENTIALITY = 0x00000010,
    ASC_RET_USE_SESSION_KEY = 0x00000020,
    ASC_RET_ALLOCATED_MEMORY = 0x00000100,
    ASC_RET_USED_DCE_STYLE = 0x00000200,
    ASC_RET_DATAGRAM = 0x00000400,
    ASC_RET_CONNECTION = 0x00000800,
    ASC_RET_CALL_LEVEL = 0x00002000,
    ASC_RET_THIRD_LEG_FAILED = 0x00004000,
    ASC_RET_EXTENDED_ERROR = 0x00008000,
    ASC_RET_STREAM = 0x00010000,
    ASC_RET_INTEGRITY = 0x00020000,
    ASC_RET_LICENSING = 0x00040000,
    ASC_RET_IDENTIFY = 0x00080000,
    ASC_RET_NULL_SESSION = 0x00100000,
    ASC_RET_ALLOW_NON_USER_LOGONS = 0x00200000,
    ASC_RET_FRAGMENT_ONLY = 0x00800000,
    ASC_RET_NO_TOKEN = 0x01000000,
    ASC_RET_NO_PROXY_BINDINGS = 0x04000000,
    ASC_RET_MISSING_BINDINGS = 0x10000000
};

enum CredentialUse {
    SECPKG_CRED_INBOUND = 0x00000001,
    SECPKG_CRED_OUTBOUND = 0x00000002,
    SECPKG_CRED_BOTH = 0x00000003,
    SECPKG_CRED_AUTOLOGON_RESTRICTED = 0x00000010,
    SECPKG_CRED_PROCESS_POLICY_ONLY = 0x00000020
};


/**
 * TSRequest ::= SEQUENCE {
 *     version    [0] INTEGER,
 *     negoTokens [1] NegoData OPTIONAL,
 *     authInfo   [2] OCTET STRING OPTIONAL,
 *     pubKeyAuth [3] OCTET STRING OPTIONAL,
 *     errorCode  [4] INTEGER OPTIONAL,
 *     clientNonce[5] OCTET STRING OPTIONAL
 * }
 *
 * NegoData ::= SEQUENCE OF NegoDataItem
 *
 * NegoDataItem ::= SEQUENCE {
 *     negoToken [0] OCTET STRING
 * }
 *
 * TSCredentials ::= SEQUENCE {
 *     credType    [0] INTEGER,
 *     credentials [1] OCTET STRING
 * }
 *
 * TSPasswordCreds ::= SEQUENCE {
 *     domainName  [0] OCTET STRING,
 *     userName    [1] OCTET STRING,
 *     password    [2] OCTET STRING
 * }
 *
 * TSSmartCardCreds ::= SEQUENCE {
 *     pin        [0] OCTET STRING,
 *     cspData    [1] TSCspDataDetail,
 *     userHint   [2] OCTET STRING OPTIONAL,
 *     domainHint [3] OCTET STRING OPTIONAL
 * }
 *
 * TSCspDataDetail ::= SEQUENCE {
 *     keySpec       [0] INTEGER,
 *     cardName      [1] OCTET STRING OPTIONAL,
 *     readerName    [2] OCTET STRING OPTIONAL,
 *     containerName [3] OCTET STRING OPTIONAL,
 *     cspName       [4] OCTET STRING OPTIONAL
 * }
 *
 */


struct ClientNonce {
    static const int CLIENT_NONCE_LENGTH = 32;
    bool initialized = false;
    uint8_t data[CLIENT_NONCE_LENGTH] = {};

    static inline int sizeof_client_nonce(int length) {
        length = BER::sizeof_octet_string(length);
        length += BER::sizeof_contextual_tag(length);
        return length;
    }

    ClientNonce() {}

    bool isset() {
        return this->initialized;
    }

    void reset()
    {
        this->initialized = false;
    }

    int ber_length(int use_version)
    {
        return (use_version >= 5 && this->initialized)
            ? sizeof_client_nonce(CLIENT_NONCE_LENGTH)
            : 0;
    }

    void ber_write(int version, OutStream & stream)
    {
        if (version >= 5 && this->initialized) {
            // LOG(LOG_INFO, "Credssp: TSCredentials::emit() clientNonce");
            BER::write_sequence_octet_string(stream, 5, this->data, CLIENT_NONCE_LENGTH);
        }
    }

    int ber_read(int version, int & length, InStream & stream)
    {
        if (version >= 5 && BER::read_contextual_tag(stream, 5, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCredentials::recv() CLIENTNONCE");
            if(!BER::read_octet_string_tag(stream, length)){
                return -1;
            }
            this->initialized = true;
            if (length != CLIENT_NONCE_LENGTH){
                LOG(LOG_ERR, "Truncated client nonce");
                return -1;
            }
            stream.in_copy_bytes(this->data, CLIENT_NONCE_LENGTH);
            this->initialized = true;
        }
        return 0;
    }
};


namespace CredSSP {


    inline int sizeof_nego_token(int length) {
        length = BER::sizeof_octet_string(length);
        length += BER::sizeof_contextual_tag(length);
        return length;
    }

    inline int sizeof_nego_tokens(int length) {
        length = sizeof_nego_token(length);
        length += BER::sizeof_sequence_tag(length);
        length += BER::sizeof_sequence_tag(length);
        length += BER::sizeof_contextual_tag(length);
        return length;
    }

    inline int sizeof_pub_key_auth(int length) {
        length = BER::sizeof_octet_string(length);
        length += BER::sizeof_contextual_tag(length);
        return length;
    }

    inline int sizeof_auth_info(int length) {
        length = BER::sizeof_octet_string(length);
        length += BER::sizeof_contextual_tag(length);
        return length;
    }


    inline int sizeof_octet_string_seq(int length) {
        length = BER::sizeof_octet_string(length);
        length += BER::sizeof_contextual_tag(length);
        return length;
    }
}  // namespace CredSSP

struct TSRequest final {
    /* TSRequest */

    /* [0] version */
    uint32_t version;
    uint32_t use_version;

    /* [1] negoTokens (NegoData) */
    std::vector<uint8_t> negoTokens;
    // BStream negoTokens;
    /* [2] authInfo (OCTET STRING) */
    std::vector<uint8_t> authInfo;
    // BStream authInfo;
    /* [3] pubKeyAuth (OCTET STRING) */
    std::vector<uint8_t> pubKeyAuth;
    // BStream pubKeyAuth;
    /* [4] errorCode (INTEGER OPTIONAL) */
    uint32_t error_code{0};
    /* [5] clientNonce (OCTET STRING OPTIONAL) */
    ClientNonce clientNonce;

    TSRequest(uint32_t version = 6)
        : version(version)
        , use_version(this->version)
        , error_code(0)
    {
    }

    int ber_sizeof(int length) {
        length += BER::sizeof_integer(this->version);
        length += BER::sizeof_contextual_tag(BER::sizeof_integer(this->version));
        if (this->version >= 3
            && this->version != 5
            && this->error_code != 0) {
            length += BER::sizeof_integer(this->error_code);
            length += BER::sizeof_contextual_tag(BER::sizeof_integer(this->error_code));
        }
        return length;
    }

    void emit(OutStream & stream) /* TODO const*/ {
        int nego_tokens_length = (this->negoTokens.size() > 0)
            ? CredSSP::sizeof_nego_tokens(this->negoTokens.size())
            : 0;
        int pub_key_auth_length = (this->pubKeyAuth.size() > 0)
            ? CredSSP::sizeof_pub_key_auth(this->pubKeyAuth.size())
            : 0;
        int auth_info_length = (this->authInfo.size() > 0)
            ? CredSSP::sizeof_auth_info(this->authInfo.size())
            : 0;

        int client_nonce_length = this->clientNonce.ber_length(use_version);

        if (this->version >= 3
            && this->version != 5
            && this->error_code != 0) {
            nego_tokens_length = 0;
            pub_key_auth_length = 0;
            auth_info_length = 0;
            client_nonce_length = 0;
        }

        int length = nego_tokens_length
            + pub_key_auth_length
            + auth_info_length
            + client_nonce_length;
        int ts_request_length = this->ber_sizeof(length);

        /* TSRequest */
        BER::write_sequence_tag(stream, ts_request_length);

        /* [0] version */
        BER::write_contextual_tag(stream, 0, BER::sizeof_integer(this->version), true);
        BER::write_integer(stream, this->version);
        LOG(LOG_INFO, "Credssp TSCredentials::emit() Local Version %u", this->version);

        /* [1] negoTokens (NegoData) */
        if (nego_tokens_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCredentials::emit() NegoToken");
            length = nego_tokens_length;

            int sequence_length   = BER::sizeof_sequence_octet_string(this->negoTokens.size());
            int sequenceof_length = BER::sizeof_sequence(sequence_length);
            int context_length    = BER::sizeof_sequence(sequenceof_length);

            length -= BER::write_contextual_tag(stream, 1, context_length, true);
            length -= BER::write_sequence_tag(stream, sequenceof_length);
            length -= BER::write_sequence_tag(stream, sequence_length);
            length -= BER::write_sequence_octet_string(stream, 0, this->negoTokens.data(), this->negoTokens.size());

            assert(length == 0);
            (void)length;
        }

        /* [2] authInfo (OCTET STRING) */
        if (auth_info_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCredentials::emit() AuthInfo");
            length = auth_info_length;
            length -= BER::write_sequence_octet_string(stream, 2,
                                                       this->authInfo.data(),
                                                       this->authInfo.size());
            assert(length == 0);
            (void)length;
        }

        /* [3] pubKeyAuth (OCTET STRING) */
        if (pub_key_auth_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCredentials::emit() pubKeyAuth");
            length = pub_key_auth_length;
            length -= BER::write_sequence_octet_string(stream, 3,
                                                       this->pubKeyAuth.data(),
                                                       this->pubKeyAuth.size());
            assert(length == 0);
            (void)length;
        }
        /* [4] errorCode (INTEGER) */
        if (this->version >= 3
            && this->version != 5
            && this->error_code != 0) {
            LOG(LOG_INFO, "Credssp: TSCredentials::emit() errorCode");
            BER::write_contextual_tag(stream, 0, BER::sizeof_integer(this->error_code), true);
            BER::write_integer(stream, this->error_code);
        }

        /* [5] clientNonce (OCTET STRING) */
        this->clientNonce.ber_write(this->version, stream);
    }

    int recv(InStream & stream) {
        int length;
        uint32_t remote_version;

        /* TSRequest */
        if(!BER::read_sequence_tag(stream, length) ||
           !BER::read_contextual_tag(stream, 0, length, true) ||
           !BER::read_integer(stream, remote_version)) {
            return -1;
        }
        LOG(LOG_INFO, "Credssp TSCredentials::recv() Remote Version %u", remote_version);

        if (remote_version < this->use_version) {
            this->use_version = remote_version;
        }
        LOG(LOG_INFO, "Credssp TSCredentials::recv() Negotiated version %u", this->use_version);

        /* [1] negoTokens (NegoData) */
        if (BER::read_contextual_tag(stream, 1, length, true))        {
            // LOG(LOG_INFO, "Credssp TSCredentials::recv() NEGOTOKENS");

            if (!BER::read_sequence_tag(stream, length) || /* SEQUENCE OF NegoDataItem */ /*NOLINT(misc-redundant-expression)*/
                !BER::read_sequence_tag(stream, length) || /* NegoDataItem */
                !BER::read_contextual_tag(stream, 0, length, true) || /* [0] negoToken */
                !BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
                !stream.in_check_rem(length)) {
                return -1;
            }

            this->negoTokens = std::vector<uint8_t>(length);
            stream.in_copy_bytes(this->negoTokens.data(), length);
        }

        /* [2] authInfo (OCTET STRING) */
        if (BER::read_contextual_tag(stream, 2, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCredentials::recv() AUTHINFO");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->authInfo = std::vector<uint8_t>(length);
            stream.in_copy_bytes(this->authInfo.data(), length);
        }

        /* [3] pubKeyAuth (OCTET STRING) */
        if (BER::read_contextual_tag(stream, 3, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCredentials::recv() PUBKEYAUTH");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }
            this->pubKeyAuth = std::vector<uint8_t>(length);
            stream.in_copy_bytes(this->pubKeyAuth.data(), length);
        }
        /* [4] errorCode (INTEGER) */
        if (remote_version >= 3
            && remote_version != 5
            && BER::read_contextual_tag(stream, 4, length, true)) {
            LOG(LOG_INFO, "Credssp TSCredentials::recv() ErrorCode");
            if (!BER::read_integer(stream, this->error_code)) {
                return -1;
            }
            LOG(LOG_INFO, "Credssp TSCredentials::recv() "
                "ErrorCode = %x, Facility = %x, Code = %x",
                this->error_code,
                (this->error_code >> 16) & 0x7FF,
                (this->error_code & 0xFFFF)
            );
        }
        /* [5] clientNonce (OCTET STRING) */
        if (this->clientNonce.ber_read(remote_version, length, stream) == -1){
            return -1;
        }
        return 0;
    }

};


/*
 * TSPasswordCreds ::= SEQUENCE {
 *     domainName  [0] OCTET STRING,
 *     userName    [1] OCTET STRING,
 *     password    [2] OCTET STRING
 * }
 */
struct TSPasswordCreds {
    uint8_t domainName[256];
    size_t domainName_length{0};
    uint8_t userName[256];
    size_t userName_length{0};
    uint8_t password[256];
    size_t password_length{0};

    TSPasswordCreds() = default;

    TSPasswordCreds(const uint8_t * domain, size_t domain_length, const uint8_t * user, size_t user_length, const uint8_t * pass, size_t pass_length) {
        this->domainName_length = (domain_length < sizeof(this->domainName))
            ? domain_length
            : sizeof(this->domainName);
        memcpy(this->domainName, domain, this->domainName_length);

        this->userName_length = (user_length < sizeof(this->userName))
            ? user_length
            : sizeof(this->userName);
        memcpy(this->userName, user, this->userName_length);

        this->password_length = (pass_length < sizeof(this->password))
            ? pass_length
            : sizeof(this->password);
        memcpy(this->password, pass, this->password_length);
    }

    // TSPasswordCreds(InStream & stream) {
    //     this->recv(stream);
    // }


    int ber_sizeof() const {
        int length = 0;
        // TO COMPLETE
        length += BER::sizeof_sequence_octet_string(domainName_length);
        length += BER::sizeof_sequence_octet_string(userName_length);
        length += BER::sizeof_sequence_octet_string(password_length);
        return length;
    }

    int emit(OutStream & stream) const {
        int size = 0;
        int innerSize = this->ber_sizeof();

        // /* TSPasswordCreds (SEQUENCE) */

        size += BER::write_sequence_tag(stream, innerSize);

        // /* [0] domainName (OCTET STRING) */
        size += BER::write_sequence_octet_string(stream, 0, this->domainName,
                                                 this->domainName_length);

        // /* [1] userName (OCTET STRING) */
        size += BER::write_sequence_octet_string(stream, 1, this->userName,
                                                 this->userName_length);

        // /* [2] password (OCTET STRING) */
        size += BER::write_sequence_octet_string(stream, 2, this->password,
                                                 this->password_length);
        return size;
    }


    void recv(InStream & stream) {
        int length = 0;
        /* TSPasswordCreds (SEQUENCE) */
        BER::read_sequence_tag(stream, length);

        /* [0] domainName (OCTET STRING) */
        BER::read_contextual_tag(stream, 0, length, true);
        BER::read_octet_string_tag(stream, length);

        this->domainName_length = length;
        stream.in_copy_bytes(this->domainName, length);

        /* [1] userName (OCTET STRING) */
        BER::read_contextual_tag(stream, 1, length, true);
        BER::read_octet_string_tag(stream, length);

        this->userName_length = length;
        stream.in_copy_bytes(this->userName, length);

        /* [2] password (OCTET STRING) */
        BER::read_contextual_tag(stream, 2, length, true);
        BER::read_octet_string_tag(stream, length);

        this->password_length = length;
        stream.in_copy_bytes(this->password, length);

    }
};

/* TSCspDataDetail ::= SEQUENCE {
 *     keySpec       [0] INTEGER,
 *     cardName      [1] OCTET STRING OPTIONAL,
 *     readerName    [2] OCTET STRING OPTIONAL,
 *     containerName [3] OCTET STRING OPTIONAL,
 *     cspName       [4] OCTET STRING OPTIONAL
 * }
 *
 */
struct TSCspDataDetail {
    uint32_t keySpec{0};
    uint8_t cardName[256]{};
    size_t cardName_length{0};
    uint8_t readerName[256]{};
    size_t readerName_length{0};
    uint8_t containerName[256]{};
    size_t containerName_length{0};
    uint8_t cspName[256]{};
    size_t cspName_length{0};

    TSCspDataDetail()

    = default;

    TSCspDataDetail(uint32_t keySpec, uint8_t * cardName, size_t cardName_length,
                    uint8_t * readerName, size_t readerName_length,
                    uint8_t * containerName, size_t containerName_length,
                    uint8_t * cspName, size_t cspName_length)
        : keySpec(keySpec)
        ,
         cardName_length(cardName_length)
        ,
         readerName_length(readerName_length)
        ,
         containerName_length(containerName_length)
        ,
         cspName_length(cspName_length)
    {
        this->cardName_length = (cardName_length < sizeof(this->cardName))
            ? cardName_length
            : sizeof(this->cardName);
        memcpy(this->cardName, cardName, this->cardName_length);

        this->readerName_length = (readerName_length < sizeof(this->readerName))
            ? readerName_length
            : sizeof(this->readerName);
        memcpy(this->readerName, readerName, this->readerName_length);

        this->containerName_length = (containerName_length < sizeof(this->containerName))
            ? containerName_length
            : sizeof(this->containerName);
        memcpy(this->containerName, containerName, this->containerName_length);

        this->cspName_length = (cspName_length < sizeof(this->cspName))
            ? cspName_length
            : sizeof(this->cspName);
        memcpy(this->cspName, cspName, this->cspName_length);

    }

    int ber_sizeof() const {
        int length = 0;
        length += BER::sizeof_contextual_tag(BER::sizeof_integer(this->keySpec));
        length += BER::sizeof_integer(this->keySpec);
        length += (this->cardName_length > 0) ?
            CredSSP::sizeof_octet_string_seq(this->cardName_length) : 0;
        length += (this->readerName_length > 0) ?
            CredSSP::sizeof_octet_string_seq(this->readerName_length) : 0;
        length += (this->containerName_length > 0) ?
            CredSSP::sizeof_octet_string_seq(this->containerName_length) : 0;
        length += (this->cspName_length > 0) ?
            CredSSP::sizeof_octet_string_seq(this->cspName_length) : 0;
        return length;
    }

    int emit(OutStream & stream) const {
        int length = 0;
        int size = 0;
        int innerSize = this->ber_sizeof();

        // /* TSCspDataDetail (SEQUENCE) */

        size += BER::write_sequence_tag(stream, innerSize);

        /* [0] keySpec */
        size += BER::write_contextual_tag(stream, 0, BER::sizeof_integer(this->keySpec), true);
        size += BER::write_integer(stream, this->keySpec);

        /* [1] cardName (OCTET STRING OPTIONAL) */
        if (this->cardName_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCspDataDetail::emit() cardName");
            length = CredSSP::sizeof_octet_string_seq(this->cardName_length);
            size += length;
            length -= BER::write_sequence_octet_string(stream, 1,
                                                       this->cardName,
                                                       this->cardName_length);
            assert(length == 0);
            (void)length;
        }
        /* [2] readerName (OCTET STRING OPTIONAL) */
        if (this->readerName_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCspDataDetail::emit() readerName");
            length = CredSSP::sizeof_octet_string_seq(this->readerName_length);
            size += length;
            length -= BER::write_sequence_octet_string(stream, 2,
                                                       this->readerName,
                                                       this->readerName_length);
            assert(length == 0);
            (void)length;
        }
        /* [3] containerName (OCTET STRING OPTIONAL) */
        if (this->containerName_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCspDataDetail::emit() containerName");
            length = CredSSP::sizeof_octet_string_seq(this->containerName_length);
            size += length;
            length -= BER::write_sequence_octet_string(stream, 3,
                                                       this->containerName,
                                                       this->containerName_length);
            assert(length == 0);
            (void)length;
        }
        /* [4] cspName (OCTET STRING OPTIONAL) */
        if (this->cspName_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSCspDataDetail::emit() cspName");
            length = CredSSP::sizeof_octet_string_seq(this->cspName_length);
            size += length;
            length -= BER::write_sequence_octet_string(stream, 4,
                                                       this->cspName,
                                                       this->cspName_length);
            assert(length == 0);
            (void)length;
        }
        return size;
    }

    int recv(InStream & stream) {
        int length = 0;
        /* TSCspDataDetail ::= SEQUENCE */
        /* TSSmartCardCreds (SEQUENCE) */
        BER::read_sequence_tag(stream, length);


        /* [0] keySpec (INTEGER) */
        BER::read_contextual_tag(stream, 0, length, true);
        BER::read_integer(stream, this->keySpec);

        /* [1] cardName (OCTET STRING OPTIONAL) */
        if (BER::read_contextual_tag(stream, 1, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCspDataDetail::recv() : cardName");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->cardName_length = length;
            stream.in_copy_bytes(this->cardName, length);
        }
        /* [2] readerName (OCTET STRING OPTIONAL) */
        if (BER::read_contextual_tag(stream, 2, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCspDataDetail::recv() : readerName");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->readerName_length = length;
            stream.in_copy_bytes(this->readerName, length);
        }
        /* [3] containerName (OCTET STRING OPTIONAL) */
        if (BER::read_contextual_tag(stream, 3, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCspDataDetail::recv() : containerName");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->containerName_length = length;
            stream.in_copy_bytes(this->containerName, length);
        }
        /* [4] cspName (OCTET STRING OPTIONAL) */
        if (BER::read_contextual_tag(stream, 4, length, true)) {
            // LOG(LOG_INFO, "Credssp TSCspDataDetail::recv() : cspName");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->cspName_length = length;
            stream.in_copy_bytes(this->cspName, length);
        }
        return 0;

    }
};
/*
 * TSSmartCardCreds ::= SEQUENCE {
 *     pin        [0] OCTET STRING,
 *     cspData    [1] TSCspDataDetail,
 *     userHint   [2] OCTET STRING OPTIONAL,
 *     domainHint [3] OCTET STRING OPTIONAL
 * }
 */

struct TSSmartCardCreds {
    uint8_t pin[256]{};
    size_t pin_length{0};
    TSCspDataDetail cspData;
    uint8_t userHint[256]{};
    size_t userHint_length{0};
    uint8_t domainHint[256]{};
    size_t domainHint_length{0};

    TSSmartCardCreds() = default;

    TSSmartCardCreds(uint8_t * pin, size_t pin_length,
                     uint8_t * userHint, size_t userHint_length,
                     uint8_t * domainHint, size_t domainHint_length)
    {
        this->pin_length = (pin_length < sizeof(this->pin))
            ? pin_length
            : sizeof(this->pin);
        memcpy(this->pin, pin, this->pin_length);

        this->userHint_length = (userHint_length < sizeof(this->userHint))
            ? userHint_length
            : sizeof(this->userHint);
        memcpy(this->userHint, userHint, this->userHint_length);

        this->domainHint_length = (domainHint_length < sizeof(this->domainHint))
            ? domainHint_length
            : sizeof(this->domainHint);
        memcpy(this->domainHint, domainHint, this->domainHint_length);
    }

    void set_cspdatadetail(uint32_t keySpec, uint8_t * cardName, size_t cardName_length,
                           uint8_t * readerName, size_t readerName_length,
                           uint8_t * containerName, size_t containerName_length,
                           uint8_t * cspName, size_t cspName_length) {
        this->cspData = TSCspDataDetail(keySpec, cardName, cardName_length,
                           readerName, readerName_length,
                           containerName, containerName_length,
                           cspName, cspName_length);
    }

    int ber_sizeof() const {
        int length = 0;
        length += CredSSP::sizeof_octet_string_seq(this->pin_length);
        length += BER::sizeof_contextual_tag(BER::sizeof_sequence(this->cspData.ber_sizeof()));
        length += BER::sizeof_sequence(this->cspData.ber_sizeof());
        length += (this->userHint_length > 0) ?
            CredSSP::sizeof_octet_string_seq(this->userHint_length) : 0;
        length += (this->domainHint_length > 0) ?
            CredSSP::sizeof_octet_string_seq(this->domainHint_length) : 0;
        return length;
    }

    int emit(OutStream & stream) const {
        int size = 0;
        int length;
        int innerSize = this->ber_sizeof();
        int cspDataSize = 0;

        /* TSCredentials (SEQUENCE) */
        size += BER::write_sequence_tag(stream, innerSize);

        /* [0] pin (OCTET STRING) */
        size += BER::write_sequence_octet_string(stream, 0, this->pin,
                                         this->pin_length);

        /* [1] cspData (OCTET STRING) */

        cspDataSize = BER::sizeof_sequence(this->cspData.ber_sizeof());
        size += BER::write_contextual_tag(stream, 1, cspDataSize, true);
        size += this->cspData.emit(stream);

        /* [2] userHint (OCTET STRING OPTIONAL) */
        if (this->userHint_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSSmartCard::emit() userHint");
            length = CredSSP::sizeof_octet_string_seq(this->userHint_length);
            size += length;
            length -= BER::write_sequence_octet_string(stream, 2,
                                                       this->userHint,
                                                       this->userHint_length);
            assert(length == 0);
            (void)length;
        }

        /* [3] domainHint (OCTET STRING OPTIONAL) */
        if (this->domainHint_length > 0) {
            // LOG(LOG_INFO, "Credssp: TSSmartCard::emit() domainHint");
            length = CredSSP::sizeof_octet_string_seq(this->domainHint_length);
            size += length;
            length -= BER::write_sequence_octet_string(stream, 3,
                                                       this->domainHint,
                                                       this->domainHint_length);
            assert(length == 0);
            (void)length;
        }

        return size;
    }

    int recv(InStream & stream) {
        int length = 0;
        /* TSSmartCardCreds (SEQUENCE) */
        BER::read_sequence_tag(stream, length);

        /* [0] pin (OCTET STRING) */
        BER::read_contextual_tag(stream, 0, length, true);
        BER::read_octet_string_tag(stream, length);

        this->pin_length = length;
        stream.in_copy_bytes(this->pin, length);

        /* [1] cspData (TSCspDataDetail) */
        BER::read_contextual_tag(stream, 1, length, true);
        this->cspData.recv(stream);

        /* [2] userHint (OCTET STRING) */
        if (BER::read_contextual_tag(stream, 2, length, true)) {
            // LOG(LOG_INFO, "Credssp TSSmartCardCreds::recv() : userHint");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->userHint_length = length;
            stream.in_copy_bytes(this->userHint, length);
        }

        /* [3] domainHint (OCTET STRING) */
        if (BER::read_contextual_tag(stream, 3, length, true)) {
            // LOG(LOG_INFO, "Credssp TSSmartCardCreds::recv() : domainHint");
            if(!BER::read_octet_string_tag(stream, length) || /* OCTET STRING */
               !stream.in_check_rem(length)) {
                return -1;
            }

            this->domainHint_length = length;
            stream.in_copy_bytes(this->domainHint, length);
        }

        return 0;
    }
};




/*
 * TSCredentials ::= SEQUENCE {
 *     credType    [0] INTEGER,
 *     credentials [1] OCTET STRING
 * }
 */
struct TSCredentials
{
    uint32_t credType{1};
    TSPasswordCreds passCreds;
    TSSmartCardCreds smartcardCreds;
    // For now, TSCredentials can only contains TSPasswordCreds (not TSSmartCardCreds)

    TSCredentials() = default;

    TSCredentials(const uint8_t * domain, size_t domain_length, const uint8_t * user, size_t user_length, const uint8_t * pass, size_t pass_length)
        : credType(1)
        , passCreds(domain, domain_length,
                    user, user_length,
                    pass, pass_length)
    {

    }

    TSCredentials(uint8_t * pin, size_t pin_length,
                  uint8_t * userHint, size_t userHint_length,
                  uint8_t * domainHint, size_t domainHint_length,
                  uint32_t keySpec, uint8_t * cardName, size_t cardName_length,
                  uint8_t * readerName, size_t readerName_length,
                  uint8_t * containerName, size_t containerName_length,
                  uint8_t * cspName, size_t cspName_length)
        : credType(2)
        , smartcardCreds(pin, pin_length,
                         userHint, userHint_length,
                         domainHint, domainHint_length)
    {
        this->smartcardCreds.set_cspdatadetail(keySpec, cardName, cardName_length,
                                               readerName, readerName_length,
                                               containerName, containerName_length,
                                               cspName, cspName_length);

    }

    void set_smartcard(uint8_t * pin, size_t pin_length,
                       uint8_t * userHint, size_t userHint_length,
                       uint8_t * domainHint, size_t domainHint_length,
                       uint32_t keySpec, uint8_t * cardName, size_t cardName_length,
                       uint8_t * readerName, size_t readerName_length,
                       uint8_t * containerName, size_t containerName_length,
                       uint8_t * cspName, size_t cspName_length) {
        this->credType = 2;
        this->smartcardCreds = TSSmartCardCreds(pin, pin_length,
                                                userHint, userHint_length,
                                                domainHint, domainHint_length);
        this->smartcardCreds.set_cspdatadetail(keySpec, cardName, cardName_length,
                                               readerName, readerName_length,
                                               containerName, containerName_length,
                                               cspName, cspName_length);
    }

//    void set_credentials(const uint8_t * domain, int domain_length, const uint8_t * user,
//                         int user_length, const uint8_t * pass, int pass_length) {
//        this->passCreds = TSPasswordCreds(domain, domain_length, user, user_length, pass, pass_length);
//    }

    void set_credentials_from_av(cbytes_view domain_av, cbytes_view user_av, cbytes_view password_av) {
        this->passCreds = TSPasswordCreds(domain_av.data(), domain_av.size(),
                                          user_av.data(), user_av.size(),
                                          password_av.data(), password_av.size());
    }

    int ber_sizeof() const {
        int size = 0;
        size += BER::sizeof_integer(this->credType);
        size += BER::sizeof_contextual_tag(BER::sizeof_integer(this->credType));
        if (this->credType == 2) {
            size += BER::sizeof_sequence_octet_string(BER::sizeof_sequence(this->smartcardCreds.ber_sizeof()));
        } else {
            size += BER::sizeof_sequence_octet_string(BER::sizeof_sequence(this->passCreds.ber_sizeof()));
        }
        return size;
    }

    int emit(OutStream & ts_credentials) const {
        // ts_credentials is the authInfo Stream field of TSRequest before it is sent
        // ts_credentials will not be encrypted and should be encrypted after calling emit
        int size = 0;

        int innerSize = this->ber_sizeof();
        int credsSize;

        /* TSCredentials (SEQUENCE) */
        size += BER::write_sequence_tag(ts_credentials, innerSize);

        /* [0] credType (INTEGER) */
        size += BER::write_contextual_tag(ts_credentials, 0, BER::sizeof_integer(this->credType), true);
        size += BER::write_integer(ts_credentials, this->credType);

        /* [1] credentials (OCTET STRING) */

        credsSize = (this->credType == 2) ?
            BER::sizeof_sequence(this->smartcardCreds.ber_sizeof()) :
            BER::sizeof_sequence(this->passCreds.ber_sizeof());

        size += BER::write_contextual_tag(ts_credentials, 1, BER::sizeof_octet_string(credsSize), true);
        size += BER::write_octet_string_tag(ts_credentials, credsSize);
        size += (this->credType == 1) ?
            this->passCreds.emit(ts_credentials) :
            this->smartcardCreds.emit(ts_credentials);

        return size;
    }


    void recv(InStream & ts_credentials) {
        // ts_credentials is decrypted and should be decrypted before calling recv
        int length;
        int creds_length;

        /* TSCredentials (SEQUENCE) */
        BER::read_sequence_tag(ts_credentials, length);

        /* [0] credType (INTEGER) */
        BER::read_contextual_tag(ts_credentials, 0, length, true);
        BER::read_integer(ts_credentials, this->credType);

        /* [1] credentials (OCTET STRING) */
        BER::read_contextual_tag(ts_credentials, 1, length, true);
        BER::read_octet_string_tag(ts_credentials, creds_length);

        if (this->credType == 2) {
            this->smartcardCreds.recv(ts_credentials);
        } else {
            this->passCreds.recv(ts_credentials);
        }
    }
};


// struct TSCspDataDetail : public TSCredentials {
//     int keySpec;
//     uint8_t cardName[256];
//     uint8_t readerName[256];
//     uint8_t containerName[256];
//     uint8_t cspName[256];

// };
// struct TSSmartCardCreds : public TSCredentials {
//     uint8_t pin[256];
//     TSCspDataDetail capData;
//     uint8_t userHint[256];
//     uint8_t domainHint[256];

// };
