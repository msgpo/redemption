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

   Transport layer abstraction
*/

#if !defined(__TRANSPORT_HPP__)
#define __TRANSPORT_HPP__

#include <sys/types.h> // recv, send
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include </usr/include/openssl/ssl.h>
#include </usr/include/openssl/err.h>

#include "error.hpp"
#include "log.hpp"


static inline int connect(const char* ip, int port, const char * name,
             int nbretry = 3, int retry_delai_ms = 1000) throw (Error)
{
    int sck = 0;
    LOG(LOG_INFO, "connecting to %s (%s:%d)\n", name, ip, port);
    // we will try connection several time
    // the trial process include socket opening, hostname resolution, etc
    // because some problems can come from the local endpoint,
    // not necessarily from the remote endpoint.
    sck = socket(PF_INET, SOCK_STREAM, 0);

    /* set snd buffer to at least 32 Kbytes */
    int snd_buffer_size;
    unsigned int option_len = sizeof(snd_buffer_size);
    if (0 == getsockopt(sck, SOL_SOCKET, SO_SNDBUF, &snd_buffer_size, &option_len)) {
        if (snd_buffer_size < 32768) {
            snd_buffer_size = 32768;
            if (-1 == setsockopt(sck,
                    SOL_SOCKET,
                    SO_SNDBUF,
                    &snd_buffer_size, sizeof(snd_buffer_size))){
                LOG(LOG_WARNING, "setsockopt failed with errno=%d", errno);
                throw Error(ERR_SOCKET_CONNECT_FAILED);
            }
        }
    }
    else {
        LOG(LOG_WARNING, "getsockopt failed with errno=%d", errno);
        throw Error(ERR_SOCKET_CONNECT_FAILED);
    }

    struct sockaddr_in s;
    memset(&s, 0, sizeof(struct sockaddr_in));
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    s.sin_addr.s_addr = inet_addr(ip);
    if (s.sin_addr.s_addr == INADDR_NONE) {
    TODO(" gethostbyname is obsolete use new function getnameinfo")
        LOG(LOG_INFO, "Asking ip to DNS for %s\n", ip);
        struct hostent *h = gethostbyname(ip);
        if (!h) {
            LOG(LOG_ERR, "DNS resolution failed for %s with errno =%d (%s)\n",
                ip, errno, strerror(errno));
            throw Error(ERR_SOCKET_GETHOSTBYNAME_FAILED);
        }
        s.sin_addr.s_addr = *((int*)(*(h->h_addr_list)));
    }
    fcntl(sck, F_SETFL, fcntl(sck, F_GETFL) | O_NONBLOCK);

    int trial = 0;
    for (; trial < nbretry ; trial++){
        int res = ::connect(sck, (struct sockaddr*)&s, sizeof(s));
        if (-1 != res){
            // connection suceeded
            break;
        }
        if (trial > 0){
            LOG(LOG_INFO, "Connection to %s failed with errno = %d (%s)",
                ip, errno, strerror(errno));
        }
        if ((errno == EINPROGRESS) || (errno == EALREADY)){
            // try again
            fd_set fds;
            FD_ZERO(&fds);
            struct timeval timeout = {
                retry_delai_ms / 1000,
                1000 * (retry_delai_ms % 1000)
            };
            FD_SET(sck, &fds);
            // exit select on timeout or connect or error
            // connect will catch the actual error if any,
            // no need to care of select result
            select(sck+1, NULL, &fds, NULL, &timeout);
        }
        else {
            // real failure
           trial = nbretry;
        }
    }
    if (trial >= nbretry){
        LOG(LOG_INFO, "All trials done connecting to %s\n", ip);
        throw Error(ERR_SOCKET_CONNECT_FAILED);
    }
    LOG(LOG_INFO, "connection to %s succeeded : socket %d\n", ip, sck);
    return sck;
}

class Transport {
public:
    uint64_t total_received;
    uint64_t last_quantum_received;
    uint64_t total_sent;
    uint64_t last_quantum_sent;
    uint64_t quantum_count;

    Transport() :
        total_received(0),
        last_quantum_received(0),
        total_sent(0),
        last_quantum_sent(0),
        quantum_count(0)
    {}

    void tick() {
        quantum_count++;
        last_quantum_received = 0;
        last_quantum_sent = 0;
    }

    virtual void enable_tls()
    {
        // default enable_tls do nothing
    }

    void recv(uint8_t ** pbuffer, size_t len) throw (Error) {
        this->recv(reinterpret_cast<char **>(pbuffer), len);
    }
    virtual void recv(char ** pbuffer, size_t len) throw (Error) = 0;
    virtual void send(const char * const buffer, size_t len) throw (Error) = 0;
    void send(const uint8_t * const buffer, size_t len) throw (Error) {
        this->send(reinterpret_cast<const char * const>(buffer), len);
    }
};

class GeneratorTransport : public Transport {

    public:
    size_t current;
    char * data;
    size_t len;


    GeneratorTransport(const char * data, size_t len)
        : Transport(), current(0), data(0), len(len)
    {
        this->data = (char *)malloc(len);
        memcpy(this->data, data, len);
    }

    void reset(const char * data, size_t len)
    {
        delete this->data;
        current = 0;
        this->len = len;
        this->data = (char *)malloc(len);
        memcpy(this->data, data, len);
    }

    using Transport::recv;
    virtual void recv(char ** pbuffer, size_t len) throw (Error) {
        if (current + len > this->len){
            size_t available_len = this->len - this->current;
            memcpy(*pbuffer, (const char *)(&this->data[this->current]),
                                            available_len);
            *pbuffer += available_len;
            this->current += available_len;
            LOG(LOG_INFO, "Generator transport has no more data");
            throw Error(ERR_TRANSPORT_NO_MORE_DATA, 0);
        }
        memcpy(*pbuffer, (const char *)(&this->data[current]), len);
        *pbuffer += len;
        current += len;
    }

    using Transport::send;
    virtual void send(const char * const buffer, size_t len) throw (Error) {
        // send perform like a /dev/null and does nothing in generator transport
    }
};

class CheckTransport : public Transport {

    public:
    bool status;
    size_t current;
    char * data;
    size_t len;


    CheckTransport(const char * data, size_t len)
        : Transport(), status(true), current(0), data(0), len(len)
    {
        this->data = (char *)malloc(len);
        memcpy(this->data, data, len);
    }

    void reset(const char * data, size_t len)
    {
        delete this->data;
        current = 0;
        this->len = len;
        this->data = (char *)malloc(len);
        memcpy(this->data, data, len);
    }

    using Transport::recv;
    virtual void recv(char ** pbuffer, size_t len) throw (Error) {
        // CheckTransport does never receive anything
        throw Error(ERR_TRANSPORT_OUTPUT_ONLY_USED_FOR_RECV);
    }

    using Transport::send;
    virtual void send(const char * const buffer, size_t len) throw (Error) {
        size_t available_len = (this->current + len > this->len)?this->len - this->current:len;
        if (0 != memcmp(buffer, (const char *)(&this->data[this->current]), available_len)){
            // data differs
            this->status = false;
            // find where
            uint32_t differs = 0;
            for (size_t i = 0; i < available_len ; i++){
                if (buffer[i] != ((const char *)(&this->data[this->current]))[i]){
                    differs = i;
                    break;
                }
            }
            LOG(LOG_INFO, "=============== Common Part =======");
            hexdump(buffer, differs);
            LOG(LOG_INFO, "=============== Expected ==========");
            hexdump((const char *)(&this->data[this->current]) + differs, available_len - differs);
            LOG(LOG_INFO, "=============== Got ===============");
            hexdump(buffer+differs, available_len - differs);
        }
        this->current += available_len;
        if (available_len != len){
            LOG(LOG_INFO, "Check transport out of reference data");
            TODO("Maybe we should expose it as a SOCKET CLOSE event ?");
            this->status = false;
            throw Error(ERR_TRANSPORT_NO_MORE_DATA, 0);
        }
    }
};

class TestTransport : public Transport {

    GeneratorTransport out;
    CheckTransport in;
    public:
    bool status;
    char name[256];
    uint32_t verbose;

    TestTransport(const char * name, const char * outdata, size_t outlen, const char * indata, size_t inlen, uint32_t verbose = 0)
        : out(outdata, outlen), in(indata, inlen), status(true), verbose(verbose)
    {
        strncpy(this->name, name, 254);
        this->name[255]=0;
    }

    using Transport::recv;
    virtual void recv(char ** pbuffer, size_t len) throw (Error) {
        if (this->status){
            this->out.recv(pbuffer, len);
            if (this->verbose & 0x100){
                LOG(LOG_INFO, "Recv done on %s (Test Data)", this->name);
                hexdump_c(*pbuffer - len, len);
                LOG(LOG_INFO, "Dump done on %s (Test Data)", this->name);
            }
        }
    }

    using Transport::send;
    virtual void send(const char * const buffer, size_t len) throw (Error) {
        if (this->status){
            if (this->verbose & 0x100){
                LOG(LOG_INFO, "Test Transport %s (Test Data) sending %u bytes", this->name, len);
                hexdump_c(buffer, len);
                LOG(LOG_INFO, "Dump done %s (Test Data) sending %u bytes", this->name, len);
            }
            this->in.send(buffer, len);
            this->status = this->in.status;
        }
    }
};

class OutFileTransport : public Transport {

    public:
    int fd;

    OutFileTransport(int fd) : Transport(), fd(fd) {}

    ~OutFileTransport() {}

    // recv is not implemented for OutFileTransport
    using Transport::recv;
    virtual void recv(char ** pbuffer, size_t len) throw (Error) {
        LOG(LOG_INFO, "OutFileTransport used for recv");
        throw Error(ERR_TRANSPORT_OUTPUT_ONLY_USED_FOR_RECV, 0);
    }

    using Transport::send;
    virtual void send(const char * const buffer, size_t len) throw (Error) {
        ssize_t status = 0;
        size_t remaining_len = len;
        size_t total_sent = 0;
        while (remaining_len) {
            status = ::write(this->fd, buffer + total_sent, remaining_len);
            if (status > 0){
                remaining_len -= status;
                total_sent += status;
            }
            else {
                if (errno == EINTR){
                    continue;
                }
                LOG(LOG_INFO, "Outfile transport write failed with error %s", strerror(errno));
                throw Error(ERR_TRANSPORT_WRITE_FAILED, errno);
            }
        }
    }

};

class InFileTransport : public Transport {

    public:
    int fd;

    InFileTransport(int fd)
        : Transport(), fd(fd)
    {
    }

    ~InFileTransport()
    {
    }

    using Transport::recv;
    virtual void recv(char ** pbuffer, size_t len) throw (Error) {
        size_t status = 0;
        size_t remaining_len = len;
        char * buffer = *pbuffer;
        while (remaining_len) {
            status = ::read(this->fd, buffer, remaining_len);
            if (status > 0){
                remaining_len -= status;
                buffer += status;
            }
            else {
                if (errno == EINTR){
                    continue;
                }
                *pbuffer = buffer;
                LOG(LOG_INFO, "Infile transport read failed with error %s", strerror(errno));
                throw Error(ERR_TRANSPORT_READ_FAILED, 0);
            }
        }
        *pbuffer = buffer;
    }

    // send is not implemented for InFileTransport
    using Transport::send;
    virtual void send(const char * const buffer, size_t len) throw (Error) {
        LOG(LOG_INFO, "InFileTransport used for writing");
        throw Error(ERR_TRANSPORT_INPUT_ONLY_USED_FOR_SEND, 0);
    }

};

TODO("for now loop transport is not yet implemented, it's a null transport")

class LoopTransport : public Transport {
    public:
    using Transport::recv;
    virtual void recv(char ** pbuffer, size_t len) throw (Error) {
    }
    using Transport::send;
    virtual void send(const char * const buffer, size_t len) throw (Error) {
    }
};

class SocketTransport : public Transport {
        bool tls;
        SSL * ssl;
    public:
        int sck;
        int sck_closed;
        const char * name;
        uint32_t verbose;

    SocketTransport(const char * name, int sck, uint32_t verbose)
        : Transport(), name(name), verbose(verbose)
    {
        this->ssl = NULL;
        this->tls = false;
        this->sck = sck;
        this->sck_closed = 0;
    }

    ~SocketTransport(){
        if (!this->sck_closed){
            this->disconnect();
        }
    }


    virtual void enable_tls() throw (Error)
    {
            //            tls::tls_verify_certificate
            //            crypto::x509_verify_certificate

            //                X509_STORE_CTX* csc;
            //                X509_STORE* cert_ctx = NULL;
            //                X509_LOOKUP* lookup = NULL;
            //                X509* xcert = cert->px509;
            //                cert_ctx = X509_STORE_new();
            //                OpenSSL_add_all_algorithms();
            //                lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
            //                lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
            //                X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
            //                X509_LOOKUP_add_dir(lookup, certificate_store_path, X509_FILETYPE_ASN1);
            //                csc = X509_STORE_CTX_new();
            //                X509_STORE_set_flags(cert_ctx, 0);
            //                X509_STORE_CTX_init(csc, cert_ctx, xcert, 0);
            //                X509_verify_cert(csc);
            //                X509_STORE_CTX_free(csc);
            //                X509_STORE_free(cert_ctx);

            //            crypto::x509_verify_certificate done
            //            crypto::crypto_get_certificate_data
            //            crypto::crypto_cert_fingerprint

            //                X509_digest(xcert, EVP_sha1(), fp, &fp_len);

            //            crypto::crypto_cert_fingerprint done
            //            crypto::crypto_get_certificate_data done
            //            crypto::crypto_cert_subject_common_name

            //                subject_name = X509_get_subject_name(xcert);
            //                index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
            //                entry = X509_NAME_get_entry(subject_name, index);
            //                entry_data = X509_NAME_ENTRY_get_data(entry);

            //            crypto::crypto_cert_subject_common_name done
            //            crypto::crypto_cert_subject_alt_name

            //                subject_alt_names = X509_get_ext_d2i(xcert, NID_subject_alt_name, 0, 0);

            //            crypto::crypto_cert_subject_alt_name (!subject_alt_names) done
            //            crypto::crypto_cert_issuer

            //                char * res = crypto_print_name(X509_get_issuer_name(xcert));

            //            crypto::crypto_print_name

            //                BIO* outBIO = BIO_new(BIO_s_mem());
            //                X509_NAME_print_ex(outBIO, name, 0, XN_FLAG_ONELINE)
            //                BIO_read(outBIO, buffer, size);
            //                BIO_free(outBIO);

            //            crypto::crypto_print_name done
            //            crypto::crypto_cert_issuer done
            //            crypto::crypto_cert_subject

            //                char * res = crypto_print_name(X509_get_subject_name(xcert));

            //            crypto::crypto_print_name

            //                BIO* outBIO = BIO_new(BIO_s_mem());
            //                X509_NAME_print_ex(outBIO, name, 0, XN_FLAG_ONELINE)
            //                BIO_read(outBIO, buffer, size);
            //                BIO_free(outBIO);

            //            crypto::crypto_print_name done
            //            crypto::crypto_cert_subject done
            //            crypto::crypto_cert_fingerprint


            //                X509_digest(xcert, EVP_sha1(), fp, &fp_len);

            //            crypto::crypto_cert_fingerprint done
            //            tls::tls_verify_certificate verification_status=1 done
            //            tls::tls_free_certificate

            //                X509_free(cert->px509);

            //            tls::tls_free_certificate done
            //            tls::tls_connect -> true done


        LOG(LOG_INFO, "Transport::enable_tls()");
        SSL_load_error_strings();
        SSL_library_init();

        LOG(LOG_INFO, "Transport::SSL_CTX_new()");
        SSL_CTX* ctx = SSL_CTX_new(TLSv1_client_method());

        /*
         * This is necessary, because the Microsoft TLS implementation is not perfect.
         * SSL_OP_ALL enables a couple of workarounds for buggy TLS implementations,
         * but the most important workaround being SSL_OP_TLS_BLOCK_PADDING_BUG.
         * As the size of the encrypted payload may give hints about its contents,
         * block padding is normally used, but the Microsoft TLS implementation
         * won't recognize it and will disconnect you after sending a TLS alert.
         */
        LOG(LOG_INFO, "Transport::SSL_CTX_set_options()");
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
        LOG(LOG_INFO, "Transport::SSL_new()");
        this->ssl = SSL_new(ctx);

        int flags = fcntl(this->sck, F_GETFL);
        fcntl(this->sck, F_SETFL, flags & ~(O_NONBLOCK));

        LOG(LOG_INFO, "Transport::SSL_set_fd()");
        SSL_set_fd(this->ssl, this->sck);
        LOG(LOG_INFO, "Transport::SSL_connect()");
        int connection_status = SSL_connect(ssl);

        if (connection_status <= 0)
        {
            unsigned long error;

            switch (SSL_get_error(this->ssl, connection_status))
            {
                case SSL_ERROR_ZERO_RETURN:
                    LOG(LOG_INFO, "Server closed TLS connection\n");
                    LOG(LOG_INFO, "tls::tls_print_error SSL_ERROR_ZERO_RETURN done\n");
                    break;

                case SSL_ERROR_WANT_READ:
                    LOG(LOG_INFO, "SSL_ERROR_WANT_READ\n");
                    LOG(LOG_INFO, "tls::tls_print_error SSL_ERROR_WANT_READ done\n");
                    break;

                case SSL_ERROR_WANT_WRITE:
                    LOG(LOG_INFO, "SSL_ERROR_WANT_WRITE\n");
                    LOG(LOG_INFO, "tls::tls_print_error SSL_ERROR_WANT_WRITE done\n");
                    break;

                case SSL_ERROR_SYSCALL:
                    LOG(LOG_INFO, "I/O error\n");
                    while ((error = ERR_get_error()) != 0)
                        LOG(LOG_INFO, "%s\n", ERR_error_string(error, NULL));
                    LOG(LOG_INFO, "tls::tls_print_error SSL_ERROR_SYSCLASS done\n");
                    break;

                case SSL_ERROR_SSL:
                    LOG(LOG_INFO, "Failure in SSL library (protocol error?)\n");
                    while ((error = ERR_get_error()) != 0)
                        LOG(LOG_INFO, "%s\n", ERR_error_string(error, NULL));
                    LOG(LOG_INFO, "tls::tls_print_error SSL_ERROR_SSL done\n");
                    break;

                default:
                    LOG(LOG_INFO, "Unknown error\n");
                    while ((error = ERR_get_error()) != 0)
                        LOG(LOG_INFO, "%s\n", ERR_error_string(error, NULL));
                    LOG(LOG_INFO, "tls::tls_print_error Unknown error done\n");
                    break;
            }
        }

        LOG(LOG_INFO, "Transport::SSL_get_peer_certificate()");
        X509 * px509 = SSL_get_peer_certificate(ssl);
        if (!px509)
        {
            LOG(LOG_INFO, "Transport::crypto_cert_get_public_key: SSL_get_peer_certificate() failed");
            exit(0);
        }

        LOG(LOG_INFO, "Transport::X509_get_pubkey()");
        EVP_PKEY* pkey = X509_get_pubkey(px509);
        if (!pkey)
        {
            LOG(LOG_INFO, "Transport::crypto_cert_get_public_key: X509_get_pubkey() failed");
            exit(0);
        }

        LOG(LOG_INFO, "Transport::i2d_PublicKey()");
        int public_key_length = i2d_PublicKey(pkey, NULL);
        LOG(LOG_INFO, "Transport::i2d_PublicKey() -> length = %u", public_key_length);
        uint8_t * public_key_data = (uint8_t *)malloc(public_key_length);
        LOG(LOG_INFO, "Transport::i2d_PublicKey()");
        i2d_PublicKey(pkey, &public_key_data);
        // verify_certificate -> ignore for now
        this->tls = true;
        LOG(LOG_INFO, "Transport::enable_tls() done");
    }

    static bool try_again(int errnum){
        int res = false;
        switch (errno){
            case EAGAIN:
            /* case EWOULDBLOCK: */ // same as EAGAIN on Linux
            case EINPROGRESS:
            case EALREADY:
            case EBUSY:
            case EINTR:
                res = true;
                break;
            default:
                ;
        }
        return res;
    }

    void disconnect(){
        LOG(LOG_INFO, "Socket %s (%d) : closing connection\n", this->name, this->sck);
        if (this->sck != 0) {
            shutdown(this->sck, 2);
            close(this->sck);
        }
        this->sck = 0;
        this->sck_closed = 1;
    }

    enum direction_t {
        NONE = 0,
        RECV = 1,
        SEND = 2
    };

    void wait_ready(direction_t d, int delay_ms) throw (Error)
    {
        fd_set fds;
        struct timeval time;

        time.tv_sec = delay_ms / 1000;
        time.tv_usec = (delay_ms * 1000) % 1000000;
        FD_ZERO(&fds);
        FD_SET(((unsigned int)this->sck), &fds);
        if (select(this->sck + 1,
            (d & RECV)? &fds : 0,
            (d & SEND)? &fds : 0,
            0, &time) > 0) {
            int opt = 0;
            unsigned int opt_len = sizeof(opt);
            getsockopt(this->sck, SOL_SOCKET, SO_ERROR, (char*)(&opt), &opt_len);
            // Test if we got a socket error

            if (opt) {
                LOG(LOG_INFO, "Socket error detected on %s : %s", this->name, strerror(errno));
                throw Error(ERR_SESSION_TERMINATED);
            }

        }
    }

    using Transport::recv;

    virtual void recv(char ** pbuffer, size_t len) throw (Error)
    {
        if (this->tls){
            this->recv_tls(pbuffer, len);
        }
        else {
            this->recv_tcp(pbuffer, len);
        }
    }

    void recv_tls(char ** input_buffer, size_t total_len) throw (Error)
    {
        if (this->verbose & 0x100){
            LOG(LOG_INFO, "TLS Socket %s (%u) receiving %u bytes", this->name, this->sck, total_len);
        }
        char * start = *input_buffer;
        size_t len = total_len;
        char * pbuffer = *input_buffer;
        unsigned long error;

        if (this->sck_closed) {
            LOG(LOG_INFO, "TLS Socket %s (%u) already closed", this->name, this->sck);
            throw Error(ERR_SOCKET_ALLREADY_CLOSED);
        }

        while (len > 0) {
            ssize_t rcvd = ::SSL_read(this->ssl, pbuffer, len);
            switch (rcvd) {
                case -1: /* error, maybe EAGAIN */
                    switch (SSL_get_error(this->ssl, rcvd))
                    {
                        case SSL_ERROR_NONE:
                            LOG(LOG_INFO, "send_tls ERROR NONE");
                            break;

                        case SSL_ERROR_WANT_READ:
                            LOG(LOG_INFO, "send_tls WANT READ");
                            break;

                        case SSL_ERROR_WANT_WRITE:
                            LOG(LOG_INFO, "send_tls WANT WRITE");
                            break;

                        default:
                            LOG(LOG_INFO, "Failure in SSL library (protocol error?)");
                            while ((error = ERR_get_error()) != 0)
                                LOG(LOG_INFO, "%s", ERR_error_string(error, NULL));
                            LOG(LOG_INFO, "Closing socket %s (%u) on recv", this->name, this->sck);
                            this->sck_closed = 1;
                            throw Error(ERR_SOCKET_ERROR, errno);
                    }
                    break;
                case 0: /* no data received, socket closed */
                    LOG(LOG_INFO, "No data received. TLS Socket %s (%u) closed on recv", this->name, this->sck);
                    this->sck_closed = 1;
                    throw Error(ERR_SOCKET_CLOSED);
                default: /* some data received */
                    pbuffer += rcvd;
                    len -= rcvd;
            }
        }

        if (this->verbose & 0x100){
            LOG(LOG_INFO, "Recv done on %s (%u)", this->name, this->sck);
            hexdump_c(start, total_len);
            LOG(LOG_INFO, "Dump done on %s (%u)", this->name, this->sck);
        }
        *input_buffer = pbuffer;
        total_received += total_len;
        last_quantum_received += total_len;
    }

    void recv_tcp(char ** input_buffer, size_t total_len) throw (Error)
    {
        if (this->verbose & 0x100){
            LOG(LOG_INFO, "Socket %s (%u) receiving %u bytes", this->name, this->sck, total_len);
        }
        char * start = *input_buffer;
        size_t len = total_len;
        char * pbuffer = *input_buffer;

        if (this->sck_closed) {
            LOG(LOG_INFO, "Socket %s (%u) already closed", this->name, this->sck);
            throw Error(ERR_SOCKET_ALLREADY_CLOSED);
        }

        while (len > 0) {
            ssize_t rcvd = ::recv(this->sck, pbuffer, len, 0);
            switch (rcvd) {
                case -1: /* error, maybe EAGAIN */
                    if (!this->try_again(errno)) {
                        LOG(LOG_INFO, "Closing socket %s (%u) on recv", this->name, this->sck);
                        this->sck_closed = 1;
                        throw Error(ERR_SOCKET_ERROR, errno);
                    }
                    this->wait_ready(RECV, 10);
                    break;
                case 0: /* no data received, socket closed */
                    LOG(LOG_INFO, "No data received. Socket %s (%u) closed on recv", this->name, this->sck);
                    this->sck_closed = 1;
                    throw Error(ERR_SOCKET_CLOSED);
                default: /* some data received */
                    pbuffer += rcvd;
                    len -= rcvd;
            }
        }

        if (this->verbose & 0x100){
            LOG(LOG_INFO, "Recv done on %s (%u)", this->name, this->sck);
            hexdump_c(start, total_len);
            LOG(LOG_INFO, "Dump done on %s (%u)", this->name, this->sck);
        }

        *input_buffer = pbuffer;
        total_received += total_len;
        last_quantum_received += total_len;
    }



    using Transport::send;

    virtual void send(const char * const buffer, size_t len) throw (Error)
    {
        if (this->tls){
            this->send_tls(buffer, len);
        }
        else {
            this->send_tcp(buffer, len);
        }
    }

    void send_tls(const char * const buffer, size_t len) throw (Error)
    {
        if (this->verbose & 0x100){
            LOG(LOG_INFO, "TLS Socket %s (%u) sending %u bytes", this->name, this->sck, len);
            hexdump_c(buffer, len);
            LOG(LOG_INFO, "TLS Dump done %s (%u) sending %u bytes", this->name, this->sck, len);
        }

        if (this->sck_closed) {
            LOG(LOG_INFO, "Socket already closed on %s (%u)", this->name, this->sck);
            throw Error(ERR_SOCKET_ALLREADY_CLOSED);
        }

        int status = SSL_write(this->ssl, buffer, len);

        unsigned long error;
        switch (SSL_get_error(this->ssl, status))
        {
            case SSL_ERROR_NONE:
                LOG(LOG_INFO, "send_tls ERROR NONE");
                break;

            case SSL_ERROR_WANT_READ:
                LOG(LOG_INFO, "send_tls WANT READ");
                break;

            case SSL_ERROR_WANT_WRITE:
                LOG(LOG_INFO, "send_tls WANT WRITE");
                break;

            default:
                LOG(LOG_INFO, "Failure in SSL library (protocol error?)");
                while ((error = ERR_get_error()) != 0)
                    LOG(LOG_INFO, "%s", ERR_error_string(error, NULL));
                break;
        }

        total_sent += len;
        last_quantum_sent += len;

        if (this->verbose & 0x100){
            LOG(LOG_INFO, "TLS Send done on %s (%u)", this->name, this->sck);
        }

    }

    void send_tcp(const char * const buffer, size_t len) throw (Error)
    {
        if (this->verbose & 0x100){
            LOG(LOG_INFO, "Socket %s (%u) sending %u bytes", this->name, this->sck, len);
            hexdump_c(buffer, len);
            LOG(LOG_INFO, "Dump done %s (%u) sending %u bytes", this->name, this->sck, len);
        }
        if (this->sck_closed) {
            LOG(LOG_INFO, "Socket already closed on %s (%u)", this->name, this->sck);
            throw Error(ERR_SOCKET_ALLREADY_CLOSED);
        }
        size_t total = 0;
        while (total < len) {
            ssize_t sent = ::send(this->sck, buffer + total, len - total, 0);
            switch (sent){
            case -1:
                if (!this->try_again(errno)) {
                    this->sck_closed = 1;
                    LOG(LOG_INFO, "Socket %s (%u) : %s", this->name, this->sck, strerror(errno));
                    throw Error(ERR_SOCKET_ERROR, errno);
                }
                this->wait_ready(SEND, 10);
                break;
            case 0:
                this->sck_closed = 1;
                LOG(LOG_INFO, "Socket %s (%u) closed on sending : %s", this->name, this->sck, strerror(errno));
                throw Error(ERR_SOCKET_CLOSED, errno);
            default:
                total = total + sent;
            }
        }
        total_sent += len;
        last_quantum_sent += len;
        if (this->verbose & 0x100){
            LOG(LOG_INFO, "Send done on %s (%u)", this->name, this->sck);
        }
    }

    private:

};

#endif
