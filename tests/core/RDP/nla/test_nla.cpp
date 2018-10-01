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

#define RED_TEST_MODULE TestNLA
#include "system/redemption_unit_tests.hpp"

#include "core/RDP/nla/nla.hpp"
#include "core/RDP/tpdu_buffer.hpp"

#include "test_only/transport/test_transport.hpp"

#include "test_only/lcg_random.hpp"

RED_AUTO_TEST_CASE(TestNlaclient)
{
    const char client[] =
        // negotiate
    "\x30\x37\xa0\x03\x02\x01\x06\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04" //07......00.0,.*. !
    "\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\xb7\x82\x08" //(NTLMSSP........ !
    "\xe2\x00\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00" //.....(.......(.. !
    "\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f" //......... !
        // authenticate
    "\x30\x82\x01\x59\xa0\x03\x02\x01\x06\xa1\x82\x01\x2c\x30\x82\x01" //0..Y........,0.. !
    "\x28\x30\x82\x01\x24\xa0\x82\x01\x20\x04\x82\x01\x1c\x4e\x54\x4c" //(0..$... ....NTL !
    "\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x18\x00\x18\x00\x58\x00\x00" //MSSP.........X.. !
    "\x00\x70\x00\x70\x00\x70\x00\x00\x00\x0e\x00\x0e\x00\xe0\x00\x00" //.p.p.p.......... !
    "\x00\x0c\x00\x0c\x00\xee\x00\x00\x00\x12\x00\x12\x00\xfa\x00\x00" //................ !
    "\x00\x10\x00\x10\x00\x0c\x01\x00\x00\x35\xa2\x88\xe2\x06\x01\xb1" //.........5...... !
    "\x1d\x00\x00\x00\x0f\x9d\x98\xe1\x30\xdc\x7a\xce\x81\xa9\x7a\x11" //........0.z...z. !
    "\x14\x7d\x5d\x73\xd0\x34\xbe\xb5\x6e\xce\xec\x0a\x50\x2d\x29\x63" //.}]s.4..n...P-)c !
    "\x7f\xcc\x5e\xe7\x18\xb8\x6c\xda\xa6\xf0\xf6\x30\x8d\xa6\x41\xcc" //.^...l....0..A. !
    "\x7a\x52\x8e\x7a\xb3\x06\x7d\x0b\xe0\x00\xd5\xf6\x13\x01\x01\x00" //zR.z..}......... !
    "\x00\x00\x00\x00\x00\x67\x95\x0e\x5a\x4e\x56\x76\xd6\xb8\x6c\xda" //.....g..ZNVv..l. !
    "\xa6\xf0\xf6\x30\x8d\x00\x00\x00\x00\x01\x00\x08\x00\x57\x00\x49" //...0.........W.I !
    "\x00\x4e\x00\x37\x00\x02\x00\x08\x00\x57\x00\x49\x00\x4e\x00\x37" //.N.7.....W.I.N.7 !
    "\x00\x03\x00\x08\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x04\x00\x08" //.....w.i.n.7.... !
    "\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x07\x00\x08\x00\x67\x95\x0e" //.w.i.n.7.....g.. !
    "\x5a\x4e\x56\x76\xd6\x00\x00\x00\x00\x00\x00\x00\x00\x49\x00\x74" //ZNVv.........I.t !
    "\x00\x68\x00\x61\x00\x71\x00\x75\x00\x65\x00\x55\x00\x6c\x00\x79" //.h.a.q.u.e.U.l.y !
    "\x00\x73\x00\x73\x00\x65\x00\x54\x00\xe9\x00\x6c\x00\xe9\x00\x6d" //.s.s.e.T...l...m !
    "\x00\x61\x00\x71\x00\x75\x00\x65\x00\x44\xbc\x4d\x7a\x13\x3f\x6b" //.a.q.u.e.D.Mz.?k !
    "\x81\xdb\x1d\x2b\x7b\xbf\x1e\x18\x0f\xa3\x22\x04\x20\x01\x00\x00" //...+{.....". ... !
    "\x00\x89\xe2\xda\x48\x17\x29\xb5\x08\x00\x00\x00\x00\x20\x59\x27" //....H.)...... Y' !
    "\x3f\x08\xd0\xc2\xe4\x75\x66\x10\x49\x7b\xbd\x8d\xf7" //?....uf.I{... !]
//         // ts credentials (authinfo)
/* 0000 */ "\x30\x5c\xa0\x03\x02\x01\x06\xa2\x55\x04\x53\x01\x00\x00\x00\xaf" // 0.......U.S.....
/* 0010 */ "\xad\x46\x2a\x6a\x9d\xf7\x88\x01\x00\x00\x00\xd5\x4f\xc8\xd0\xbd" // .F*j........O...
/* 0020 */ "\x89\x60\xe0\x71\x60\x31\x7a\xcc\xec\xc5\xbf\x23\x4b\xe5\xf9\xa5" // .`.q`1z....#K...
/* 0030 */ "\x8c\x21\x66\xa6\x78\xda\xd1\xbd\xef\xa4\xfd\x47\xa6\xf1\x56\xa5" // .!f.x......G..V.
/* 0040 */ "\xd9\x52\x72\x92\xfa\x41\xa5\xb4\x9d\x94\xfb\x0e\xe2\x61\xba\xfc" // .Rr..A.......a..
/* 0050 */ "\xd5\xf3\xa7\xb5\x33\xd5\x62\x8d\x93\x18\x54\x39\x8a\xe7"         // ....3.b...T9..
        ;

    const char server[] =
        // challenge

/* 0000 */ "\x30\x81\x88\xa0\x03\x02\x01\x02\xa1\x81\x80\x30\x7e\x30\x7c\xa0" //0..........0~0|.
/* 0010 */ "\x7a\x04\x78\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x00" //z.xNTLMSSP......
/* 0020 */ "\x00\x00\x00\x38\x00\x00\x00\xb7\x82\x08\xe2\xb8\x6c\xda\xa6\xf0" //...8........l...
/* 0030 */ "\xf6\x30\x8d\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x40\x00\x38" //.0.........@.@.8
/* 0040 */ "\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x01\x00\x08\x00\x57" //.....(.........W
/* 0050 */ "\x00\x49\x00\x4e\x00\x37\x00\x02\x00\x08\x00\x57\x00\x49\x00\x4e" //.I.N.7.....W.I.N
/* 0060 */ "\x00\x37\x00\x03\x00\x08\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x04" //.7.....w.i.n.7..
/* 0070 */ "\x00\x08\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x07\x00\x08\x00\x67" //...w.i.n.7.....g
/* 0080 */ "\x95\x0e\x5a\x4e\x56\x76\xd6\x00\x00\x00\x00"                     //..ZNVv.....

        // pubauthkey
/* 0000 */ "\x30\x29\xa0\x03\x02\x01\x02\xa3\x22\x04\x20\x01\x00\x00\x00\xa2" //0)......". .....
/* 0010 */ "\xe0\x5b\x50\x97\x8e\x99\x27\x00\x00\x00\x00\xdc\xa7\x0b\xfe\x37" //.[P...'........7
/* 0020 */ "\x45\x3d\x1b\x05\x15\xce\x56\x0a\x54\xa1\xf1"                     //E=....V.T..
        ;

    LOG(LOG_INFO, "TEST CLIENT SIDE");

    TestTransport logtrans(server, sizeof(server)-1, client, sizeof(client)-1);
    logtrans.set_public_key(byte_ptr_cast("1245789652325415"), 16);
    uint8_t user[] = "Ulysse";
    uint8_t domain[] = "Ithaque";
    uint8_t pass[] = "Pénélope";
    uint8_t host[] = "Télémaque";
    LCGRandom rand(0);
    LCGTime timeobj;
    std::string extra_message;
    Translation::language_t lang = Translation::EN;
    rdpCredsspClient credssp(logtrans, user, domain, pass, host, "107.0.0.1", false, false, rand, timeobj, extra_message, lang);
    RED_CHECK(credssp.credssp_client_authenticate_init());

    rdpCredsspClient::State st = rdpCredsspClient::State::Cont;
    TpduBuffer buf;
    while (rdpCredsspClient::State::Cont == st) {
        buf.load_data(logtrans);
        while (buf.next_credssp() && rdpCredsspClient::State::Cont == st) {
            InStream in_stream(buf.current_pdu_buffer());
            st = credssp.credssp_client_authenticate_next(in_stream);
        }
    }
    RED_CHECK_EQUAL(0, buf.remaining());
    RED_CHECK_EQUAL(st, rdpCredsspClient::State::Finish);
}



RED_AUTO_TEST_CASE(TestNlaserver)
{
    const char client[] =
        // negotiate
    "\x30\x37\xa0\x03\x02\x01\x06\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04" //07......00.0,.*. !
    "\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\xb7\x82\x08" //(NTLMSSP........ !
    "\xe2\x00\x00\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00" //.....(.......(.. !
    "\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f" //......... !
        // authenticate + pubauthkey
    "\x30\x82\x01\x59\xa0\x03\x02\x01\x02\xa1\x82\x01\x2c\x30\x82\x01" //0..Y........,0.. !
    "\x28\x30\x82\x01\x24\xa0\x82\x01\x20\x04\x82\x01\x1c\x4e\x54\x4c" //(0..$... ....NTL !
    "\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x18\x00\x18\x00\x58\x00\x00" //MSSP.........X.. !
    "\x00\x70\x00\x70\x00\x70\x00\x00\x00\x0e\x00\x0e\x00\xe0\x00\x00" //.p.p.p.......... !
    "\x00\x0c\x00\x0c\x00\xee\x00\x00\x00\x12\x00\x12\x00\xfa\x00\x00" //................ !
    "\x00\x10\x00\x10\x00\x0c\x01\x00\x00\x35\xa2\x88\xe2\x06\x01\xb1" //.........5...... !
    "\x1d\x00\x00\x00\x0f\x2e\x5b\xe2\x1f\x57\x20\x79\xa8\x5c\x70\x2d" //......[..W y..p- !
    "\x3d\xb6\x46\x81\x9a\x34\xbe\xb5\x6e\xce\xec\x0a\x50\x2d\x29\x63" //=.F..4..n...P-)c !
    "\x7f\xcc\x5e\xe7\x18\xb8\x6c\xda\xa6\xf0\xf6\x30\x8d\xa6\x41\xcc" //.^...l....0..A. !
    "\x7a\x52\x8e\x7a\xb3\x06\x7d\x0b\xe0\x00\xd5\xf6\x13\x01\x01\x00" //zR.z..}......... !
    "\x00\x00\x00\x00\x00\x67\x95\x0e\x5a\x4e\x56\x76\xd6\xb8\x6c\xda" //.....g..ZNVv..l. !
    "\xa6\xf0\xf6\x30\x8d\x00\x00\x00\x00\x01\x00\x08\x00\x57\x00\x49" //...0.........W.I !
    "\x00\x4e\x00\x37\x00\x02\x00\x08\x00\x57\x00\x49\x00\x4e\x00\x37" //.N.7.....W.I.N.7 !
    "\x00\x03\x00\x08\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x04\x00\x08" //.....w.i.n.7.... !
    "\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x07\x00\x08\x00\x67\x95\x0e" //.w.i.n.7.....g.. !
    "\x5a\x4e\x56\x76\xd6\x00\x00\x00\x00\x00\x00\x00\x00\x49\x00\x74" //ZNVv.........I.t !
    "\x00\x68\x00\x61\x00\x71\x00\x75\x00\x65\x00\x55\x00\x6c\x00\x79" //.h.a.q.u.e.U.l.y !
    "\x00\x73\x00\x73\x00\x65\x00\x54\x00\xe9\x00\x6c\x00\xe9\x00\x6d" //.s.s.e.T...l...m !
    "\x00\x61\x00\x71\x00\x75\x00\x65\x00\x44\xbc\x4d\x7a\x13\x3f\x6b" //.a.q.u.e.D.Mz.?k !
    "\x81\xdb\x1d\x2b\x7b\xbf\x1e\x18\x0f\xa3\x22\x04\x20\x01\x00\x00" //...+{.....". ... !
    "\x00\x89\xe2\xda\x48\x17\x29\xb5\x08\x00\x00\x00\x00\x20\x59\x27" //....H.)...... Y' !
    "\x3f\x08\xd0\xc2\xe4\x75\x66\x10\x49\x7b\xbd\x8d\xf7" //?....uf.I{... !]

        // ts credentials (authinfo)
/* 0000 */ "\x30\x5c\xa0\x03\x02\x01\x02\xa2\x55\x04\x53\x01\x00\x00\x00\xaf" // 0.......U.S.....
/* 0010 */ "\xad\x46\x2a\x6a\x9d\xf7\x88\x01\x00\x00\x00\xd5\x4f\xc8\xd0\xbd" // .F*j........O...
/* 0020 */ "\x89\x60\xe0\x71\x60\x31\x7a\xcc\xec\xc5\xbf\x23\x4b\xe5\xf9\xa5" // .`.q`1z....#K...
/* 0030 */ "\x8c\x21\x66\xa6\x78\xda\xd1\xbd\xef\xa4\xfd\x47\xa6\xf1\x56\xa5" // .!f.x......G..V.
/* 0040 */ "\xd9\x52\x72\x92\xfa\x41\xa5\xb4\x9d\x94\xfb\x0e\xe2\x61\xba\xfc" // .Rr..A.......a..
/* 0050 */ "\xd5\xf3\xa7\xb5\x33\xd5\x62\x8d\x93\x18\x54\x39\x8a\xe7"         // ....3.b...T9..

        ;

    const char server[] =
        // challenge
    "\x30\x81\x88\xa0\x03\x02\x01\x06\xa1\x81\x80\x30\x7e\x30\x7c\xa0" //0..........0~0|. !
    "\x7a\x04\x78\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x00" //z.xNTLMSSP...... !
    "\x00\x00\x00\x38\x00\x00\x00\xb7\x82\x08\xe2\xb8\x6c\xda\xa6\xf0" //...8........l... !
    "\xf6\x30\x8d\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x40\x00\x38" //.0.........@.@.8 !
    "\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f\x01\x00\x08\x00\x57" //...............W !
    "\x00\x49\x00\x4e\x00\x37\x00\x02\x00\x08\x00\x57\x00\x49\x00\x4e" //.I.N.7.....W.I.N !
    "\x00\x37\x00\x03\x00\x08\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x04" //.7.....w.i.n.7.. !
    "\x00\x08\x00\x77\x00\x69\x00\x6e\x00\x37\x00\x07\x00\x08\x00\x67" //...w.i.n.7.....g !
    "\x95\x0e\x5a\x4e\x56\x76\xd6\x00\x00\x00\x00" //..ZNVv..... !]
//         // pubauthkey
/* 0000 */ "\x30\x29\xa0\x03\x02\x01\x06\xa3\x22\x04\x20\x01\x00\x00\x00\xa2" //0)......". .....
/* 0010 */ "\xe0\x5b\x50\x97\x8e\x99\x27\x00\x00\x00\x00\xdc\xa7\x0b\xfe\x37" //.[P...'........7
/* 0020 */ "\x45\x3d\x1b\x05\x15\xce\x56\x0a\x54\xa1\xf1"                     //E=....V.T..
        ;

    LOG(LOG_INFO, "TEST SERVER SIDE");
    TestTransport logtrans(client, sizeof(client)-1, server, sizeof(server)-1);
    logtrans.set_public_key(byte_ptr_cast("1245789652325415"), 16);
    uint8_t user[] = "Ulysse";
    uint8_t domain[] = "Ithaque";
    uint8_t pass[] = "Pénélope";
    uint8_t host[] = "Télémaque";
    LCGRandom rand(0);
    LCGTime timeobj;
    std::string extra_message;
    Translation::language_t lang = Translation::EN;
    rdpCredsspServer credssp(
        logtrans, false, false, rand, timeobj, extra_message, lang,
        [&](SEC_WINNT_AUTH_IDENTITY& identity){
            auto arr2av = [&](Array& arr){ return make_array_view(arr.get_data(), arr.size()); };
            std::vector<uint8_t> vec;
            vec.resize((std::size(user) - 1) * 2);
            UTF8toUTF16(user, vec.data(), vec.size());
            RED_CHECK_MEM_AA(arr2av(identity.User), vec);
            vec.resize((std::size(domain) - 1) * 2);
            UTF8toUTF16(domain, vec.data(), vec.size());
            RED_CHECK_MEM_AA(arr2av(identity.Domain), vec);
            identity.SetPasswordFromUtf8(pass);
            return Ntlm_SecurityFunctionTable::PasswordCallback::Ok;
        }
    );
    credssp.set_credentials(user, domain, pass, host);
    RED_CHECK(credssp.credssp_server_authenticate_init());

    rdpCredsspServer::State st = rdpCredsspServer::State::Cont;
    TpduBuffer buf;
    while (rdpCredsspServer::State::Cont == st) {
        buf.load_data(logtrans);
        while (buf.next_credssp() && rdpCredsspServer::State::Cont == st) {
            InStream in_stream(buf.current_pdu_buffer());
            st = credssp.credssp_server_authenticate_next(in_stream);
        }
    }
    RED_CHECK_EQUAL(0, buf.remaining());
    RED_CHECK_EQUAL(st, rdpCredsspServer::State::Finish);
}
