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
Copyright (C) Wallix 2010-2018
Author(s): Jonathan Poelen
*/

#ifdef IN_IDE_PARSER
# define REDEMPTION_UNIT_TEST_CPP
#endif

#include "./redemption_unit_tests.hpp"
#include "cxx/cxx.hpp"

#include <boost/test/results_collector.hpp>
// #include <boost/test/results_reporter.hpp>
#include <boost/test/framework.hpp>

#include <algorithm>
#include <ostream>
#include <iomanip>


namespace redemption_unit_test__
{
    unsigned long current_count_error()
    {
        using boost::unit_test::results_collector;
        using boost::unit_test::framework::current_test_case;
        using boost::unit_test::test_case;
        using boost::unit_test::test_results;
        return results_collector.results(current_test_case().p_id).p_assertions_failed.get();
    }

    // std::ostream& current_stream()
    // {
    //     return boost::unit_test::results_reporter::get_stream();
    // }

    bool compare_bytes(size_t& pos, bytes_view b, bytes_view a) noexcept
    {
        pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();
        return pos == a.size() && a.size() == b.size();
    }

    // based on element_compare from boost/test/tools/collection_comparison_op.hpp
    boost::test_tools::assertion_result bytes_EQ(bytes_view a, bytes_view b, char pattern)
    {
        size_t pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();

        boost::test_tools::assertion_result ar(true);

        const bool r = pos != a.size() || a.size() != b.size();
        if (REDEMPTION_UNLIKELY(r))
        {
            ar = false;

            ar.message() << "[" << Put2Mem{pos, a, b, pattern, " == "};
            ar.message() << "\nMismatch at position " << pos;

            if (a.size() != b.size())
            {
                ar.message()
                    << "\nCollections size mismatch: "
                    << a.size() << " != " << b.size()
                ;
            }
        }

        return ar;
    }

    boost::test_tools::assertion_result bytes_NE(bytes_view a, bytes_view b, char pattern)
    {
        size_t pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();

        boost::test_tools::assertion_result ar(true);

        const bool r = pos == a.size() && a.size() == b.size();
        if (REDEMPTION_UNLIKELY(r))
        {
            ar = false;
            ar.message() << "[" << Put2Mem{pos, a, b, pattern, " != "};
        }

        return ar;
    }

    boost::test_tools::assertion_result bytes_LT(bytes_view a, bytes_view b, char pattern)
    {
        size_t pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();

        boost::test_tools::assertion_result ar(true);

        const bool r = (pos == a.size())
            ? a.size() < b.size()
            : (pos != b.size() && a[pos] < b[pos]);
        if (REDEMPTION_UNLIKELY(r))
        {
            ar = false;
            ar.message() << "[" << Put2Mem{pos, a, b, pattern, " >= "};
            ar.message() << "\nMismatch at position " << pos;
        }

        return ar;
    }

    boost::test_tools::assertion_result bytes_LE(bytes_view a, bytes_view b, char pattern)
    {
        size_t pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();

        boost::test_tools::assertion_result ar(true);

        const bool r = (pos == a.size())
            ? a.size() <= b.size()
            : (pos != b.size() && a[pos] <= b[pos]);
        if (REDEMPTION_UNLIKELY(r))
        {
            ar = false;
            ar.message() << "[" << Put2Mem{pos, a, b, pattern, " > "};
            ar.message() << "\nMismatch at position " << pos;
        }

        return ar;
    }

    boost::test_tools::assertion_result bytes_GT(bytes_view a, bytes_view b, char pattern)
    {
        size_t pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();

        boost::test_tools::assertion_result ar(true);

        const bool r = (pos == a.size())
            ? a.size() > b.size()
            : (pos != b.size() && a[pos] > b[pos]);
        if (REDEMPTION_UNLIKELY(r))
        {
            ar = false;
            ar.message() << "[" << Put2Mem{pos, a, b, pattern, " <= "};
            ar.message() << "\nMismatch at position " << pos;
        }

        return ar;
    }

    boost::test_tools::assertion_result bytes_GE(bytes_view a, bytes_view b, char pattern)
    {
        size_t pos = std::mismatch(a.begin(), a.end(), b.begin(), b.end()).first - a.begin();

        boost::test_tools::assertion_result ar(true);

        const bool r = (pos == a.size())
            ? a.size() >= b.size()
            : (pos != b.size() && a[pos] >= b[pos]);
        if (REDEMPTION_UNLIKELY(r))
        {
            ar = false;
            ar.message() << "[" << Put2Mem{pos, a, b, pattern, " < "};
            ar.message() << "\nMismatch at position " << pos;
        }

        return ar;
    }

    namespace
    {
        constexpr uint8_t utf8_byte_size_table[] {
            // 0xxx x[xxx]
            1, 1, 1, 1,
            1, 1, 1, 1,
            1, 1, 1, 1,
            1, 1, 1, 1,
            // 10xx x[xxx]  invalid value
            0, 0, 0, 0,
            0, 0, 0, 0,
            // 110x x[xxx]  2 bytes
            2, 2, 2, 2,
            // 1110 x[xxx]  3 bytes
            0, 0,
            // 1111 0[xxx]  4 bytes
            0,
            // 1111 1[xxx]  invalid value
            0,
        };

        using N0 = std::integral_constant<std::size_t, 0>;
        using N1 = std::integral_constant<std::size_t, 1>;
        using N2 = std::integral_constant<std::size_t, 2>;
        using N3 = std::integral_constant<std::size_t, 3>;
        using N4 = std::integral_constant<std::size_t, 4>;

        template<class Size, class F>
        void utf8_char_process(byte_ptr v, Size size, F&& f)
        {
            switch (utf8_byte_size_table[v[0] >> 3]) {
                case 0: return f(N0{});
                case 1: return f(N1{});
                case 2: return size >= 2 && (v[1] >> 6) == 0b10 ? f(N2{}) : f(N0{});
                // case 3:
                //     if (size < 3 || (v[2] >> 6) != 0b10) {
                //         return f(N0{});
                //     }
                //     switch (v[0] & 0b1111) {
                //         case 0: return (v[1] >> 5) == 0b101 ? f(N3{}) : f(N0{});
                //         case 0b1101: return (v[1] >> 5) == 0b100 ? f(N3{}) : f(N0{});
                //         default: return (v[1] >> 6) == 0b10 ? f(N3{}) : f(N0{});
                //     }
                // case 4:
                //     if (size < 4 || (v[2] >> 6) != 0b10 || (v[3] >> 6) != 0b10) {
                //         return f(N0{});
                //     }
                //     switch (v[0] & 0b111) {
                //         case 0b000: return (v[1] >> 6) == 0b10 && (v[1] >> 4) != 0b1000 ? f(N4{}) : f(N0{});
                //         case 0b001:
                //         case 0b010:
                //         case 0b011: return (v[1] >> 6) == 0b10 ? f(N4{}) : f(N0{});
                //         case 0b100: return (v[1] >> 4) == 0b1000 ? f(N4{}) : f(N0{});
                //         default: return f(N0{});
                //     }
            }

            REDEMPTION_UNREACHABLE();
        }
    }

    static bool is_printable_ascii(uint8_t c)
    {
        return 0x20 <= c && c < 127;
    }

    static void put_char(std::ostream& out, uint8_t c, char const* newline = "\\n")
    {
        if (is_printable_ascii(c)) {
            out << char(c);
        }
        else {
            char const * hex_table = "0123456789abcdef";
            switch (c) {
                case ' ':
                case '!': out << char(c); break;
                case '"': out << "\\\""; break;
                case '\b': out << "\\b"; break;
                case '\t': out << "\\t"; break;
                case '\r': out << "\\r"; break;
                case '\n': out << newline; break;
                default: out << "\\x" << hex_table[c >> 4] << hex_table[c & 0xf];
            }
        }
    }

    static std::ostream& put_dump_bytes(size_t pos, std::ostream& out, bytes_view x)
    {
        if (x.size() == 0){
            return out << "\"\"\n";
        }
        char const * hex_table = "0123456789abcdef";
        size_t q = 0;
        size_t split = 16;
        uint8_t tmpbuf[16];
        size_t i = 0;
        for (unsigned c : x) {
            if (q%split == 0){
                if (x.size()>split){
                    out << "\n\"";
                }
                else {
                    out << "\"";
                }
            }
            if (q++ == pos){ out << "\x1b[35m";}
            out << "\\x" << hex_table[c >> 4] << hex_table[c & 0xf];
            tmpbuf[i++] = c;
            if (q%split == 0){
                if (x.size()>split) {
                    out << "\" //";
                    for (size_t v = 0 ; v < i ; v++){
                        if (is_printable_ascii(tmpbuf[v])) {
                            out << char(tmpbuf[v]);
                        }
                        else {
                            out << ".";
                        }
                    }
                    out << " !";
                    i = 0;
                }
                else {
                    out << "\"";
                }
            }
        }
        if (q%split != 0){
            if (x.size()>split) {
                out << "\" "
                    << std::setfill(' ')
                    << std::setw((split - q % split) * 4 + 2)
                    << "//";
                for (size_t v = 0 ; v < i ; v++){
                    if (is_printable_ascii(tmpbuf[v])) {
                        out << char(tmpbuf[v]);
                    }
                    else {
                        out << ".";
                    }
                }
                out << " !";
            }
            else {
                out << "\"";
            }
        }
        return out << "\x1b[0m";
    }

    static void put_utf8_bytes(size_t pos, std::ostream& out, bytes_view v, char const* newline = "\\n")
    {
        auto print = [&](bytes_view x, bool is_markable){
            auto* p = x.as_u8p();
            auto* end = p + x.size();

            auto consume_char = [&](auto f0){
                utf8_char_process(p, end-p, [&](std::size_t n){
                    if (n == 0) {
                        f0();
                        put_char(out, *p, newline);
                        ++p;
                    }
                    else if (n == 1) {
                        put_char(out, *p, newline);
                        ++p;
                    }
                    else {
                        out.write(char_ptr_cast(p), n);
                        p += n;
                    }
                });
            };

            while (p < end) {
                consume_char([]{});
            }

            if (is_markable) {
                out << "\x1b[35m";
            }
        };

        print(v.first(pos), pos != v.size());
        if (pos != v.size()) {
            out << "\x1b[35m";
            print(v.from_offset(pos), false);
            out << "\x1b[0m";
        }
    }

    static void put_utf8_bytes2(size_t pos, std::ostream& out, bytes_view v)
    {
        put_utf8_bytes(pos, out, v, "\n");
    }

    static void put_ascii_bytes(size_t pos, std::ostream& out, bytes_view v, char const* newline = "\\n")
    {
        auto print = [&](bytes_view x){
            for (uint8_t c : x) {
                if (is_printable_ascii(c)) {
                    out << char(c);
                }
                else {
                    put_char(out, c, newline);
                }
            }
        };

        print(v.first(pos));
        if (pos != v.size()) {
            out << "\x1b[35m";
            print(v.from_offset(pos));
            out << "\x1b[0m";
        }
    }

    static void put_ascii_bytes2(size_t pos, std::ostream& out, bytes_view v)
    {
        put_ascii_bytes(pos, out, v, "\n");
    }

    static void put_hex_bytes(size_t pos, std::ostream& out, bytes_view v)
    {
        char const * hex_table = "0123456789abcdef";
        auto print = [&](bytes_view x){
            for (uint8_t c : x) {
                out << "\\x" << hex_table[c >> 4] << hex_table[c & 0xf];
            }
        };

        print(v.first(pos));
        if (pos != v.size()) {
            out << "\x1b[35m";
            print(v.from_offset(pos));
            out << "\x1b[0m";
        }
    }

    static void put_auto_bytes(size_t pos, std::ostream& out, bytes_view v)
    {
        auto n = std::min(int(v.size()), 36);
        auto* p = v.as_u8p();
        auto* end = p + n;
        int count_invalid = 0;
        while (p < end) {
            utf8_char_process(p, end-p, [&](std::size_t n){
                if (n == 0) {
                    ++count_invalid;
                    ++p;
                }
                else {
                    if (n == 1 && !is_printable_ascii(*p)) {
                        ++count_invalid;
                    }
                    p += n;
                }
            });
        }

        if (count_invalid > n / 6) {
            put_ascii_bytes(pos, out, v);
        }
        else {
            put_utf8_bytes(pos, out, v);
        }
    }

    std::ostream & operator<<(std::ostream & out, Put2Mem const & x)
    {
        out << "\"";
        switch (x.pattern) {
            #define CASE(c, print) case c:       \
                print(x.pos, out, x.lhs);        \
                out << "\"" << x.revert << "\""; \
                print(x.pos, out, x.rhs);        \
                break
            CASE('c', put_ascii_bytes);
            CASE('C', put_ascii_bytes2);
            CASE('s', put_utf8_bytes);
            CASE('S', put_utf8_bytes2);
            CASE('b', put_hex_bytes);
            CASE('d', put_dump_bytes);
            default:
            CASE('a', put_auto_bytes);
            #undef CASE
        }
        return out << "\"]";
    }

    namespace
    {
#ifdef __clang__
        constexpr std::size_t start_type_name = 43;
        constexpr std::size_t end_type_name = 1;

        constexpr std::size_t prefix_value_name = 60;
        constexpr char end_value_name = '>';
#elif defined(__GNUC__)
        constexpr std::size_t start_type_name = 48;
        constexpr std::size_t end_type_name = 34;

        [[maybe_unused]] constexpr std::size_t prefix_value_name = 97;
        [[maybe_unused]] constexpr char end_value_name = ';';
#endif
    }

    std::string_view Enum::get_type_name(std::string_view s) noexcept
    {
        return {s.data() + start_type_name, s.size() - start_type_name - end_type_name};
    }

    std::string_view Enum::get_value_name(
        long long x, std::string_view name,
        std::string_view s0, std::string_view s1, std::string_view s2,
        std::string_view s3, std::string_view s4, std::string_view s5,
        std::string_view s6, std::string_view s7, std::string_view s8,
        std::string_view s9) noexcept
    {
        std::string_view s;
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 9)
        switch (x)
        {
            case 0: s = s0; break;
            case 1: s = s1; break;
            case 2: s = s2; break;
            case 3: s = s3; break;
            case 4: s = s4; break;
            case 5: s = s5; break;
            case 6: s = s6; break;
            case 7: s = s7; break;
            case 8: s = s8; break;
            case 9: s = s9; break;
            default:
                return {};
        }

        s.remove_prefix(prefix_value_name);

#ifdef __clang__
        if ('0' <= s[0] && s[0] <= '9')
#else
        if ('(' == s[name.size()])
#endif
        {
            return {};
        }

        s.remove_prefix(name.size());
        auto pos = s.find(end_value_name, name.size() + 2);
        if (pos != std::string_view::npos) {
            s.remove_suffix(s.size() - pos);
        }
        else {
            s = {};
        }
#else
        (void)x;
        (void)name;
        (void)s0; (void)s1; (void)s2; (void)s3; (void)s4;
        (void)s5; (void)s6; (void)s7; (void)s8; (void)s9;
#endif

        return s;
    }
} // namespace redemption_unit_test__


void RED_TEST_PRINT_TYPE_STRUCT_NAME<redemption_unit_test__::int_variation>::operator()(
    std::ostream& out, redemption_unit_test__::int_variation const & x) const
{
    if (x.left == x.right) {
        out << x.left;
    }
    else {
        out << x.value << "+-" << x.variant << (x.is_percent ? "%" : "")
            << " [" << x.left << ", " << x.right << "]";
    }
}

std::ostream& std::operator<<(std::ostream& out, ::redemption_unit_test__::Enum const& e)
{
    if (e.value_name.empty()) {
        out << e.name << "{";
        if (e.is_signed) {
            out << e.x;
        }
        else {
            out << static_cast<unsigned long long>(e.x);
        }
        out << "}";
    }
    else {
        out << e.value_name;
    }
    return out;
}

std::ostream& std::operator<<(std::ostream& out, ::redemption_unit_test__::BytesView const& v)
{
    out << "\"";
    ::redemption_unit_test__::put_auto_bytes(v.bytes.size(), out, v.bytes);
    out << "\"";
    return out;
}
