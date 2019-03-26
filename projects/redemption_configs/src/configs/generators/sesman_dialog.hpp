/*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
*   Product name: redemption, a FLOSS RDP proxy
*   Copyright (C) Wallix 2010-2015
*   Author(s): Jonathan Poelen
*/

#pragma once

#include "configs/attributes/spec.hpp"
#include "configs/generators/utils/spec_writer.hpp"
#include "configs/generators/cpp_config.hpp"
#include "configs/generators/python_spec.hpp"

#include <iostream>
#include <fstream>
#include <sstream>

#include <cerrno>
#include <cstring>


namespace cfg_generators
{

namespace sesman_dialog_writer
{

using namespace cfg_attributes;

class SesmanDialogWriterBase
{
    std::ofstream out;
    int errnum = 0;

public:
    using attribute_name_type = cfg_attributes::sesman::name;

    SesmanDialogWriterBase(std::string const& filename)
    : out(filename)
    {
        if (!out) {
            errnum = errno;
            std::cerr << "SesmanDialogWriterBase: " << filename << ": " << strerror(errnum) << "\n";
        }

        out <<
            "DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN\n\n"
            "       cpp name       |       sesman / passthrough name\n\n"
        ;
    }

    void do_init()
    {}

    int do_finish()
    {
        if (!errnum) {
            out.flush();
            if (!out) {
                if (errno) {
                    errnum = errno;
                }
            }
        }
        return errnum;
    }

    void do_start_section(std::string const & /*section_name*/)
    {}

    void do_stop_section(std::string const & /*section_name*/)
    {
        this->out << "\n";
    }

    template<class Pack>
    void evaluate_member(std::string const & section_name, Pack const & infos, type_enumerations& enums)
    {
        if constexpr (is_convertible_v<Pack, sesman_io_t>) {
            using sesman_io = sesman::internal::io;
            auto const properties = get_elem<sesman_io_t>(infos).value;
            auto cpp_type = get_type<cpp::type_>(infos);
            auto sesman_type = get_type<sesman::type_>(infos);

            char const* dialog = " <-> ";

            if ((properties & sesman_io::rw) == sesman_io::sesman_to_proxy) {
                dialog = " <- ";
            }
            else if ((properties & sesman_io::rw) == sesman_io::proxy_to_sesman) {
                dialog = " -> ";
            }

            this->out
                << "cfg::" << section_name << "::" << get_name<cpp::name>(infos)
                << dialog
                << get_name<sesman::name>(infos)
                << "   ["
            ;
            cpp_config_writer::write_type(this->out, cpp_type);

            if constexpr (is_t_convertible_v<Pack, sesman::type_>) {
                this->out << dialog;
                cpp_config_writer::write_type(this->out, sesman_type);
            }

            this->out << "]\n";

            std::stringstream comments;

            python_spec_writer::write_description(comments, enums, sesman_type, infos);
            python_spec_writer::write_enumeration_value_description(comments, enums, sesman_type, infos);

            this->out << io_prefix_lines{comments.str().c_str(), "    ", "", 0};
        }
    }
};

}

}
