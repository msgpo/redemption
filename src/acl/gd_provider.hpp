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
  Copyright (C) Wallix 2019
  Author(s): Christophe Grosjean

*/
#pragma once

#include "gdi/graphic_api.hpp"
#include "utils/sugar/noncopyable.hpp"

struct GdProvider : private noncopyable
{
    virtual gdi::GraphicApi & get_graphics() = 0;
    virtual bool is_ready_to_draw() = 0;
    virtual void display_osd_message(std::string const & message) = 0;
    virtual ~GdProvider() = default;
};

class GdForwarder : public GdProvider
{
    gdi::GraphicApi & gd;

public:
    GdForwarder(gdi::GraphicApi & gd) : gd(gd) {}
    gdi::GraphicApi & get_graphics() override { return this->gd; }
    bool is_ready_to_draw() override { return true; }
    void display_osd_message(std::string const & message) override { (void)message; }
};

