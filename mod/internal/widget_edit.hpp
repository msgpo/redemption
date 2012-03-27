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
   Author(s): Christophe Grosjean, Javier Caverni

*/

#if !defined(__MOD_INTERNAL_WIDGET_EDIT__)
#define __MOD_INTERNAL_WIDGET_EDIT__

#include "widget.hpp"
#include "internal/internal_mod.hpp"

struct widget_edit : public Widget {

    char buffer[256];

    widget_edit(GraphicalContext * mod, const Rect & r, Widget * parent, int id, int tab_stop, const char * caption, int pointer, int edit_pos)
    : Widget(mod, r.cx, r.cy, parent, WND_TYPE_EDIT) {

        assert(type == WND_TYPE_EDIT);

        this->rect.x = r.x;
        this->rect.y = r.y;
        this->tab_stop = tab_stop;
        this->id = id;
        this->buffer[0] = 0;
        if (caption){
            strncpy(this->buffer, caption, 255);
            this->buffer[255] = 0;
        }
        this->pointer = pointer;
        this->edit_pos = edit_pos;
        this->caption1 = 0;
    }

    ~widget_edit() {
    }

    virtual void draw(const Rect & clip)
    {

        Rect r(0, 0, this->rect.cx, this->rect.cy);
        const Rect scr_r = this->to_screen_rect(r);
        const Region region = this->get_visible_region(&this->mod->screen, this, this->parent, scr_r);

        for (size_t ir = 0 ; ir < region.rects.size() ; ir++){
            const Rect region_clip = region.rects[ir].intersect(this->to_screen_rect(clip));

            this->mod->draw_edit(scr_r,
                this->password_char,
                this->buffer,
                this->edit_pos,
                this->has_focus,
                region_clip);
        }
    }

    virtual void def_proc(const int msg, int const param1, int const param2, const Keymap * keymap)
    {
        wchar_t c;
        int n;
        int ext;
        int scan_code;
        int num_bytes;
        int num_chars;

        if (msg == WM_KEYDOWN) {
            scan_code = param1 % 128;
            ext = param2 & 0x0100;
            /* left or up arrow */
            if ((scan_code == 75 || scan_code == 72)
            && (ext || keymap->key_flags & 5)) // numlock = 0
            {
                if (this->edit_pos > 0) {
                    this->edit_pos--;
                    this->refresh(this->rect.wh());
                }
            }
            /* right or down arrow */
            else if ((scan_code == 77 || scan_code == 80)
            && (ext || keymap->key_flags & 5)) // numlock = 0
            {
                if (this->edit_pos < (int)mbstowcs(0, this->buffer, 0)) {
                    this->edit_pos++;
                    this->refresh(this->rect.wh());
                }
            }
            /* backspace */
            else if (scan_code == 14) {

                n = mbstowcs(0, this->buffer, 0);
                if (n > 0) {
                    if (this->edit_pos > 0) {
                        this->edit_pos--;
                        remove_char_at(this->buffer, 255, this->edit_pos);
                        this->refresh(this->rect.wh());
                    }
                }
            }
            /* delete */
            else if (scan_code == 83  && (ext || keymap->key_flags & 5)) // numlock = 0
            {
                n = mbstowcs(0, this->buffer, 0);
                if (n > 0) {
                    if (this->edit_pos < n) {
                        remove_char_at(this->buffer, 255, this->edit_pos);
                        this->refresh(this->rect.wh());
                    }
                }
            }
            /* end */
            else if (scan_code == 79  && (ext || keymap->key_flags & 5)) {
                n = mbstowcs(0, this->buffer, 0);
                if (this->edit_pos < n) {
                    this->edit_pos = n;
                    this->refresh(this->rect.wh());
                }
            }
            /* home */
            else if ((scan_code == 71)  &&
                     (ext || (keymap->key_flags & 5))) {
                if (this->edit_pos > 0) {
                    this->edit_pos = 0;
                    this->refresh(this->rect.wh());
                }
            }
            else {
                c = (wchar_t)(keymap->get_key_info_from_scan_code(param2, scan_code)->chr);
                num_chars = mbstowcs(0, this->buffer, 0);
                num_bytes = strlen(this->buffer);

                if ((c >= 32) && (num_chars < 127) && (num_bytes < 250)) {
                    char text[256];
                    strncpy(text, this->buffer, 255);

                    int index = this->edit_pos;
                    TODO(" why not always keep wcs instead of constantly converting back and from wcs ?")
                    int len = mbstowcs(0, text, 0);
                    wchar_t wstr[len + 16];
                    mbstowcs(wstr, text, len + 1);
                    if ((this->edit_pos >= len) || (this->edit_pos < 0)) {
                        wstr[len] = c;
                    }
                    else{
                    TODO(" is backward loop necessary ? a memcpy could do the trick")
                        int i;
                        for (i = (len - 1); i >= index; i--) {
                            wstr[i + 1] = wstr[i];
                        }
                        wstr[i + 1] = c;
                    }
                    wstr[len + 1] = 0;
                    wcstombs(text, wstr, 255);
                    this->edit_pos++;
                    strncpy(this->buffer, text, 255);
                    this->buffer[255] = 0;
                    this->refresh(this->rect.wh());
                }

            }
        }
    }



};

#endif
