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
   Copyright (C) Wallix 2010
   Author(s): Christophe Grosjean, Javier Caverni, Xavier Dunat, Martin Potier
*/

#ifndef _REDEMPTION_CORE_RDP_CACHES_BMPCACHE_HPP_
#define _REDEMPTION_CORE_RDP_CACHES_BMPCACHE_HPP_

#include <map>

#include "bitmap.hpp"
#include "RDP/PersistentKeyListPDU.hpp"
#include "RDP/orders/RDPOrdersSecondaryBmpCache.hpp"
#include "fileutils.hpp"

enum {
      BITMAP_FOUND_IN_CACHE
    , BITMAP_ADDED_TO_CACHE
};

struct BmpCache {
    static const uint8_t  MAXIMUM_NUMBER_OF_CACHES        = 5;
    static const uint16_t MAXIMUM_NUMBER_OF_CACHE_ENTRIES = 8192;

    static const uint8_t IN_WAIT_LIST = 0x80;

    const uint8_t bpp;

    uint8_t number_of_cache;
    bool    use_waiting_list;

    uint16_t cache_0_entries;
    uint16_t cache_0_size;
    bool     cache_0_persistent;
    uint16_t cache_1_entries;
    uint16_t cache_1_size;
    bool     cache_1_persistent;
    uint16_t cache_2_entries;
    uint16_t cache_2_size;
    bool     cache_2_persistent;
    uint16_t cache_3_entries;
    uint16_t cache_3_size;
    bool     cache_3_persistent;
    uint16_t cache_4_entries;
    uint16_t cache_4_size;
    bool     cache_4_persistent;

    const Bitmap * cache [MAXIMUM_NUMBER_OF_CACHES + 1 /* wait_list */][MAXIMUM_NUMBER_OF_CACHE_ENTRIES];
    uint32_t       stamps[MAXIMUM_NUMBER_OF_CACHES + 1 /* wait_list */][MAXIMUM_NUMBER_OF_CACHE_ENTRIES];
    uint8_t        sha1  [MAXIMUM_NUMBER_OF_CACHES + 1 /* wait_list */][MAXIMUM_NUMBER_OF_CACHE_ENTRIES][20];

    // Map based bitmap finder.
    class Finder {
    public:
        static const uint32_t invalid_cache_index = 0xFFFFFFFF;

    private:
        struct map_value {
            const Bitmap * bmp;
            uint16_t       cache_index;
        };

        typedef std::map<std::string, map_value> container_type;

        container_type bmp_map;

        inline void get_key(const uint8_t (& sha1)[20], uint16_t cx, uint16_t cy, char (& key)[51]) {
            ::snprintf( key, sizeof(key)
                      , "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
                        "_%dx%d"
                      , sha1[ 0], sha1[ 1], sha1[ 2], sha1[ 3], sha1[ 4]
                      , sha1[ 5], sha1[ 6], sha1[ 7], sha1[ 8], sha1[ 9]
                      , sha1[10], sha1[11], sha1[12], sha1[13], sha1[14]
                      , sha1[15], sha1[16], sha1[17], sha1[18], sha1[19]
                      , cx, cy
                      );
        }

    public:
        inline void add( const uint8_t (& sha1)[20], uint16_t cx, uint16_t cy, const Bitmap * bmp
                       , uint16_t cache_index) {
            char key[51];
            get_key(sha1, cx, cy, key);

            map_value val;
            val.bmp         = bmp;
            val.cache_index = cache_index;

            bmp_map[key] = val;
        }

        inline void clear() {
            bmp_map.clear();
        }

        inline uint32_t get_cache_index(const uint8_t (& sha1)[20], uint16_t cx, uint16_t cy) {
            char key[51];
            get_key(sha1, cx, cy, key);

            container_type::const_iterator it;

            it = bmp_map.find(key);
            if (it == bmp_map.end()) {
                return invalid_cache_index;
            }

            return it->second.cache_index;
        }

        inline void remove(const uint8_t (& sha1)[20], uint16_t cx, uint16_t cy) {
            char key[51];
            get_key(sha1, cx, cy, key);

            container_type::iterator it;

            it = bmp_map.find(key);
            if (it != bmp_map.end()) {
                bmp_map.erase(it);
            }
        }
    };

    Finder finders[MAXIMUM_NUMBER_OF_CACHES + 1 /* wait_list */];

    uint32_t stamp;
    uint32_t verbose;

    unsigned finding_counter;
    unsigned found_counter;
    unsigned not_found_counter;

    public:
        BmpCache(const uint8_t bpp,
                 uint8_t number_of_cache,
                 bool use_waiting_list,
                 uint16_t cache_0_entries,     uint16_t cache_0_size,     bool cache_0_persistent,
                 uint16_t cache_1_entries,     uint16_t cache_1_size,     bool cache_1_persistent,
                 uint16_t cache_2_entries,     uint16_t cache_2_size,     bool cache_2_persistent,
                 uint16_t cache_3_entries = 0, uint16_t cache_3_size = 0, bool cache_3_persistent = false,
                 uint16_t cache_4_entries = 0, uint16_t cache_4_size = 0, bool cache_4_persistent = false,
                 uint32_t verbose = 0)
            : bpp(bpp)
            , number_of_cache(number_of_cache)
            , use_waiting_list(use_waiting_list)
            , cache_0_entries   (cache_0_entries)
            , cache_0_size      (cache_0_size)
            , cache_0_persistent(cache_0_persistent)
            , cache_1_entries   (cache_1_entries)
            , cache_1_size      (cache_1_size)
            , cache_1_persistent(cache_1_persistent)
            , cache_2_entries   (cache_2_entries)
            , cache_2_size      (cache_2_size)
            , cache_2_persistent(cache_2_persistent)
            , cache_3_entries   (cache_3_entries)
            , cache_3_size      (cache_3_size)
            , cache_3_persistent(cache_3_persistent)
            , cache_4_entries   (cache_4_entries)
            , cache_4_size      (cache_4_size)
            , cache_4_persistent(cache_4_persistent)
            , stamp(0)
            , verbose(verbose)
            , finding_counter(0)
            , found_counter(0)
            , not_found_counter(0)

        {
            if (this->verbose) {
                LOG( LOG_INFO
                   , "BmpCache: bpp=%u number_of_cache=%u use_waiting_list=%s "
                     "cache_0(%u, %u, %s) cache_1(%u, %u, %s) cache_2(%u, %u, %s) "
                     "cache_3(%u, %u, %s) cache_4(%u, %u, %s)"
                   , this->bpp, this->number_of_cache, (this->use_waiting_list ? "yes" : "no")
                   , this->cache_0_entries, this->cache_0_size, (cache_0_persistent ? "yes" : "no")
                   , this->cache_1_entries, this->cache_1_size, (cache_1_persistent ? "yes" : "no")
                   , this->cache_2_entries, this->cache_2_size, (cache_2_persistent ? "yes" : "no")
                   , this->cache_3_entries, this->cache_3_size, (cache_3_persistent ? "yes" : "no")
                   , this->cache_4_entries, this->cache_4_size, (cache_4_persistent ? "yes" : "no")
                   );
            }

            if (this->number_of_cache > MAXIMUM_NUMBER_OF_CACHES) {
                LOG(LOG_ERR, "BmpCache: number_of_cache(%u) > %u", this->number_of_cache,
                    MAXIMUM_NUMBER_OF_CACHES);
                throw Error(ERR_RDP_PROTOCOL);
            }
            this->reset_values();
        }

        ~BmpCache() {
            this->destroy_cache();
        }

    private:
        void destroy_cache() {
            if (this->verbose) {
                this->log();
            }
            for (uint8_t cid = 0; cid < MAXIMUM_NUMBER_OF_CACHES + 1 /* wait_list */; cid++) {
                for (uint16_t cidx = 0; cidx < MAXIMUM_NUMBER_OF_CACHE_ENTRIES; cidx++) {
                    delete this->cache[cid][cidx];
                }
                this->finders[cid].clear();
            }
        }

        void reset_values() {
            this->stamp = 0;
            for (uint8_t cid = 0; cid < MAXIMUM_NUMBER_OF_CACHES + 1 /* wait_list */; cid++) {
                for (uint16_t cidx = 0; cidx < MAXIMUM_NUMBER_OF_CACHE_ENTRIES; cidx++) {
                    this->cache[cid][cidx]  = NULL;
                    this->stamps[cid][cidx] = 0;
                    bzero(this->sha1[cid][cidx], sizeof(this->sha1[cid][cidx]));
                }
                this->finders[cid].clear();
            }
        }

    public:
        void reset() {
            this->destroy_cache();
            this->reset_values();
        }

        void put(uint8_t id, uint16_t idx, const Bitmap * const bmp) {
            REDASSERT((id & IN_WAIT_LIST) == 0);
            if (idx == RDPBmpCache::BITMAPCACHE_WAITING_LIST_INDEX) {
                // Last bitmap cache entry is used by waiting list.
                //LOG(LOG_INFO, "BmpCache: Put bitmap to waiting list.");
                idx = MAXIMUM_NUMBER_OF_CACHE_ENTRIES - 1;
            }
            if (this->cache[id][idx]) {
                this->finders[id].remove(this->sha1[id][idx], this->cache[id][idx]->cx,
                    this->cache[id][idx]->cy);
                delete this->cache[id][idx];
            }
            this->cache[id][idx]  = bmp;
            this->stamps[id][idx] = ++this->stamp;
            bmp->compute_sha1(this->sha1[id][idx]);
            this->finders[id].add(this->sha1[id][idx], bmp->cx, bmp->cy, bmp, idx);
        }

        void restamp(uint8_t id, uint16_t idx) {
            REDASSERT((id & IN_WAIT_LIST) == 0);
            this->stamps[id][idx] = ++this->stamp;
        }

        const Bitmap * get(uint8_t id, uint16_t idx) {
            if (id & IN_WAIT_LIST)
                return this->cache[MAXIMUM_NUMBER_OF_CACHES][idx];
            if (idx == RDPBmpCache::BITMAPCACHE_WAITING_LIST_INDEX) {
                // Last bitmap cache entry is used by waiting list.
                //LOG(LOG_INFO, "BmpCache: Get bitmap from waiting list.");
                idx = MAXIMUM_NUMBER_OF_CACHE_ENTRIES - 1;
            }
            return this->cache[id][idx];
        }

        unsigned get_stamp(uint8_t id, uint16_t idx) {
            REDASSERT((id & IN_WAIT_LIST) == 0);
            return this->stamps[id][idx];
        }

        bool is_cache_persistent(uint8_t id) {
            switch (id) {
                case 0:                        return this->cache_0_persistent;
                case 1:                        return this->cache_1_persistent;
                case 2:                        return this->cache_2_persistent;
                case 3:                        return this->cache_3_persistent;
                case 4:                        return this->cache_4_persistent;
                // Wait list.
                case MAXIMUM_NUMBER_OF_CACHES: return true;
            }

            LOG(LOG_ERR, "BmpCache: index_of_cache(%u) > %u", id, MAXIMUM_NUMBER_OF_CACHES);
            throw Error(ERR_RDP_PROTOCOL);
            return false;
        }

        inline uint16_t get_cache_usage(uint8_t cache_id, uint16_t max_cache_entries) {
            REDASSERT((cache_id & IN_WAIT_LIST) == 0);

            uint16_t cache_entries = 0;
            for (unsigned cache_index = 0; cache_index < max_cache_entries; cache_index++) {
                if (this->cache[cache_id][cache_index]) {
                    cache_entries++;
                }
            }

            return cache_entries;
        }

        void log() {
            LOG( LOG_INFO
               , "BmpCache: total=%u found=%u not_found=%u "
                 "(0=>%u, %u) (1=>%u, %u) (2=>%u, %u) (3=>%u, %u) (4=>%u, %u)"
               , this->finding_counter, this->found_counter, this->not_found_counter
               , get_cache_usage(0, this->cache_0_entries), this->cache_0_entries
               , get_cache_usage(1, this->cache_1_entries), this->cache_1_entries
               , get_cache_usage(2, this->cache_2_entries), this->cache_2_entries
               , get_cache_usage(3, this->cache_3_entries), this->cache_3_entries
               , get_cache_usage(4, this->cache_4_entries), this->cache_4_entries);
        }

        TODO("palette to use for conversion when we are in 8 bits mode should be passed from memblt.cache_id, not stored in bitmap");
        uint32_t cache_bitmap(const Bitmap & oldbmp) {
            // Generating source code for unit test.
            //if (this->verbose & 8192) {
            //    if (this->finding_counter == 500) {
            //        BOOM;
            //    }
            //    LOG(LOG_INFO, "uint8_t palette_data_%d[] = {", this->finding_counter);
            //    hexdump_d((const char *)(void *)oldbmp.original_palette, sizeof(oldbmp.original_palette));
            //    LOG(LOG_INFO, "};", this->finding_counter);
            //    LOG(LOG_INFO, "uint8_t bitmap_data_%d[] = {", this->finding_counter);
            //    hexdump_d((const char *)(void *)oldbmp.data_bitmap.get(), oldbmp.bmp_size);
            //    LOG(LOG_INFO, "};", this->finding_counter);
            //    LOG(LOG_INFO, "memcpy(palette, palette_data_%d, sizeof(palette));", this->finding_counter);
            //    LOG(LOG_INFO, "init_palette332(palette);", this->finding_counter);
            //    LOG(LOG_INFO,
            //        "Bitmap * bmp_%d = new Bitmap(%u, %u, &palette, %u, %u, bitmap_data_%d, %u, false);",
            //        this->finding_counter, this->bpp, oldbmp.original_bpp, oldbmp.cx, oldbmp.cy,
            //        this->finding_counter, oldbmp.bmp_size);
            //}

            this->finding_counter++;

            const Bitmap * bmp = new Bitmap(this->bpp, oldbmp);

            uint8_t bmp_sha1[20];
            bmp->compute_sha1(bmp_sha1);

            uint16_t oldest_cidx = 0;

            uint16_t   entries    = 0;
            uint8_t    id_real    = 0;
            bool       persistent = false;
            uint32_t   bmp_size   = bmp->bmp_size;

                   if (this->cache_0_entries && (bmp_size <= this->cache_0_size)) {
                entries    = this->cache_0_entries;
                id_real    = 0;
                persistent = this->cache_0_persistent;
            } else if (this->cache_1_entries && (bmp_size <= this->cache_1_size)) {
                entries    = this->cache_1_entries;
                id_real    = 1;
                persistent = this->cache_1_persistent;
            } else if (this->cache_2_entries && (bmp_size <= this->cache_2_size)) {
                entries    = this->cache_2_entries;
                id_real    = 2;
                persistent = this->cache_2_persistent;
            } else if (this->cache_3_entries && (bmp_size <= this->cache_3_size)) {
                entries    = this->cache_3_entries;
                id_real    = 3;
                persistent = this->cache_3_persistent;
            } else if (this->cache_4_entries && (bmp_size <= this->cache_4_size)) {
                entries    = this->cache_4_entries;
                id_real    = 4;
                persistent = this->cache_4_persistent;
            }
            else {
                LOG(LOG_ERR,
                    "BmpCache: bitmap size(%u) too big: cache_0=%u cache_1=%u cache_2=%u cache_3=%u cache_4=%u",
                    bmp_size,
                    (this->cache_0_entries ? this->cache_0_size : 0),
                    (this->cache_1_entries ? this->cache_1_size : 0),
                    (this->cache_2_entries ? this->cache_2_size : 0),
                    (this->cache_3_entries ? this->cache_3_size : 0),
                    (this->cache_4_entries ? this->cache_4_size : 0));
                REDASSERT(0);
                throw Error(ERR_BITMAP_CACHE_TOO_BIG);
            }
            if (persistent && this->use_waiting_list) {
                // Last bitmap cache entry is used by waiting list.
                entries--;
            }

            uint8_t   id     = id_real;
            Finder  & finder = this->finders[id];

            uint32_t cache_index_32 = finder.get_cache_index(bmp_sha1, bmp->cx, bmp->cy);
            if (cache_index_32 == Finder::invalid_cache_index) {
                unsigned oldstamp = this->stamps[id][0];
                for (uint16_t cidx = 0 ; cidx < entries; cidx++) {
                    if (this->stamps[id][cidx] < oldstamp) {
                        oldest_cidx = cidx;
                        oldstamp    = this->stamps[id][cidx];
                    }
                }
            }
            else {
                if (this->verbose & 512) {
                    if (persistent) {
                        LOG(LOG_INFO,
                            "BmpCache: use bitmap %02X%02X%02X%02X%02X%02X%02X%02X stored in persistent disk bitmap cache",
                            bmp_sha1[0], bmp_sha1[1], bmp_sha1[2], bmp_sha1[3],
                            bmp_sha1[4], bmp_sha1[5], bmp_sha1[6], bmp_sha1[7]);
                    }
                }
                this->stamps[id][cache_index_32] = ++this->stamp;
                delete bmp;
                this->found_counter++;
                // Generating source code for unit test.
                //if (this->verbose & 8192) {
                //    LOG(LOG_INFO, "cache_id    = %u;", id);
                //    LOG(LOG_INFO, "cache_index = %u;", cache_index_32);
                //    LOG(LOG_INFO,
                //        "BOOST_CHECK_EQUAL(((BITMAP_FOUND_IN_CACHE << 24) | (cache_id << 16) | cache_index), "
                //            "bmp_cache.cache_bitmap(*bmp_%d));",
                //        this->finding_counter - 1);
                //    LOG(LOG_INFO, "delete bmp_%d;", this->finding_counter - 1);
                //    LOG(LOG_INFO, "");
                //}
                return (BITMAP_FOUND_IN_CACHE << 24) | (id << 16) | cache_index_32;
            }

            this->not_found_counter++;

            if (persistent && this->use_waiting_list) {
                // The bitmap cache is persistent.

                Finder & wait_list_finder = this->finders[MAXIMUM_NUMBER_OF_CACHES];

                cache_index_32 = wait_list_finder.get_cache_index(bmp_sha1, bmp->cx, bmp->cy);
                if (cache_index_32 == Finder::invalid_cache_index) {
                    unsigned oldstamp = this->stamps[MAXIMUM_NUMBER_OF_CACHES][0];
                    for (uint16_t cidx = 0 ; cidx < MAXIMUM_NUMBER_OF_CACHE_ENTRIES; cidx++) {
                        if (this->stamps[MAXIMUM_NUMBER_OF_CACHES][cidx] < oldstamp) {
                            oldest_cidx = cidx;
                            oldstamp    = this->stamps[MAXIMUM_NUMBER_OF_CACHES][cidx];
                        }
                    }

                    id_real     =  MAXIMUM_NUMBER_OF_CACHES;
                    id          |= IN_WAIT_LIST;

                    if (this->verbose & 512) {
                        LOG(LOG_INFO, "BmpCache: Put bitmap %02X%02X%02X%02X%02X%02X%02X%02X into wait list.",
                            bmp_sha1[0], bmp_sha1[1], bmp_sha1[2], bmp_sha1[3],
                            bmp_sha1[4], bmp_sha1[5], bmp_sha1[6], bmp_sha1[7]);
                    }
                }
                else {
                    this->cache [MAXIMUM_NUMBER_OF_CACHES][cache_index_32] = NULL;
                    this->stamps[MAXIMUM_NUMBER_OF_CACHES][cache_index_32] = 0;
                    bzero(this->sha1[MAXIMUM_NUMBER_OF_CACHES][cache_index_32],
                          sizeof(this->sha1[MAXIMUM_NUMBER_OF_CACHES][cache_index_32]));

                    wait_list_finder.remove(bmp_sha1, bmp->cx, bmp->cy);

                    if (this->verbose & 512) {
                        LOG(LOG_INFO,
                            "BmpCache: Put bitmap %02X%02X%02X%02X%02X%02X%02X%02X into persistent cache, cache_index=%u",
                            bmp_sha1[0], bmp_sha1[1], bmp_sha1[2], bmp_sha1[3],
                            bmp_sha1[4], bmp_sha1[5], bmp_sha1[6], bmp_sha1[7], oldest_cidx);
                    }
                }
            }

            // find oldest stamp (or 0) and replace bitmap
            if (this->cache[id_real][oldest_cidx]) {
                this->finders[id_real].remove(this->sha1[id_real][oldest_cidx],
                    this->cache[id_real][oldest_cidx]->cx, this->cache[id_real][oldest_cidx]->cy);
                delete this->cache[id_real][oldest_cidx];
            }
            this->cache [id_real][oldest_cidx] = bmp;
            this->stamps[id_real][oldest_cidx] = ++this->stamp;
            ::memcpy(this->sha1[id_real][oldest_cidx], bmp_sha1, 20);
            this->finders[id_real].add(bmp_sha1, bmp->cx, bmp->cy, bmp, oldest_cidx);
            // Generating source code for unit test.
            //if (this->verbose & 8192) {
            //    LOG(LOG_INFO, "cache_id    = %u;", id);
            //    LOG(LOG_INFO, "cache_index = %u;", oldest_cidx);
            //    LOG(LOG_INFO,
            //        "BOOST_CHECK_EQUAL(((BITMAP_ADDED_TO_CACHE << 24) | (cache_id << 16) | cache_index), "
            //            "bmp_cache.cache_bitmap(*bmp_%d));",
            //        this->finding_counter - 1);
            //    LOG(LOG_INFO, "delete bmp_%d;", this->finding_counter - 1);
            //    LOG(LOG_INFO, "");
            //}
            return (BITMAP_ADDED_TO_CACHE << 24) | (id << 16) | oldest_cidx;
        }
};

#endif
