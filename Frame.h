#pragma once

#include <stdint.h>

struct ieee80211_MngFrame {
    uint8_t radiotap[8];
    uint16_t frame_ctl;
    uint16_t duartion;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctl;
};


struct ieee80211_AuthFixParam {
    uint16_t auth_alg;
    uint16_t auth_seq;
    uint16_t stat_code;
};


struct ieee08211_deAuthFixParam {
    uint16_t reason_code;
};
