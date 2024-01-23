#include <stdio.h>
#include <string.h>

#include "deauth-attack.h"

void usage();

int main(int argc, char* argv[]) {

    const char* interface;
    const char* ap_mac;
    const char* station_mac;

    int res;

    if(argc == 3) { // <interfrace> <ap mac>
        // send ap broadcast
        interface = argv[1];
        ap_mac = argv[2];
        res = deauth_attack_broadcast(interface, ap_mac);
        
    } else if (argc == 4) { // <interfrace> <ap mac> <station mac>
        // send station's deauth
        interface = argv[1];
        ap_mac = argv[2];
        station_mac = argv[3];
        res = deauth_attack_station(interface, ap_mac, station_mac);

    } else if (argc==5) { // <interfrace> <ap mac> <station mac> -auth
        // send station's fake auth
        if(strcmp(argv[4], "-auth") == 0) {
            interface = argv[1];
            ap_mac = argv[2];
            station_mac = argv[3];
            res = deauth_attack_auth(interface, ap_mac, station_mac);
        }
        else {
            usage();
            res = -1;
        }
        
    } else {
        usage();
        res = -1;
    }

    return res;
    
}

void usage() {
    puts("syntax: deauth-attack <interfrace> <ap mac> [<station mac> [-auth]]");
    puts("sample: deauth-attack wlan0 aa:bb:cc:dd:ee:ff 11:22:33:44:55:66");
}
