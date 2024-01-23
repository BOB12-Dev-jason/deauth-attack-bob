#pragma once

// send ap's broadcast deauth packet. disable all station of the ESS.
int deauth_attack_broadcast(const char* interface, const char* ap_mac);

// send station's deauth packet to ap. disable only one target station.
int deauth_attack_station(const char* interface, const char* ap_mac, const char* station_mac);

// send station's auth packet to ap. disable only one target station.
int deauth_attack_auth(const char* interface, const char* ap_mac, const char* station_mac);
