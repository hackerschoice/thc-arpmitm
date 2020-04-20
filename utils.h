
#ifndef THC_ARPMITM_UTILS_H_
#define THC_ARPMITM_UTILS_H_

int GetDefaultGW(struct in_addr *gw_addr, char *hwif);
int GetMyMac(const char *hwif, unsigned char *mac);
int GetMacFromArpTable(unsigned long ip, unsigned char *mac);
#ifndef int_ntoa
const char *int_ntoa(unsigned long ip);
#endif

int mac_aton(const char *mac_str, unsigned char *mac);

#endif /* THC_ARPMITM_UTILS_H_ */

