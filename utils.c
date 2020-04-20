#include "common.h"

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "utils.h"

#define BUFFER_SIZE 4096

/*
 * Get my MAC address for a given hw interface (e.g. eth0)
 *
 * Return 0 on success.
 */
int
GetMyMac(const char *hwif, unsigned char *mac)
{
	int fd;
	struct ifreq ifr;
	int ret;
	
	memset(&ifr, 0, sizeof ifr);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, hwif, IF_NAMESIZE-1);

	ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (ret != 0)
		return -1;

	memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, 6);

	return 0;
}

/*
 * LINUX specific: Find the first default GW address.
 * Return 0 on success.
 */
int
GetDefaultGW(struct in_addr *gw_addr, char *hwif)
{
    int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
    int     sock = -1, msgseq = 0;
    struct  nlmsghdr *nlh, *nlmsg;
    struct  rtmsg *route_entry;
    // This struct contain route attributes (route type)
    struct  rtattr *route_attribute;
    char    msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
    char    *ptr = buffer;
    struct timeval tv;
	int hwif_found = 0;
	int gw_found = 0;

    if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        perror("socket failed");
        return EXIT_FAILURE;
    }

    memset(msgbuf, 0, sizeof(msgbuf));
    memset(buffer, 0, sizeof(buffer));

    /* point the header and the msg structure pointers into the buffer */
    nlmsg = (struct nlmsghdr *)msgbuf;

    /* Fill in the nlmsg header*/
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlmsg->nlmsg_seq = msgseq++; // Sequence of the message packet.
    nlmsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* 1 Sec Timeout to avoid stall */
    tv.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
    /* send msg */
    if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
        perror("send failed");
        return EXIT_FAILURE;
    }

    /* receive response */
    do
    {
        received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
        if (received_bytes < 0) {
            perror("Error in recv");
            return EXIT_FAILURE;
        }

        nlh = (struct nlmsghdr *) ptr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlmsg, received_bytes) == 0) ||
           (nlmsg->nlmsg_type == NLMSG_ERROR))
        {
            perror("Error in received packet");
            return EXIT_FAILURE;
        }

        /* If we received all data break */
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        else {
            ptr += received_bytes;
            msg_len += received_bytes;
        }

        /* Break if its not a multi part message */
        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;
    }
    while ((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

    /* parse response */
    for ( ; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes))
    {
        /* Get the route data */
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        /* We are just interested in main routing table */
        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        route_attribute = (struct rtattr *) RTM_RTA(route_entry);
        route_attribute_len = RTM_PAYLOAD(nlh);

        /* Loop through all attributes */
        for ( ; RTA_OK(route_attribute, route_attribute_len);
              route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
        {
            switch(route_attribute->rta_type) {
            case RTA_OIF:
		if (hwif_found)
			break;
		hwif_found = 1;
                if_indextoname(*(int *)RTA_DATA(route_attribute), hwif);
                break;
            case RTA_GATEWAY:
		if (gw_found)
			break;
		gw_found = 1;
		memcpy(gw_addr, RTA_DATA(route_attribute), sizeof *gw_addr);
                break;
            default:
                break;
            }
        }
    }

	close(sock);
	if (hwif_found == 0)
		return -1;
	if (gw_found == 0)
		return -1;

	return 0;
}

/*
 * Read trough arp table and find MAC address...
 */
int
GetMacFromArpTable(unsigned long ip, unsigned char *mac)
{
	FILE *fp;
	char buf[1024];

	snprintf(buf, sizeof buf, "arp -an %s", int_ntoa(ip));
	fp = popen(buf, "r");
	if (fp == NULL)
		return -1;
	if (fgets(buf, sizeof buf, fp) == NULL)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	char macstr[1024];
	int ret;
	/*
	 * arp -an output looks like this:
	 * '? (10.0.2.2) at 52:54:00:12:35:02 [ether] on enp0s3'
	 */
	ret = sscanf(buf, "%*c%*s at %1024s", macstr);
	if (ret != 1)
		return -1;

	ret = mac_aton(macstr, mac);
	if (ret != 0)
		return -1;
	
	return 0;
}
#else

int
GetMyMac(const char *hwif, unsigned char *mac)
{
	return -1;
}

int
GetDefaultGW(struct in_addr *gw_addr, char *hwif, unsigned char *mac)
{
	return -1;
}

int
GetMacFromArpTable(unsigned long ip, unsigned char *mac)
{
	return -1;
}

#endif

#ifndef int_ntoa
const char *
int_ntoa(unsigned long ip)
{
	struct in_addr in;

	in.s_addr = ip;
	return inet_ntoa(in);
}
#endif

/*
 * Return 0 on success
 */
int
mac_aton(const char *mac_str, unsigned char *mac)
{
	unsigned int tmp[6];
	int i;

	i = sscanf(mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
	if (i != 6)
		return -1;

	for (i = 0; i < 6; i++)
		mac[i] = tmp[i];

	return 0;
}

#ifndef PACKAGE
int
main()
{
	struct in_addr gw;
	char hwif[IF_NAMESIZE];
	unsigned char mac[6];
	GetDefaultGW(&gw, hwif, mac);
	DEBUGF("IP is %s %lu\n", inet_ntoa(gw), sizeof gw);
	DEBUGF("HW interface is %s\n", hwif);
	fprintf(stderr, "Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	GetMacFromArpTable(gw.s_addr, mac);
	fprintf(stderr, "Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
#endif

