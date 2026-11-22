/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/




#include "proxy.h"
#include <stdarg.h>
_3proxy_mutex_t log_mutex;
_3proxy_mutex_t audit_mutex;
int havelog = 0;


struct clientparam logparam;
struct srvparam logsrv;

struct auditline {
	char data[8192];
	size_t len;
};

static void auditprintf(struct auditline *line, const char *format, ...){
	va_list ap;
	int written;

	if(line->len >= sizeof(line->data) - 1) return;
	va_start(ap, format);
	written = vsnprintf(line->data + line->len, sizeof(line->data) - line->len,
		format, ap);
	va_end(ap);
	if(written > 0){
		line->len += (size_t)written;
		if(line->len >= sizeof(line->data)) line->len = sizeof(line->data) - 1;
	}
}

/* Values go into one whitespace-delimited field. Percent-encoding makes the
   line unambiguous without losing bytes from a name. */
static void audittokenmax(struct auditline *line, const unsigned char *value,
	int maxchars){
	static const char hex[] = "0123456789ABCDEF";
	int i;

	if(!value || !*value){
		auditprintf(line, "-");
		return;
	}
	for(i = 0; value[i] && (!maxchars || i < maxchars); i++){
		unsigned char c = value[i];

		if(c <= 0x20 || c == 0x7f || c == '%' || c == '=' || c == '\\'){
			auditprintf(line, "%%%c%c", hex[c >> 4], hex[c & 15]);
		}
		else {
			auditprintf(line, "%c", c);
		}
	}
	if(maxchars && value[i]) auditprintf(line, "...");
}

static void audittoken(struct auditline *line, const unsigned char *value){
	audittokenmax(line, value, 0);
}

static const char * auditresult(struct clientparam *param){
	int action = param->lastace? param->lastace->action : -1;
	int res = param->res;

	if(!res) return "allow";
	if(res == 10) return "limit";
	if(action == DENY || res == 1 || res == 3) return "deny";
	if(res == 4) return "auth_required";
	if(res >= 5 && res <= 9) return "auth_failed";
	if(res < 100) return "denied";
	return "error";
}

static const char * auditservice(PROXYSERVICE service){
	switch(service){
		case S_PROXY: return "proxy";
		case S_TCPPM: return "tcppm";
		case S_POP3P: return "pop3p";
		case S_SOCKS4: return "socks4";
		case S_SOCKS5: return "socks5";
		case S_UDPPM: return "udppm";
		case S_SOCKS: return "socks";
		case S_SOCKS45: return "socks4a";
		case S_ADMIN: return "admin";
		case S_DNSPR: return "dnspr";
		case S_FTPPR: return "ftppr";
		case S_SMTPP: return "smtpp";
		case S_AUTO: return "auto";
		case S_TLSPR: return "tlspr";
		case S_IMAPP: return "imapp";
		case S_HTTPSRV: return "httpsrv";
		default: return "unknown";
	}
}

static const char * auditaction(int action){
	switch(action){
		case ALLOW: return "allow";
		case DENY: return "deny";
		case REDIRECT: return "redirect";
		case BANDLIM: return "bandlim";
		case NOBANDLIM: return "nobandlim";
		case COUNTIN: return "countin";
		case NOCOUNTIN: return "nocountin";
		case COUNTOUT: return "countout";
		case NOCOUNTOUT: return "nocountout";
		case CONNLIM: return "connlim";
		case NOCONNLIM: return "noconnlim";
		case COUNTALL: return "countall";
		case NOCOUNTALL: return "nocountall";
		default: return "unknown";
	}
}

/* Written alongside every ordinary access-log record, and whether or not one
   is configured. Authentication and ACL failures are recorded with the user
   name the client offered, never with its password. */
void auditsession(struct clientparam *param, const unsigned char *text){
	struct auditline line;
	char timestamp[64], host[128];
	const unsigned char *target;
	struct tm tm, *tmp;
	time_t now;
	uint64_t elapsed = 0;
	unsigned msec = 0;
	FILE *out;
	char *ip;

	if(!param || !param->srv || !param->time_start) return;
	_3proxy_mutex_lock(&audit_mutex);
	out = conf.auditstdout? stdout : conf.auditfp;
	if(!out){
		_3proxy_mutex_unlock(&audit_mutex);
		return;
	}

	now = time(NULL);
	tmp = localtime(&now);
	if(tmp) tm = *tmp;
	else memset(&tm, 0, sizeof(tm));
	if(!strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", &tm))
		strcpy(timestamp, "-");
#ifdef _WIN32
	{
		struct timeb tb;

		ftime(&tb);
		msec = (unsigned)tb.millitm;
	}
#else
	{
		struct timeval tv;

		gettimeofday(&tv, NULL);
		msec = (unsigned)(tv.tv_usec / 1000);
	}
#endif
	if(now >= param->time_start){
		elapsed = (uint64_t)(now - param->time_start) * 1000;
		if(msec >= param->msec_start) elapsed += msec - param->msec_start;
	}

	line.len = 0;
	line.data[0] = 0;
	auditprintf(&line, "audit ts=%s", timestamp);
	auditprintf(&line, " event=session result=%s", auditresult(param));
	auditprintf(&line, " user=");
	audittoken(&line, param->username);

	ip = "-";
	if(*SAFAMILY(&param->sincr) == AF_INET
#ifndef NOIPV6
	   || *SAFAMILY(&param->sincr) == AF_INET6
#endif
	  ){
		if(myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr),
				host, sizeof(host))) ip = host;
	}
	auditprintf(&line, " client=");
	audittoken(&line, (unsigned char *)ip);
	auditprintf(&line, ":%hu", ntohs(*SAPORT(&param->sincr)));

	target = (param->hostname && *param->hostname)? param->hostname : NULL;
	if(!target){
		if(*SAFAMILY(&param->req) == AF_INET
#ifndef NOIPV6
		   || *SAFAMILY(&param->req) == AF_INET6
#endif
		  ){
			if(myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req),
					host, sizeof(host))) target = (unsigned char *)host;
		}
	}
	auditprintf(&line, " target=");
	audittoken(&line, target);
	auditprintf(&line, ":%hu", ntohs(*SAPORT(&param->req)));
	auditprintf(&line, " service=%s", auditservice(param->service));
	auditprintf(&line, " status=%d error=%d", param->status, param->res);
	auditprintf(&line, " bytes_in=%"PRIu64" bytes_out=%"PRIu64,
		param->statssrv64, param->statscli64);
	auditprintf(&line, " duration_ms=%"PRIu64, elapsed);
	auditprintf(&line, " acl=%s", param->lastace? auditaction(param->lastace->action) : "-");
	auditprintf(&line, " request=");
	audittokenmax(&line, text, 1024);
	auditprintf(&line, " throttled=%d", param->userbandthrottled? 1 : 0);
	auditprintf(&line, " rate_in=%u rate_out=%u",
		param->userbandratein, param->userbandrateout);

	fprintf(out, "%s\n", line.data);
	fflush(out);
	_3proxy_mutex_unlock(&audit_mutex);
}



void dolog(struct clientparam * param, const unsigned char *s){
	if(param) auditsession(param, s);
	if(param && param->srv)param->srv->logfunc(param, s);
	else logstdout(NULL, s);
}


void clearstat(struct clientparam * param) {

#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	param->time_start = (time_t)tb.time;
	param->msec_start = (unsigned)tb.millitm;

#else
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);

	param->time_start = (time_t)tv.tv_sec;
	param->msec_start = (tv.tv_usec / 1000);
#endif
	param->statscli64 = param->statssrv64 = param->nreads = param->nwrites =
		param->nconnects = 0;
}


char months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format){
	int i, j;
	int len;
	time_t sec;
	unsigned msec;

	long timezone;
	unsigned delay;

#ifdef _WIN32
	struct timeb tb;
#else
	struct timeval tv;
	struct timezone tz;
#endif

	if(!logparam.srv) srvinit(&logsrv, &logparam);
	if(!param) param = &logparam;



#ifdef _WIN32
	ftime(&tb);
	sec = (time_t)tb.time;
	msec = (unsigned)tb.millitm;
	timezone = tm->tm_isdst*60 - tb.timezone;

#else
	gettimeofday(&tv, &tz);

	sec = (time_t)tv.tv_sec;
	msec = tv.tv_usec / 1000;
#ifdef _SOLARIS
	timezone = -altzone / 60;
#else
	timezone = tm->tm_gmtoff / 60;
#endif
#endif

	delay = param->time_start?((unsigned) ((sec - param->time_start))*1000 + msec) - param->msec_start : 0;
	*buf = 0;
	for(i=0, j=0; format[j] && i < 4040; j++){
		if(format[j] == '%' && format[j+1]){
			j++;
			switch(format[j]){
				case '%':
				 buf[i++] = '%';
				 break;
				case 'y':
				 sprintf((char *)buf+i, "%.2d", tm->tm_year%100);
				 i+=2;
				 break;
				case 'Y':
				 sprintf((char *)buf+i, "%.4d", tm->tm_year+1900);
				 i+=4;
				 break;
				case 'm':
				 sprintf((char *)buf+i, "%.2d", tm->tm_mon+1);
				 i+=2;
				 break;
				case 'o':
				 sprintf((char *)buf+i, "%s", months[tm->tm_mon]);
				 i+=3;
				 break;
				case 'd':
				 sprintf((char *)buf+i, "%.2d", tm->tm_mday);
				 i+=2;
				 break;
				case 'H':
				 sprintf((char *)buf+i, "%.2d", tm->tm_hour);
				 i+=2;
				 break;
				case 'M':
				 sprintf((char *)buf+i, "%.2d", tm->tm_min);
				 i+=2;
				 break;
				case 'S':
				 sprintf((char *)buf+i, "%.2d", tm->tm_sec);
				 i+=2;
				 break;
				case 't':
				 sprintf((char *)buf+i, "%.10u", (unsigned)sec);
				 i+=10;
				 break;
				case 'b':
				 i+=sprintf((char *)buf+i, "%u", delay?(unsigned)(param->statscli64 * 1000./delay):0);
				 break;
				case 'B':
				 i+=sprintf((char *)buf+i, "%u", delay?(unsigned)(param->statssrv64 * 1000./delay):0);
				 break;				 
				case 'D':
				 i+=sprintf((char *)buf+i, "%u", delay);
				 break;
				case '.':
				 sprintf((char *)buf+i, "%.3u", msec);
				 i+=3;
				 break;
				case 'z':
				 sprintf((char *)buf+i, "%+.2ld%.2u", timezone / 60, (unsigned)(timezone%60));
				 i+=5;
				 break;
				case 'U':
				 if(param->username && *param->username){
					for(len = 0; i< 4000 && param->username[len]; len++){
					 buf[i] = param->username[len];
					 if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
					 if(doublec && strchr((char *)doublec, buf[i])) {
						buf[i+1] = buf[i];
						i++;
					 }
					 i++;
					}
				 }
				 else {
					buf[i++] = '-';
				 }
				 break;
				case 'n':
					len = param->hostname? (int)strlen((char *)param->hostname) : 0;
					if (len > 0 && !strchr((char *)param->hostname, ':')) for(len = 0; param->hostname[len] && i < 4000; len++, i++){
						buf[i] = param->hostname[len];
					 	if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
						if(doublec && strchr((char *)doublec, buf[i])) {
							buf[i+1] = buf[i];
							i++;
						}
					}
					else {
						buf[i++] = '[';
						i += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + i, 64);
						buf[i++] = ']';
					}
					break;

				case 'N':
				 if(param->service <= MAX_SERVICE) {
					 len = (conf.stringtable)? (int)strlen((char *)conf.stringtable[SERVICES + param->service]) : 0;
					 if(len > 20) len = 20;
					 memcpy(buf+i, (len)?conf.stringtable[SERVICES + param->service]:(unsigned char*)"-", (len)?len:1);
					 i += (len)?len:1;
				 }
				 break;
				case 'E':
				 sprintf((char *)buf+i, "%.05d", param->res);
				 i += 5;
				 break;
				case 'T':
				 if(s){
					for(len = 0; i<4000 && s[len]; len++){
					 buf[i] = s[len];
					 if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
					 if(doublec && strchr((char *)doublec, buf[i])) {
						buf[i+1] = buf[i];
						i++;
					 }
					 i++;
					}
				 }
				 break;
				case 'e':
				 i += myinet_ntop(*SAFAMILY(&param->sinsl), SAADDR(&param->sinsl), (char *)buf + i, 64);
				 break;
				case 'i':
				 i += myinet_ntop(*SAFAMILY(&param->sincl), SAADDR(&param->sincl), (char *)buf + i, 64);
				 break;
				case 'C':
				 i += myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + i, 64);
				 break;
				case 'R':
				 i += myinet_ntop(*SAFAMILY(&param->sinsr), SAADDR(&param->sinsr), (char *)buf + i, 64);
				 break;
				case 'Q':
				 i += myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + i, 64);
				 break;
				case 'p':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->srv->intsa)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'c':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sincr)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'r':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sinsr)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'q':
				 sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->req)));
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'L':
				 sprintf((char *)buf+i, "%"PRIu64"", param->cycles);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'I':
				 sprintf((char *)buf+i, "%"PRIu64"", param->statssrv64);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'O':
				 sprintf((char *)buf+i, "%"PRIu64"", param->statscli64);
				 i += (int)strlen((char *)buf+i);
				 break;
				case 'h':
				 sprintf((char *)buf+i, "%d", param->redirected);
				 i += (int)strlen((char *)buf+i);
				 break;
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					{
						int k, pmin=0, pmax=0;
						for (k = j; isnumber(format[k]); k++);
						if(format[k] == '-' && isnumber(format[k+1])){
							pmin = atoi(format + j) - 1;
							k++;
							pmax = atoi(format + k) -1;
							for (; isnumber(format[k]); k++);
							j = k;
						}
						if(!s || format[k]!='T') break;
						for(k = 0, len = 0; s[len] && i < 4000; len++){
							if(isspace(s[len])){
								k++;
								while(isspace(s[len+1]))len++;
								if(k == pmin) continue;
							}
							if(k>=pmin && k<=pmax) {
								buf[i] = s[len];
								if(param->srv->nonprintable && (buf[i] < 0x20 || strchr((char *)param->srv->nonprintable, buf[i]))) buf[i] = param->srv->replace;
								if(doublec && strchr((char *)doublec, buf[i])) {
									buf[i+1] = buf[i];
									i++;
				 				}
								i++;
							}
						}
						break;

					}
				case 0:
				 j--;
				default:
				 buf[i++] = format[j];
			}
		}
		else buf[i++] = format[j];
	}
	buf[i] = 0;
	return i;
}

int dobuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec){
	struct tm* tm;
	int i;
	char * format;
	time_t t;
	int has_srv;

	time(&t);
	has_srv = param && param->srv;
	if(has_srv){
		if(param->trafcountfunc)(*param->trafcountfunc)(param);
		format = param->srv->logformat?(char *)param->srv->logformat : DEFLOGFORMAT;
	}
	else {
		format = DEFLOGFORMAT;
	}
	tm = (*format == 'G' || *format == 'g')?
		gmtime(&t) : localtime(&t);
	i = dobuf2(param, buf, s, doublec, tm, format + 1);
	if(has_srv) clearstat(param);
	return i;
}

void lognone(struct clientparam * param, const unsigned char *s) {
	if(param->trafcountfunc)(*param->trafcountfunc)(param);
	clearstat(param);
}

NOINLINE void logstdout(struct clientparam * param, const unsigned char *s) {
	FILE *log;
	unsigned char tmpbuf[8192];

	dobuf(param, tmpbuf, s, NULL);
	log = (param && param->srv && param->srv->stdlog)?param->srv->stdlog:conf.stdlog?conf.stdlog:stdout;
	if(!param || !param->nolog)if(fprintf(log, "%s\n", tmpbuf) < 0) {
		perror("printf()");
	};
	if(log != conf.stdlog)fflush(log);
}
#ifndef _WIN32
void logsyslog(struct clientparam * param, const unsigned char *s) {

	unsigned char tmpbuf[8192];
	dobuf(param, tmpbuf, s, NULL);
	if(!param->nolog)syslog(LOG_INFO, "%s", tmpbuf);
}
#endif

