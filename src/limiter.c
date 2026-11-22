/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

#include "proxy.h"

int startconnlims (struct clientparam *param){
	struct connlim * ce;
	time_t delta;
	uint64_t rating;
	int ret = 0;

	param->connlim = 1;
	_3proxy_mutex_lock(&connlim_mutex);
	for(ce = conf.connlimiter; ce; ce = ce->next) {
		if(ACLmatches(ce->ace, param)){
			if(ce->ace->action == NOCONNLIM)break;
			if(!ce->period){
				if(ce->rate <= ce->rating) {
					ret = 1;
					break;
				}
				ce->rating++;
				continue;
			}
			delta = conf.time - ce->basetime;
			if(ce->period <= delta || ce->basetime > conf.time){
				ce->basetime = conf.time;
				ce->rating = 0x100000;
				continue;
			}
			rating = delta? ((ce->rating * (ce->period - delta)) / ce->period) + 0x100000 : ce->rating + 0x100000;
			if (rating > (ce->rate<<20)) {
				ret = 2;
				break;
			}
			ce->rating = rating;
			ce->basetime = conf.time;
		}
	}
	if(ret) {
		struct connlim * cee;
		for(cee = conf.connlimiter; cee != ce; cee = cee->next) {
			if(ACLmatches(cee->ace, param) && !cee->period && cee->rating) {
				cee->rating--;
			}
		}
		param->connlim = 0;
	}
	_3proxy_mutex_unlock(&connlim_mutex);
	return ret;
}

void stopconnlims (struct clientparam *param){
	struct connlim * ce;

	_3proxy_mutex_lock(&connlim_mutex);
	for(ce = conf.connlimiter; ce; ce = ce->next) {
		if(ACLmatches(ce->ace, param)){
			if(ce->ace->action == NOCONNLIM)break;
			if(!ce->period && ce->rating){
				ce->rating--;
				continue;
			}
		}
	}
	_3proxy_mutex_unlock(&connlim_mutex);
}

void initbandlims (struct clientparam *param){
	struct bandlim * be;
	int i;

	param->bandlimfunc = NULL;
	param->bandlims[0] = NULL;
	param->bandlimsout[0] = NULL;
	param->userbandthrottled = 0;
	param->userbandratein = param->userbandrateout = 0;
	if(!conf.bandlimfunc || (!conf.bandlimiter && !conf.bandlimiterout)) return;
	for(i=0, be = conf.bandlimiter; be && i<MAXBANDLIMS; be = be->next) {
		if(ACLmatches(be->ace, param)){
			if(be->ace->action == NOBANDLIM) {
				break;
			}
			param->bandlims[i++] = be;
			param->bandlimfunc = conf.bandlimfunc;
			if(be->peruser && (!param->userbandratein || be->rate < param->userbandratein))
				param->userbandratein = be->rate;
		}
	}
	if(i<MAXBANDLIMS)param->bandlims[i] = NULL;
	for(i=0, be = conf.bandlimiterout; be && i<MAXBANDLIMS; be = be->next) {
		if(ACLmatches(be->ace, param)){
			if(be->ace->action == NOBANDLIM) {
				break;
			}
			param->bandlimsout[i++] = be;
			param->bandlimfunc = conf.bandlimfunc;
			if(be->peruser && (!param->userbandrateout || be->rate < param->userbandrateout))
				param->userbandrateout = be->rate;
		}
	}
	if(i<MAXBANDLIMS)param->bandlimsout[i] = NULL;
	param->bandlimver = conf.bandlimver;
}

/* The mutex is held by the caller. A user name which is absent shares one
   anonymous bucket, so a per-user rule with no authentication cannot be
   escaped by simply not sending a name. */
static struct bandlimuser * bandlimuser(struct bandlim *be, struct clientparam *param){
	struct bandlimuser *bu;
	const unsigned char *user = (param->username && *param->username)?
		param->username : (const unsigned char *)"-";

	for(bu = be->users; bu; bu = bu->next){
		if(!strcmp((char *)bu->user, (char *)user)) return bu;
	}
	bu = malloc(sizeof(struct bandlimuser));
	if(!bu) return NULL;
	memset(bu, 0, sizeof(struct bandlimuser));
	bu->user = (unsigned char *)strdup((char *)user);
	if(!bu->user){
		free(bu);
		return NULL;
	}
	bu->next = be->users;
	be->users = bu;
	return bu;
}

static unsigned bandlimitrule(struct clientparam *param, struct bandlim *be,
	unsigned nbytes, int outgoing, time_t sec, unsigned msec){
	time_t *basetime = &be->basetime;
	unsigned *nexttime = &be->nexttime;
	unsigned now, nsleeptime;
	uint64_t delay;

	if(be->peruser){
		struct bandlimuser *bu = bandlimuser(be, param);

		if(bu){
			basetime = &bu->basetime;
			nexttime = &bu->nexttime;
		}
	}
	if(!*basetime || *basetime > sec || *basetime < (sec - 120)){
		*basetime = sec;
		*nexttime = msec;
	}
	now = (unsigned)((sec - *basetime) * 1000000) + msec;
	nsleeptime = (*nexttime > now)? *nexttime - now : 0;
	*basetime = sec;
	if(outgoing){
		delay = (nbytes > 512)?
			(uint64_t)((nbytes + 32) / 64) * ((64 * 8 * 1000000) / be->rate) :
			(uint64_t)(nbytes + 1) * (8 * 1000000) / be->rate;
	}
	else {
		delay = ((uint64_t)nbytes * 8 * 1000000) / be->rate;
	}
	*nexttime = msec + (uint64_t)nsleeptime + delay;
	if(nsleeptime) param->userbandthrottled = 1;
	return nsleeptime;
}

unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout){
	unsigned sleeptime = 0, nsleeptime;
	time_t sec;
	unsigned msec;
	int i;

#ifdef _WIN32
	struct timeb tb;

	ftime(&tb);
	sec = (unsigned)tb.time;
	msec = (unsigned)tb.millitm*1000;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);

	sec = tv.tv_sec;
	msec = tv.tv_usec;
#endif

	if(!nbytesin && !nbytesout) return 0;
	_3proxy_mutex_lock(&bandlim_mutex);
	if(param->bandlimver != conf.bandlimver){
		initbandlims(param);
		param->bandlimver = conf.bandlimver;
	}
	for(i=0; nbytesin&& i<MAXBANDLIMS && param->bandlims[i]; i++){
		nsleeptime = bandlimitrule(param, param->bandlims[i], nbytesin, 0, sec, msec);
		sleeptime = (nsleeptime > sleeptime)? nsleeptime : sleeptime;
	}
	for(i=0; nbytesout && i<MAXBANDLIMS && param->bandlimsout[i]; i++){
		nsleeptime = bandlimitrule(param, param->bandlimsout[i], nbytesout, 1, sec, msec);
		sleeptime = (nsleeptime > sleeptime)? nsleeptime : sleeptime;
	}
	_3proxy_mutex_unlock(&bandlim_mutex);
	return sleeptime/1000;
}

void trafcountfunc(struct clientparam *param){
	struct trafcount * tc;
	int countout = 0;

	_3proxy_mutex_lock(&tc_mutex);
	for(tc = conf.trafcounter; tc; tc = tc->next) {
		if(ACLmatches(tc->ace, param)){

			if(tc->ace->action == NOCOUNTIN) {
				countout = 1;
				break;
			}
			if(tc->ace->action == NOCOUNTALL) break;
			if(tc->ace->action != COUNTIN && tc->ace->action != COUNTALL) {
				countout = 1;
				continue;
			}
			tc->traf64 += param->statssrv64;
			tc->updated = conf.time;
		}
	}
	if(countout) for(tc = conf.trafcounter; tc; tc = tc->next) {
		if(ACLmatches(tc->ace, param)){
			if(tc->ace->action == NOCOUNTOUT || tc->ace->action == NOCOUNTALL) break;
			if(tc->ace->action != COUNTOUT && tc->ace->action != COUNTALL ) {
				continue;
			}
			tc->traf64 += param->statscli64;
			tc->updated = conf.time;
		}
	}

	_3proxy_mutex_unlock(&tc_mutex);
}

