#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "ini.h"
#include "sv_config.h"
#include "iec61850_common.h"
#include "sv_publisher.h"
#include "hal_thread.h"


#define MATCH(a,b) (!strcmp(a?a:"", b?b:""))
#define SV_ALLOC_SZ 50
#define SV_MAX 256

#define DEBUG
#ifdef DEBUG
  #define debug(...) (printf(__VA_ARGS__))
#else
  #define debug(...)
#endif

SvConf def_conf = {0};
SvConf *sv_conf = NULL;
uint32_t sv_num = 0;
uint32_t sv_alloc = 0;



static int handler(void* user, const char* section, const char* key, const char* value, int lineno)
{
	static SvConf *conf = NULL;

	debug("==> [%s] %s = %s\n", section, key, value);

	// new section
	if (key == NULL) {
		if (MATCH(section, "default")) {
			// default values
			debug("- new section  = default\n");
			conf = &def_conf;
		} else {
			// sv stream
			debug("- new section (%d) = %s\n", sv_num, section);
			if (sv_num >= sv_alloc) {
				// allocate more space
				sv_alloc += SV_ALLOC_SZ;
				sv_conf = realloc(sv_conf, sv_alloc * sizeof(SvConf));
				debug("- allocate total = %d\n", sv_alloc);
			}
			conf = &sv_conf[sv_num];
			sv_num++;
			// copy from default
			memcpy(conf, &def_conf, sizeof(SvConf));
		}
		snprintf(conf->section, MAXLEN, section);
		return 1; //ok
	}

	if (conf == NULL) {
		printf("error (line %d): not allowed to have variables outside a section\n", lineno);
		return 0; //error
	}

	// fill key-value
	if (MATCH(key, "iface")) {
		if (conf == &def_conf) {
			snprintf(conf->iface, MAXLEN, value);
		} else {
			printf("error (line %d): not allowed to configure iface in regular stream, only in default\n", lineno);
			return 0; //error
		}
	} else if (MATCH(key, "mac")) {
		int ret = sv_parsemac(conf->mac, value, section);
		if (ret) {
			printf("error (line %d): not valid mac\n", lineno);
			return 0; //error
		}
		debug("parsed mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
			conf->mac[0], conf->mac[1], conf->mac[2], conf->mac[3], conf->mac[4], conf->mac[5]);
	} else if (MATCH(key, "vlanId")) {
		conf->vlanId = (uint16_t) strtol(value, NULL, 0);
	} else if (MATCH(key, "vlanPrio")) {
		conf->vlanPrio = (uint8_t) strtol(value, NULL, 0);
	} else if (MATCH(key, "appId")) {
		conf->appId = (uint16_t) strtol(value, NULL, 0);
	} else if (MATCH(key, "svId")) {
		snprintf(conf->svId, MAXLEN, value, section);
		debug("parsed svId = %s\n", conf->svId);
	} else if (MATCH(key, "datSet")) {
		snprintf(conf->datSet, MAXLEN, value, section);
		debug("parsed datSet = %s\n", conf->datSet);
	} else if (MATCH(key, "confRev")) {
		conf->confRev = (uint32_t) strtol(value, NULL, 0);
	} else if (MATCH(key, "smpCntWrap")) {
		conf->smpCntWrap = (uint32_t) strtol(value, NULL, 0);
	} else if (MATCH(key, "ia_mag")) {
		conf->ia_mag = strtod(value, NULL);
	} else if (MATCH(key, "ia_ang")) {
		conf->ia_ang = strtod(value, NULL);
	} else if (MATCH(key, "ia_q")) {
		conf->ia_q = sv_parseq(value);
	} else if (MATCH(key, "ib_mag")) {
		conf->ib_mag = strtod(value, NULL);
	} else if (MATCH(key, "ib_ang")) {
		conf->ib_ang = strtod(value, NULL);
	} else if (MATCH(key, "ib_q")) {
		conf->ib_q = sv_parseq(value);
	} else if (MATCH(key, "ic_mag")) {
		conf->ic_mag = strtod(value, NULL);
	} else if (MATCH(key, "ic_ang")) {
		conf->ic_ang = strtod(value, NULL);
	} else if (MATCH(key, "ic_q")) {
		conf->ic_q = sv_parseq(value);
	} else if (MATCH(key, "in_mag")) {
		conf->in_mag = strtod(value, NULL);
	} else if (MATCH(key, "in_ang")) {
		conf->in_ang = strtod(value, NULL);
	} else if (MATCH(key, "in_q")) {
		conf->in_q = sv_parseq(value);
	} else if (MATCH(key, "va_mag")) {
		conf->va_mag = strtod(value, NULL);
	} else if (MATCH(key, "va_ang")) {
		conf->va_ang = strtod(value, NULL);
	} else if (MATCH(key, "va_q")) {
		conf->va_q = sv_parseq(value);
	} else if (MATCH(key, "vb_mag")) {
		conf->vb_mag = strtod(value, NULL);
	} else if (MATCH(key, "vb_ang")) {
		conf->vb_ang = strtod(value, NULL);
	} else if (MATCH(key, "vb_q")) {
		conf->vb_q = sv_parseq(value);
	} else if (MATCH(key, "vc_mag")) {
		conf->vc_mag = strtod(value, NULL);
	} else if (MATCH(key, "vc_ang")) {
		conf->vc_ang = strtod(value, NULL);
	} else if (MATCH(key, "vc_q")) {
		conf->vc_q = sv_parseq(value);
	} else if (MATCH(key, "vn_mag")) {
		conf->vn_mag = strtod(value, NULL);
	} else if (MATCH(key, "vn_ang")) {
		conf->vn_ang = strtod(value, NULL);
	} else if (MATCH(key, "vn_q")) {
		conf->vn_q = sv_parseq(value);
	} else {
		//TODO
		printf("error (line %d): attribute '%s' unsupported\n", lineno, key);
		return 0; //error
	}

	return 1; //ok
}

// GOOD, INVALID, RESERVED, QUESTIONABLE,
// OVERFLOW, OUT_OF_RANGE, BAD_REFERENCE, OSCILLATORY, FAILURE, OLD_DATA, INCONSISTENT, INACCURATE,
// SUBSTITUTED, TEST, OPERATOR_BLOCKED , DERIVED

uint16_t sv_parseq(const char *value)
{
	uint16_t q = 0;

	char* token;
	char *delim = ",|";

	for (char *token = strtok(value, delim);
		token != NULL;
		token = strtok(NULL, delim))
	{
		if (MATCH(token, "GOOD")) {
			q |= QUALITY_VALIDITY_GOOD;
		} else if (MATCH(token, "INVALID")) {
			q |= QUALITY_VALIDITY_INVALID;
		} else if (MATCH(token, "QUESTIONABLE")) {
			q |= QUALITY_VALIDITY_QUESTIONABLE;
		} else if (MATCH(token, "TEST")) {
			q |= QUALITY_TEST;
		} else if (MATCH(token, "DERIVED")) {
			q |= QUALITY_DERIVED;
		} else {
			//TODO ADD MORE Q
			printf("error: unsupported quality '%s'\n", token ? token : "nil");
			return -1;
		}
	}
	return q;
}
int32_t sv_parsemac(uint8_t *mac, const char *value, const char *section)
{
	uint8_t i = 0;

	char temp[MAXLEN];
	snprintf(temp, MAXLEN, value, section);


	char* token;
	char *delim = ":-";

	for (char *token = strtok(temp, delim);
		token != NULL;
		token = strtok(NULL, delim))
	{
		uint32_t octet = strtoul(token, NULL, 16);
		if (octet >= 256 || i >= 6) {
			printf("error: parsing mac\n");
			return -1;
		}
		mac[i] = (uint8_t) octet;
		i++;
	}
	return 0;
}

void printSvConf(SvConf *conf)
{
	printf("============ %s ===========\n", conf->section);
	printf("iface: %s, mac: %02x:%02x:%02x:%02x:%02x:%02x, vlanPrio: %d, vlanId: %d, appId: 0x%04x\n",
		conf->iface, conf->mac[0], conf->mac[1], conf->mac[2], conf->mac[3], conf->mac[4], conf->mac[5], conf->vlanPrio, conf->vlanId, conf->appId);
	printf("svId: %s, datSet: %s, confRev: %d\n", conf->svId, conf->datSet, conf->confRev);
	printf("ia: {%.1f, %.1f, 0x%04x}, ib: {%.1f, %.1f, 0x%04x}, ic: {%.1f, %.1f, 0x%04x}, in: {%.1f, %.1f, 0x%04x}\n",
		conf->ia_mag, conf->ia_ang, conf->ia_q, conf->ib_mag, conf->ib_ang, conf->ib_q,
		conf->ic_mag, conf->ic_ang, conf->ic_q, conf->in_mag, conf->in_ang, conf->in_q);
	printf("va: {%.1f, %.1f, 0x%04x}, vb: {%.1f, %.1f, 0x%04x}, vc: {%.1f, %.1f, 0x%04x}, vn: {%.1f, %.1f, 0x%04x}\n",
		conf->va_mag, conf->va_ang, conf->va_q, conf->vb_mag, conf->vb_ang, conf->vb_q,
		conf->vc_mag, conf->vc_ang, conf->vc_q, conf->vn_mag, conf->vn_ang, conf->vn_q);
}

int32_t sv_smppoint(double rms, double degrees, double fact, int32_t point)
{
	double radians = 2 * M_PI * degrees / 360.0 + 2 * M_PI * point / 80.0;
	return (int32_t) (rms * sqrt(2) * sin(radians) * fact);
}


uint16_t reverse16(uint16_t x)
{
    x = (((x & 0xAAAA) >> 1) | ((x & 0x5555) << 1));
    x = (((x & 0xCCCC) >> 2) | ((x & 0x3333) << 2));
    x = (((x & 0xF0F0) >> 4) | ((x & 0x0F0F) << 4));
    return (x >> 8) | (x << 8);
}


struct sSvSocket {
	int32_t socket;
	struct {
		struct sockaddr_ll address[SV_MAX];
		struct mmsghdr msgvec[SV_MAX];
		struct iovec iov[SV_MAX];
	} samp[SAMPLEWRAP];
};
struct sSvSocket sv_socket;

int getInterfaceIndex(int sock, const char* deviceName)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, deviceName, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        if (DEBUG_SOCKET)
            printf("ETHERNET_LINUX: Failed to get interface index");
        return -1;
    }
    return ifr.ifr_ifindex;
}


int32_t sv_prepare(uint8_t *samples, SvConf *conf, uint32_t sv)
{
	CommParameters params;
	params.vlanPriority = conf[sv].vlanPrio;
	params.vlanId = conf[sv].vlanId;
	params.appId = conf[sv].appId;
	params.dstAddress[0] = conf[sv].mac[0];
	params.dstAddress[1] = conf[sv].mac[1];
	params.dstAddress[2] = conf[sv].mac[2];
	params.dstAddress[3] = conf[sv].mac[3];
	params.dstAddress[4] = conf[sv].mac[4];
	params.dstAddress[5] = conf[sv].mac[5];

	SVPublisher svp = SVPublisher_create(&params, conf[sv].iface);
	if (!svp) {
		printf("error: SVPublisher_create, run as root? \n");
		return -1;
	}

	SVPublisher_ASDU asdu = SVPublisher_addASDU(svp, conf[sv].svId, strlen(conf[sv].datSet) ? conf[sv].datSet : NULL, conf[sv].confRev);
	
	int32_t amp1 = SVPublisher_ASDU_addINT32(asdu);
	int32_t amp1q = SVPublisher_ASDU_addQuality(asdu);
	int32_t amp2 = SVPublisher_ASDU_addINT32(asdu);
	int32_t amp2q = SVPublisher_ASDU_addQuality(asdu);
	int32_t amp3 = SVPublisher_ASDU_addINT32(asdu);
	int32_t amp3q = SVPublisher_ASDU_addQuality(asdu);
	int32_t amp4 = SVPublisher_ASDU_addINT32(asdu);
	int32_t amp4q = SVPublisher_ASDU_addQuality(asdu);
	int32_t vol1 = SVPublisher_ASDU_addINT32(asdu);
	int32_t vol1q = SVPublisher_ASDU_addQuality(asdu);
	int32_t vol2 = SVPublisher_ASDU_addINT32(asdu);
	int32_t vol2q = SVPublisher_ASDU_addQuality(asdu);
	int32_t vol3 = SVPublisher_ASDU_addINT32(asdu);
	int32_t vol3q = SVPublisher_ASDU_addQuality(asdu);
	int32_t vol4 = SVPublisher_ASDU_addINT32(asdu);
	int32_t vol4q = SVPublisher_ASDU_addQuality(asdu);

	//SVPublisher_ASDU_setSmpCntWrap(asdu, SAMPLEWRAP);//?
	SVPublisher_setupComplete(svp);

	for (uint16_t smp = 0; smp < SAMPLEWRAP; smp++) {
		SVPublisher_ASDU_setSmpCnt(asdu, smp);
		uint8_t point = smp % 80;

		// update currents
		int32_t currentA = sv_smppoint(conf[sv].ia_mag, conf[sv].ia_ang, 1000, point);
 		SVPublisher_ASDU_setINT32(asdu, amp1, currentA);
		SVPublisher_ASDU_setQuality(asdu, amp1q, reverse16(conf[sv].ia_q));
		int32_t currentB = sv_smppoint(conf[sv].ib_mag, conf[sv].ib_ang, 1000, point);
 		SVPublisher_ASDU_setINT32(asdu, amp2, currentB);
		SVPublisher_ASDU_setQuality(asdu, amp2q, reverse16(conf[sv].ib_q));
		int32_t currentC = sv_smppoint(conf[sv].ic_mag, conf[sv].ic_ang, 1000, point);
		SVPublisher_ASDU_setINT32(asdu, amp3, currentC);
		SVPublisher_ASDU_setQuality(asdu, amp3q, reverse16(conf[sv].ic_q));
		if (conf[sv].in_q & QUALITY_DERIVED) {
			SVPublisher_ASDU_setINT32(asdu, amp4, currentA + currentB + currentC);
		} else {
			int32_t currentN = sv_smppoint(conf[sv].in_mag, conf[sv].in_ang, 1000, point);
			SVPublisher_ASDU_setINT32(asdu, amp4, currentN);
		}
		SVPublisher_ASDU_setQuality(asdu, amp4q, reverse16(conf[sv].in_q));

		// update voltages
		int32_t voltageA = sv_smppoint(conf[sv].va_mag, conf[sv].va_ang, 100, point);
 		SVPublisher_ASDU_setINT32(asdu, vol1, voltageA);
		SVPublisher_ASDU_setQuality(asdu, vol1q, reverse16(conf[sv].va_q));
		int32_t voltageB = sv_smppoint(conf[sv].vb_mag, conf[sv].vb_ang, 100, point);
 		SVPublisher_ASDU_setINT32(asdu, vol2, voltageB);
		SVPublisher_ASDU_setQuality(asdu, vol3q, reverse16(conf[sv].vb_q));
		int32_t voltageC = sv_smppoint(conf[sv].vc_mag, conf[sv].vc_ang, 100, point);
		SVPublisher_ASDU_setINT32(asdu, vol3, voltageC);
		SVPublisher_ASDU_setQuality(asdu, vol3q, reverse16(conf[sv].vc_q));
		if (conf[sv].vn_q & QUALITY_DERIVED) {
			SVPublisher_ASDU_setINT32(asdu, vol4, voltageA + voltageB + voltageC);
		} else {
			int32_t voltageN = sv_smppoint(conf[sv].vn_mag, conf[sv].vn_ang, 100, point);
			SVPublisher_ASDU_setINT32(asdu, vol4, voltageN);
		}
		SVPublisher_ASDU_setQuality(asdu, vol4q, reverse16(conf[sv].vn_q));

		// copy packet
		uint8_t *buffer;
		uint32_t bufLen;
		SVPublisher_getBuffer(svp, &buffer, &bufLen);
		if (bufLen > PACKETSIZE) {
			printf("error: packet size (%d) too big\n", bufLen);
			return -1;
		}
		uint8_t *sample_ptr = samples + smp * sv_num * PACKETSIZE + sv * PACKETSIZE;// uint8_t sv_samples[SAMPLEWRAP][sv_num][PACKETSIZE]
		memcpy(sample_ptr, buffer, bufLen);

		// prepare sendmmsg info
		sv_socket.samp[smp].address[sv].sll_family = AF_PACKET;
		sv_socket.samp[smp].address[sv].sll_protocol = htons(0x88ba);
		sv_socket.samp[smp].address[sv].sll_ifindex = getInterfaceIndex(sv_socket.socket, conf[sv].iface);
		sv_socket.samp[smp].address[sv].sll_halen = ETH_ALEN;
		sv_socket.samp[smp].address[sv].sll_addr[0] = conf[sv].mac[0];
		sv_socket.samp[smp].address[sv].sll_addr[1] = conf[sv].mac[1];
		sv_socket.samp[smp].address[sv].sll_addr[2] = conf[sv].mac[2];
		sv_socket.samp[smp].address[sv].sll_addr[3] = conf[sv].mac[3];
		sv_socket.samp[smp].address[sv].sll_addr[4] = conf[sv].mac[4];
		sv_socket.samp[smp].address[sv].sll_addr[5] = conf[sv].mac[5];
		sv_socket.samp[smp].address[sv].sll_hatype = 0; // not needed
		sv_socket.samp[smp].address[sv].sll_pkttype = 0; // not needed
		sv_socket.samp[smp].msgvec[sv].msg_hdr.msg_name = &sv_socket.samp[smp].address[sv];
		sv_socket.samp[smp].msgvec[sv].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
		sv_socket.samp[smp].msgvec[sv].msg_hdr.msg_iov = &sv_socket.samp[smp].iov[sv];
		sv_socket.samp[smp].msgvec[sv].msg_hdr.msg_iovlen = 1;
		sv_socket.samp[smp].msgvec[sv].msg_hdr.msg_control = NULL;
		sv_socket.samp[smp].msgvec[sv].msg_hdr.msg_controllen = 0;
		sv_socket.samp[smp].iov[sv].iov_base = sample_ptr;
		sv_socket.samp[smp].iov[sv].iov_len = bufLen;
	}

	SVPublisher_destroy(svp);
	return 0;
}

#define NEXT_SV 250000
void clock_addinterval(struct timespec *ts, unsigned long ns)
{
	ts->tv_nsec += ns;
	while (ts->tv_nsec >= 1000000000) {
		ts->tv_nsec -= 1000000000;
		ts->tv_sec += 1;
	}
}
uint64_t clock_gettime_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t) ts.tv_sec) * 1000 + (ts.tv_nsec / 1000000);
}
int32_t clock_getdiff_us(struct timespec *tsref)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((tsref->tv_sec - ts.tv_sec)) * 1000000 + ((tsref->tv_nsec - ts.tv_nsec) / 1000);
}


int main(int argc, char* argv[])
{
	uint32_t sv_lim = 0;
	if (argc <= 1) {
		printf("Usage: %s filename.ini sv_lim\n", argv[0]);
		return 1;
	}
	if (argc > 2) {
		sv_lim = atoi(argv[2]);
	}

	int error = ini_parse(argv[1], handler, NULL);

	if (error < 0) {
		printf("Can't read '%s'!\n", argv[1]);
		return 2;
	}
	else if (error) {
		printf("Bad config file (first error on line %d)!\n", error);
		return 3;
	}

	// print conf
	for (int i = 0; i < sv_num; i++) {
		printSvConf(&sv_conf[i]);
	}
	

	debug("==========================\n");
	if (sv_num > SV_MAX) {
		printf("error: too many sv (%d > %d)\n", sv_num, SV_MAX);
		return -1;
	} else if ((sv_num > sv_lim) && (sv_lim > 0)) {
		debug("Succesfully parsed %d SV streams. Limited to %d \n", sv_num, sv_lim);
		sv_num = sv_lim;
	} else {
		debug("Succesfully parsed %d SV streams \n", sv_num);
	}
	
	uint32_t sv_sample_sz = PACKETSIZE * SAMPLEWRAP * sv_num;
	uint8_t *sv_samples = (uint8_t *) malloc(sv_sample_sz); // uint8_t sv_samples[SAMPLEWRAP][sv_num][PACKETSIZE]
	memset(sv_samples, 0, sv_sample_sz);

	debug("==========================\n"
		"creating packets (%d bytes) \n", sv_sample_sz);
	debug("==========================\n"
		"estimated output: %dK pps) \n", sv_num * 4);

	sv_socket.socket = socket(AF_PACKET, SOCK_RAW, 0);
	// int32_t sock_qdisc_bypass = 1;
	// errno = 0;
	// int32_t sock_qdisc_ret = setsockopt(sv_socket.socket, SOL_PACKET, PACKET_QDISC_BYPASS, &sock_qdisc_bypass, sizeof(sock_qdisc_bypass));
	// debug("setsockopt PACKET_QDISC_BYPASS returned %d, errno %d\n", sock_qdisc_ret, errno);


	for (int i = 0; i < sv_num; i++) {
		int ret = sv_prepare(sv_samples, sv_conf, i);
		if (ret < 0) {
			printf("error: sv_prepare failed (%d)\n", ret);
			return -1;
		}
	}


#if 0
	for (int smp = 0; smp < SAMPLEWRAP; smp++) {
		for (int sv = 0; sv < sv_num; sv++) {
			uint8_t *b = sv_samples + smp * sv_num * PACKETSIZE + sv * PACKETSIZE;// uint8_t sv_samples[SAMPLEWRAP][sv_num][PACKETSIZE]
			debug("========= sv %d smp %d =========\n", sv, smp);
			uint8_t blen = sv_len;
			while (blen > 0) {
				char line[128];
				sprintf(line, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
						b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
				if (blen >= 16) {
					b += 16;
					blen -=16;
				} else {
					line[3*blen] = '\0';
					blen = 0;
				}
				debug("%s\n", line);
			}
		}
	}
#endif

	debug("start sending\n");
	int32_t sleeptimes[600] = {0};
	int32_t sleepindex = 0;

	// start sending
	struct timespec tsnext;
	clock_gettime(CLOCK_MONOTONIC, &tsnext);

	bool running = true;
	while (running) {
		for (uint32_t smp = 0; smp < SAMPLEWRAP; smp++) {
			// sleep until next 250us
			clock_addinterval(&tsnext, NEXT_SV);
			if (smp % 400 == 0) {
				sleeptimes[sleepindex++] = clock_getdiff_us(&tsnext);
				if (sleepindex >= sizeof(sleeptimes)/sizeof(int32_t)) {
					for (int i = 0; i < sizeof(sleeptimes)/sizeof(int32_t); i++) {
						debug("diff time [%d] = %d us\n", i, sleeptimes[i]);
					}
					return 0;
				}
			}
			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &tsnext, NULL);

			// if (smp % 4 == 0) {
			// 	// sync every 1ms, 4 samples
			// 	clock_addinterval(&tsnext, 4*NEXT_SV);
			// 	int32_t diff = clock_getdiff_us(&tsnext);
			// 	if (diff > 10) {
			// 		usleep(diff - 10);
			// 	}
			// 	if (smp % 400 == 0) {
			// 		sleeptimes[sleepindex++] = diff;
			// 		if (sleepindex >= sizeof(sleeptimes)/sizeof(int32_t)) {
			// 			for (int i = 0; i < sizeof(sleeptimes)/sizeof(int32_t); i++) {
			// 				debug("diff time [%d] = %d us\n", i, sleeptimes[i]);
			// 			}
			// 			return 0;
			// 		}
			// 	}
			// }
			// send all sv for sample
			errno = 0;
			int res = sendmmsg(sv_socket.socket, sv_socket.samp[smp].msgvec, sv_num, 0);
			if (res == -1) {
				printf("sendmsg returned -1, errno = %d\n", errno);
				return -1;
			} else {
				//debug("smp %d, sendmsg returned %d\n", smp, res);
			}
		}
	}



	
	return 0;
}