/*
 *  iec61850_9_2_LE_example.c
 *
 *  Copyright 2016 Michael Zillgith
 *
 *  This file is part of libIEC61850.
 *
 *  libIEC61850 is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libIEC61850 is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libIEC61850.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  See COPYING file for the complete license text.
 */

#define _GNU_SOURCE

//#include "iec61850_server.h"
#include "sv_publisher.h"
//#include "hal_thread.h"
#include "hal_ethernet.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <errno.h>


static int running = 0;
static int svcbEnabled = 1;

void sigint_handler(int signalId)
{
	running = 0;
}

#define SV_SIZE 256
#define NUM_SV 50
#define NUM_ROLLOVER 2000
#define IFACE "enp3s0" //"enp3s0"
#define DO_CALC 1

struct sEthRaw {
	int rawSocket;
	struct sockaddr_ll socketAddress[NUM_SV];
	struct mmsghdr msgvec[NUM_SV];
	uint32_t msgvlen;
	struct iovec iov[NUM_SV];
};
struct sEthRaw ethRaw = {0};


struct sSV {
	SVPublisher svPublisher;
	SVPublisher_ASDU asdu;
	int amp1;
	int amp2;
	int amp3;
	int amp4;
	int amp1q;
	int amp2q;
	int amp3q;
	int amp4q;
	int vol1;
	int vol2;
	int vol3;
	int vol4;
	int vol1q;
	int vol2q;
	int vol3q;
	int vol4q;
};
struct sSV sv_pubs[NUM_SV] = {0};

struct fEthernetSocket {
	int rawSocket;
	bool isBind;
	struct sockaddr_ll socketAddress;
};

struct fSVPublisher {
	uint8_t* buffer;
	uint16_t appId;
	struct fEthernetSocket *ethernetSocket;

	int lengthField; /* can probably be removed since packets have fixed size! */
	int payloadStart;

	int payloadLength; /* length of payload buffer */

	int asduCount; /* number of ASDUs in the APDU */
	SVPublisher_ASDU asduList;
};

struct fSVPublisher_ASDU {
	const char* svID;
	const char* datset;
	int dataSize;

	bool hasRefrTm;
	bool hasSmpRate;
	bool hasSmpMod;

	uint8_t* _dataBuffer;

	uint8_t smpSynch;
	uint16_t smpCnt;
	uint16_t smpCntLimit;
	uint32_t confRev;

	uint64_t refrTm;
	uint8_t smpMod;
	uint16_t smpRate;

	uint8_t* smpCntBuf;
	uint8_t* refrTmBuf;
	uint8_t* smpSynchBuf;

	void *_next;
};


void print_sv(struct fSVPublisher *svp, struct fSVPublisher_ASDU *asdu)
{
	printf("***************** %s *****************\n", asdu->svID);

	uint8_t *b = svp->buffer;
	uint32_t blen = svp->payloadStart + svp->payloadLength;
	while (blen > 0) {
		char line[256];
		sprintf(line, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
				b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
		if (blen >= 16) {
			b += 16;
			blen -=16;
		} else {
			line[3*blen] = '\0';
			blen = 0;
		}
		printf("%s\n", line);
	}
}

int
setupSVPublishers(const char* svInterface, uint32_t num)
{
	//
	CommParameters parameters = {4, 3, 0x4000, {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00}};

	for (int i = 0; i < num; i++) {
		struct sSV *sv = &sv_pubs[i];
		parameters.appId++;
		parameters.dstAddress[5]++;
		sv->svPublisher = SVPublisher_create(&parameters, svInterface);
		if (!sv->svPublisher) {
			return -1;
		}
		char svId[256];
		sprintf(svId, "AnotherMUnn%03d", i);
		sv->asdu = SVPublisher_addASDU(sv->svPublisher, svId, NULL, 1);
		sv->amp1 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->amp1q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->amp2 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->amp2q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->amp3 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->amp3q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->amp4 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->amp4q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->vol1 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->vol1q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->vol2 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->vol2q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->vol3 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->vol3q = SVPublisher_ASDU_addQuality(sv->asdu);
		sv->vol4 = SVPublisher_ASDU_addINT32(sv->asdu);
		sv->vol4q = SVPublisher_ASDU_addQuality(sv->asdu);

		SVPublisher_ASDU_setSmpCntWrap(sv->asdu, NUM_ROLLOVER);
		SVPublisher_ASDU_setRefrTm(sv->asdu, 0);
		SVPublisher_setupComplete(sv->svPublisher);

		struct fSVPublisher *svp = (struct fSVPublisher *) sv->svPublisher;
		struct fSVPublisher_ASDU *asdu = (struct fSVPublisher_ASDU *) sv->asdu;

		print_sv(svp, asdu);

		// 
		if (i == 0) {
			ethRaw.rawSocket = svp->ethernetSocket->rawSocket;
			ethRaw.msgvlen = num;
		}
		ethRaw.socketAddress[i] = svp->ethernetSocket->socketAddress;
		ethRaw.msgvec[i].msg_hdr.msg_name = &ethRaw.socketAddress[i];
		ethRaw.msgvec[i].msg_hdr.msg_namelen = sizeof(ethRaw.socketAddress[i]);
		ethRaw.msgvec[i].msg_hdr.msg_iov = &ethRaw.iov[i];
		ethRaw.msgvec[i].msg_hdr.msg_iovlen = 1;
		ethRaw.iov[i].iov_base = svp->buffer;
		ethRaw.iov[i].iov_len = svp->payloadStart + svp->payloadLength;

		printf("sock = %d, len = %d\n", svp->ethernetSocket->rawSocket, ethRaw.iov[i].iov_len);
	}
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

uint16_t reverse16(uint16_t x)
{
    x = (((x & 0xAAAA) >> 1) | ((x & 0x5555) << 1));
    x = (((x & 0xCCCC) >> 2) | ((x & 0x3333) << 2));
    x = (((x & 0xF0F0) >> 4) | ((x & 0x0F0F) << 4));
    return (x >> 8) | (x << 8);
}


int main(int argc, char** argv)
{
	uint32_t num_sv = NUM_SV;
	char* iface = IFACE;

	if (argc > 1) {
		num_sv = atoi(argv[1]);
	}
	if (argc > 2) {
		iface = argv[2];
	}
		

	running = 1;

	signal(SIGINT, sigint_handler);

	int ret = setupSVPublishers(iface, num_sv);
	if (ret) {
		printf("Cannot start SV publisher!\n");
		return -1;
	}

	Quality q = reverse16(QUALITY_VALIDITY_INVALID);

	int vol = (int) (6350.f * sqrt(2));
	int amp = 5.0;
	float phaseAngle = 0.f;

	int voltageA = 0;
	int voltageB = 0;
	int voltageC = 0;
	int voltageN = 0;
	int currentA = 0;
	int currentB = 0;
	int currentC = 0;
	int currentN = 0;

	int sampleCount = 0;

	printf("================ start sending %d sv in iface %s ================\n", num_sv, iface);

	struct timespec ts_timer;
	clock_gettime(CLOCK_MONOTONIC, &ts_timer);

	while (running) {

		/* update measurement values */
		int samplePoint = sampleCount % 80;
#if DO_CALC
		double angleA = (2 * M_PI / 80) * samplePoint;
		double angleB = (2 * M_PI / 80) * samplePoint - ( 2 * M_PI / 3);
		double angleC = (2 * M_PI / 80) * samplePoint - ( 4 * M_PI / 3);

		voltageA = (vol * sin(angleA)) * 100;
		voltageB = (vol * sin(angleB)) * 100;
		voltageC = (vol * sin(angleC)) * 100;
		voltageN = voltageA + voltageB + voltageC;

		currentA = (amp * sin(angleA - phaseAngle)) * 1000;
		currentB = (amp * sin(angleB - phaseAngle)) * 1000;
		currentC = (amp * sin(angleC - phaseAngle)) * 1000;
		currentN = currentA + currentB + currentC;
#endif

		struct timespec ts_now;
		clock_gettime(CLOCK_MONOTONIC, &ts_now);
		clock_addinterval(&ts_timer, NEXT_SV);
		if ((ts_timer.tv_sec > ts_now.tv_sec) || ((ts_timer.tv_sec == ts_now.tv_sec) && (ts_timer.tv_nsec > ts_now.tv_nsec))) {
			// sleep until next 250us
			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts_timer, NULL);
			clock_gettime(CLOCK_MONOTONIC, &ts_now);
		}
		uint64_t refrTm = ((uint64_t) ts_now.tv_sec) * 1000LL + (ts_now.tv_nsec / 1000000);


		for (int i = 0; i < NUM_SV; i++) {
			struct sSV *sv = &sv_pubs[i];
#if DO_CALC
			SVPublisher_ASDU_setINT32(sv->asdu, sv->amp1, currentA);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->amp1q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->amp2, currentB);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->amp2q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->amp3, currentC);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->amp3q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->amp4, currentN);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->amp4q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->vol1, voltageA);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->vol1q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->vol2, voltageB);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->vol2q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->vol3, voltageC);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->vol3q, q);
			SVPublisher_ASDU_setINT32(sv->asdu, sv->vol4, voltageN);
			SVPublisher_ASDU_setQuality(sv->asdu, sv->vol4q, q);
#endif
			SVPublisher_ASDU_setRefrTm(sv->asdu, refrTm);
			SVPublisher_ASDU_setSmpCnt(sv->asdu, (uint16_t) sampleCount);
			//SVPublisher_publish(sv->svPublisher);
		}
		
		errno = 0;
		int res = sendmmsg(ethRaw.rawSocket, &ethRaw.msgvec, ethRaw.msgvlen, 0);
		if (res == -1) {
			printf("sendmsg returned -1, errno = %d\n", errno);
			return -1;
		}

		sampleCount++;
		if (sampleCount >= NUM_ROLLOVER) {
			sampleCount -= NUM_ROLLOVER;
			struct timespec tp;
			clock_gettime(CLOCK_MONOTONIC, &tp);
			int64_t diff = ((uint64_t) (tp.tv_sec - ts_timer.tv_sec)) * 1000LL + ((tp.tv_nsec - ts_timer.tv_nsec) / 1000000);
			if (diff > 10) {
				printf("time diff is %ld ms\n", diff);
			}
		}
	}


	/* Cleanup - free all resources */
	for (int i = 0; i < NUM_SV; i++) {
		SVPublisher_destroy(sv_pubs[i].svPublisher);
	}
	return 0;
} /* main() */
