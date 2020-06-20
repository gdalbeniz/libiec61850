
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ini.h"
#include "sv_config.h"
#include "iec61850_common.h"



#define MATCH(a,b) (!strcmp(a?a:"", b?b:""))
#define SV_ALLOC_SZ 3 //50

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

	// fill key-value
	if (MATCH(key, "iface")) {
		if (conf == &def_conf) {
			snprintf(conf->iface, MAXLEN, value);
		} else {
			debug("error (line %d): not allowed to configure iface in regular stream, only in default\n", lineno);
			return 0; //error
		}
	} else if (MATCH(key, "mac")) {
		int ret = sv_parsemac(conf->mac, value, section);
		if (ret) {
			debug("error (line %d): not valid mac\n", lineno);
			return 0; //error
		}
		debug("parsed mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
			conf->mac[0], conf->mac[1], conf->mac[2], conf->mac[3], conf->mac[4], conf->mac[5]);
	} else if (MATCH(key, "vlanId")) {
		conf->vlanId = (uint8_t) strtol(value, NULL, 0);
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
	}/* TODO else if (MATCH(key, "refrTm")) {
	}*/ else if (MATCH(key, "ia_mag")) {
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
		debug("error (line %d): attribute '%s' unsupported\n", lineno, key);
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
			debug("error: unsupported quality '%s'\n", token ? token : "nil");
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
			debug("error: parsing mac\n");
			return -1;
		}
		mac[i] = (uint8_t) octet;
		i++;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	if (argc <= 1) {
		printf("Usage: ini_dump filename.ini\n");
		return 1;
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
	return 0;
}