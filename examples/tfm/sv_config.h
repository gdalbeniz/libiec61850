#include <stdint.h>

#define MAXLEN 128
#define SAMPLEWRAP 4000
#define PACKETSIZE 256


struct sSvConf {
    char section[MAXLEN];
    char iface[MAXLEN];
    uint8_t mac[6];
    uint8_t vlanPrio;
    uint16_t vlanId;
    uint16_t appId;
    char svId[MAXLEN];
    char datSet[MAXLEN];
    uint32_t confRev;
    uint32_t smpCntWrap;//?
    double ia_ang;
    double ia_mag;
    uint16_t ia_q;
    double ib_mag;
    double ib_ang;
    uint16_t ib_q;
    double ic_mag;
    double ic_ang;
    uint16_t ic_q;
    double in_mag;
    double in_ang;
    uint16_t in_q;
    double va_mag;
    double va_ang;
    uint16_t va_q;
    double vb_mag;
    double vb_ang;
    uint16_t vb_q;
    double vc_mag;
    double vc_ang;
    uint16_t vc_q;
    double vn_mag;
    double vn_ang;
    uint16_t vn_q;
};
typedef struct sSvConf SvConf;


extern SvConf *sv_conf;
extern uint32_t sv_num;



uint16_t sv_parseq(const char *value);
int32_t sv_parsemac(uint8_t *mac, const char *value, const char *section);
void printSvConf(SvConf *conf);