#include <stdint.h>

#define MAXLEN 256

struct sSvConf {
    char section[MAXLEN];
    char iface[MAXLEN];
    uint8_t mac[6];
    uint8_t vlanId;
    uint8_t vlanPrio;
    uint16_t appId;
    char svId[MAXLEN];
    char datSet[MAXLEN];
    uint32_t confRev;
    uint32_t smpCntWrap;//?
    char refrTm[MAXLEN];//?
    double ia_ang;
    double ia_mag;
    int32_t ia_q;
    double ib_mag;
    double ib_ang;
    int32_t ib_q;
    double ic_mag;
    double ic_ang;
    int32_t ic_q;
    double in_mag;
    double in_ang;
    int32_t in_q;
    double va_mag;
    double va_ang;
    int32_t va_q;
    double vb_mag;
    double vb_ang;
    int32_t vb_q;
    double vc_mag;
    double vc_ang;
    int32_t vc_q;
    double vn_mag;
    double vn_ang;
    int32_t vn_q;
};
typedef struct sSvConf SvConf;


extern SvConf *sv_conf;
extern uint32_t sv_num;


uint16_t sv_strtoq(const char *value);