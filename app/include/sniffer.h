/*
 * sniffer.h
 */

#ifndef SNIFFER_DEMO_INCLUDE_SNIFFER_H_
#define SNIFFER_DEMO_INCLUDE_SNIFFER_H_

#include "ets_sys.h"
#include "os_type.h"

#define SNIFFER_TEST			1

/* 使能DEAUTH */
#define DEAUTH_ENABLE 			0

/* 每隔x秒跳channel */
#define HOP_JUMP_ENABLE			1
#define CHANNEL_HOP_INTERVAL 300

extern void ICACHE_FLASH_ATTR sniffer_init(void);
extern void ICACHE_FLASH_ATTR sniffer_init_in_system_init_done(void);

struct RxControl {
    signed rssi:8;				// signal intensity of packet
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2;		// 0:is 11n packet; 1:is not 11n packet;
    unsigned legacy_length:12;	// if not 11n packet, shows length of packet.
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7;			// if is 11n packet, shows the modulation
    						// and code used (range from 0 to 76)
    unsigned CWB:1;			// if is 11n packet, shows if is HT40 packet or not
    unsigned HT_length:16;	// if is 11n packet, shows length of packet.
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1;	// if is 11n packet, shows if is LDPC packet or not.
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;		// which channel this packet in.
    unsigned:12;
};

struct LenSeq {
    uint16_t length;
    uint16_t seq;
    uint8_t  address3[6];
};

struct sniffer_buf {
    struct RxControl rx_ctrl;
    uint8_t buf[36];
    uint16_t cnt;
    struct LenSeq lenseq[1];
};

struct sniffer_buf2{
    struct RxControl rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;
};

struct packet_info {
    /* general */
    unsigned int pkt_types;            /* bitmask of packet types */

    /* wlan phy (from radiotap) */
    int phy_signal;                    /* signal strength (usually dBm) */
    int phy_noise;                     /* noise level (usually dBm) */
    unsigned int phy_snr;              /* signal to noise ratio */
    unsigned int phy_rate;             /* physical rate, unit=100kbps */

	//802.11n
	unsigned char phy_rate_idx;		   /* MCS index */
	unsigned char phy_rate_flags;	   /* MCS flags */

    unsigned int phy_freq;             /* frequency from driver */
    unsigned char phy_chan;            /* channel from driver */
    unsigned int phy_flags;            /* A, B, G, shortpre */

    /* wlan mac */
    unsigned int wlan_len;             /* packet length */
    unsigned int wlan_type;            /* frame control field */
    unsigned int pkt_fc;			   // 原始的FrameControl
    unsigned char wlan_src[MAC_LEN];
    unsigned char wlan_dst[MAC_LEN];
    unsigned char wlan_bssid[MAC_LEN];
    char wlan_essid[MAX_ESSID_LEN];
    u_int64_t wlan_tsf;                /* timestamp from beacon */
    unsigned int wlan_bintval;         /* beacon interval */
    unsigned int wlan_mode;            /* AP, STA or IBSS */
    unsigned char wlan_channel;        /* channel from beacon, probe */
    unsigned char ap_ecypt;			   // AP的加密方式，从beacon帧中获取  [n|n|n|n|wps|wpa2|wpa|wep]
    //unsigned char wlan_qos_class;      /* for QDATA frames */
    unsigned int wlan_nav;             /* frame NAV duration */
    unsigned int wlan_seqno;           /* sequence number */
    unsigned int qos_ctrl;             /* qos_control_field */

    /* flags */
    unsigned int wlan_wep:1,           /* WEP on/off */
     wlan_retry:1;

    /* IP */
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned int port_src;
    unsigned int port_dst;
    unsigned int olsr_type;
    unsigned int olsr_neigh;
    unsigned int olsr_tc;

    /* calculated from other values */
    unsigned int pkt_duration;         /* packet "airtime" */
    int pkt_chan_idx;                  /* received while on channel */
    int wlan_retries;                  /* retry count for this frame */
};


#define printmac(buf, i) os_printf("|%02X:%02X:%02X:%02X:%02X:%02X", buf[i+0], buf[i+1], buf[i+2], \
                                                   buf[i+3], buf[i+4], buf[i+5])

#define user_procTaskPrio        0
#define user_procTaskQueueLen    1
os_event_t    user_procTaskQueue[user_procTaskQueueLen];

#endif /* SNIFFER_DEMO_INCLUDE_SNIFFER_H_ */
