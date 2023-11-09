/*
 * hdf_public_ap6275s.h
 *
 * ap6275s driver header
 *
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _HDF_PUBLIC_AP6275S_H_
#define _HDF_PUBLIC_AP6275S_H_
#include <net/cfg80211.h>
#include "net_device.h"
#include "hdf_wl_interface.h"

#include "wifi_module.h"
#include "wifi_mac80211_ops.h"
#include "hdf_wlan_utils.h"
#include "net_bdh_adpater.h"

int get_scan_ifidx(const char *ifname);
extern struct cfg80211_ops wl_cfg80211_ops;
extern struct net_device_ops dhd_ops_pri;
extern struct hdf_inf_map g_hdf_infmap[HDF_INF_MAX];
extern struct net_device *GetLinuxInfByNetDevice(const struct NetDevice *netDevice);
extern struct wireless_dev *wrap_get_widev(void);
extern struct ieee80211_regdomain *wrp_get_regdomain(void);
extern int32_t wl_get_all_sta(struct net_device *ndev, uint32_t *num);
extern s32 wl_get_all_sta_info(struct net_device *ndev, char* mac, uint32_t num);
extern int g_hdf_ifidx;
extern int g_mgmt_tx_event_ifidx;
extern u32 p2p_remain_freq;
extern struct NetDevice* GetHdfNetDeviceByLinuxInf(struct net_device *dev);
extern int g_scan_event_ifidx;
extern int g_conn_event_ifidx;
extern int bdh6_reset_driver_flag;
extern int start_p2p_completed;
extern struct mutex bdh6_reset_driver_lock;
void dhd_get_mac_address(struct net_device *dev, unsigned char **addr);

int32_t wal_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy, struct net_device *netDev);
int32_t wal_cfg80211_remain_on_channel(struct wiphy *wiphy, struct net_device *netDev, int32_t freq,
    unsigned int duration);
void wl_cfg80211_add_virtual_iface_wrap(struct wiphy *wiphy, char *name, enum nl80211_iftype type,
    struct vif_params *params);
extern int memcpy_s(void *dest, size_t dest_max, const void *src, size_t count);
extern int32_t HdfWifiEventDelSta(struct NetDevice *netDev, const uint8_t *macAddr, uint8_t addrLen);
int hdf_cfgp2p_register_ndev(struct net_device *p2p_netdev, struct net_device *primary_netdev, struct wiphy *wiphy);
struct NetDeviceInterFace *wal_get_net_p2p_ops(void);
int hdf_start_p2p_device(void);
s32 wldev_ioctl_get(struct net_device *dev, u32 cmd, unsigned char *arg, u32 len);
struct wiphy *get_linux_wiphy_hdfdev(NetDevice *netDev);
extern int dhd_netdev_changemtu_wrapper(struct net_device *netdev, int mtu);
extern struct NetDeviceInterFace *wal_get_net_dev_ops(void);

int BDH6InitNetdev(struct NetDevice *netDevice, int private_data_size, int type, int ifidx);
struct NetDevice *get_hdf_netdev(int ifidx);
struct net_device *get_krn_netdev(int ifidx);
extern void rtnl_lock(void);
extern void rtnl_unlock(void);

struct NetDevice *get_real_netdev(NetDevice *netDev);
extern struct wiphy *get_linux_wiphy_ndev(struct net_device *ndev);
int get_dhd_priv_data_size(void);
extern int32_t wl_cfg80211_set_country_code(struct net_device *net, char *country_code,
    bool notify, bool user_enforced, int revinfo);
extern int snprintf_s(char *dest, size_t dest_max, size_t count, const char *format, ...);

extern int32_t WalChangeBeacon(NetDevice *hnetDev, struct WlanBeaconConf *param);
extern int32_t Bdh6Ghcap(struct NetDevice *hnetDev, struct WlanHwCapability **capability);
extern int32_t HdfStartScan(NetDevice *hhnetDev, struct WlanScanRequest *scanParam);
extern int32_t WifiScanSetUserIe(const struct WlanScanRequest *params, struct cfg80211_scan_request *request);
extern int32_t WifiScanSetChannel(const struct wiphy *wiphy, const struct WlanScanRequest *params,
    struct cfg80211_scan_request *request);
extern int32_t BDH6Init(struct HdfChipDriver *chipDriver, struct NetDevice *netDevice);

/********************************* hdf_bdh_mac80211 ***********************************************/
typedef enum {
    WLAN_BAND_2G,
    WLAN_BAND_5G,
    WLAN_BAND_BUTT
} wlan_channel_band_enum;
#define WIFI_24G_CHANNEL_NUMS   (14)
#define WAL_MIN_CHANNEL_2G      (1)
#define WAL_MAX_CHANNEL_2G      (14)
#define WAL_MIN_FREQ_2G         (2412 + 5*(WAL_MIN_CHANNEL_2G - 1))
#define WAL_MAX_FREQ_2G         (2484)
#define WAL_FREQ_2G_INTERVAL    (5)

#define WLAN_WPS_IE_MAX_SIZE    (352) // (WLAN_MEM_EVENT_SIZE2 - 32)   /* 32表示事件自身占用的空间 */
#define MAC_80211_FRAME_LEN                 24      /* 非四地址情况下，MAC帧头的长度 */
extern struct ieee80211_regdomain *bdh6_get_regdomain(void);
extern void BDH6WalReleaseHwCapability(struct WlanHwCapability *self);

/************************************* ap.c *************************************************/
extern void bdh6_nl80211_calculate_ap_params(struct cfg80211_ap_settings *params);
extern int32_t WalStartAp(NetDevice *hnetDev);


/************************************ sta.c ***************************************/
extern int32_t WifiScanSetRequest(struct NetDevice *netdev, const struct WlanScanRequest *params,
    struct cfg80211_scan_request *request);
extern struct ieee80211_channel *WalGetChannel(struct wiphy *wiphy, int32_t freq);
extern struct ieee80211_channel *GetChannelByFreq(const struct wiphy *wiphy, uint16_t center_freq);

/************************************* hdf_wl_interface.h **************************************/
extern int g_event_ifidx;

extern int32_t Bdh6SAction(struct NetDevice *hhnetDev, WifiActionData *actionData);
extern int32_t Bdh6Fband(NetDevice *hnetDev, int32_t band, int32_t *freqs, uint32_t *num);
extern int32_t HdfConnect(NetDevice *hnetDev, WlanConnectParams *param);
#endif
