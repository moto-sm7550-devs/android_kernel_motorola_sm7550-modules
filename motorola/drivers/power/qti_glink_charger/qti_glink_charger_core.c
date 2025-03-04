/*
 * Copyright (C) 2020-2021 Motorola Mobility LLC
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/version.h>
#include <linux/alarmtimer.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/soc/qcom/pmic_glink.h>
#include <linux/power/bm_adsp_ulog.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/thermal.h>

#include "mmi_charger.h"
#include "qti_glink_charger.h"
#include "trusted_shash_lib.h"
/* PPM specific definitions */
#define MSG_OWNER_OEM			32782
#define MSG_TYPE_REQ_RESP		1
#define MSG_TYPE_NOTIFY			2
#define OEM_PROPERTY_DATA_SIZE		16

#define OEM_READ_BUF_REQ		0x10000
#define OEM_WRITE_BUF_REQ		0x10001
#define OEM_NOTIFY_IND			0x10002

#define OEM_WAIT_TIME_MS		5000

#define BATT_DEFAULT_ID 107000
#define BATT_SN_UNKNOWN "unknown-sn"

#define OEM_BM_ULOG_SIZE		4096

#define VBUS_MIN_MV			4000

#define FOD_GAIN_MAX_LEN 16
#define FOD_CURR_MAX_LEN 7

#define RADIO_MAX_LEN 33

static bool debug_enabled;
module_param(debug_enabled, bool, 0600);
MODULE_PARM_DESC(debug_enabled, "Enable debug for qti glink charger driver");

struct battery_info {
	int batt_uv;
	int batt_ua;
	int batt_soc; /* 0 ~ 10000 indicating 0% to 100% */
	int batt_temp; /* hundredth degree */
	int batt_status;
	int batt_full_uah;
	int batt_design_uah;
	int batt_chg_counter;
	int batt_fv_uv;
	int batt_fcc_ua;
};

struct charger_info {
	int chrg_uv;
	int chrg_ua;
	int chrg_type;
	int chrg_pmax_mw;
	int chrg_present;
	bool chrg_otg_enabled;
};

struct charger_profile_info {
	int fg_iterm;
        int chrg_iterm;
        int max_fv_uv;
        int max_fcc_ua;
        int vfloat_comp_uv;
        int demo_fv_uv;
        int data_bk_size; /* number of byte for each data block */
	int data_size; /* number of byte for while data */
	int profile_id; /* profile id for charging profile selection in ADSP */
};

struct lpd_info {
	int lpd_present;
	int lpd_rsbu1;
	int lpd_rsbu2;
	int lpd_cid;
};

struct oem_notify_ind_msg {
	struct pmic_glink_hdr	hdr;
	u32			notification;
	u32			receiver;
	u32			data[MAX_OEM_NOTIFY_DATA_LEN];
};

struct oem_read_buf_req_msg {
	struct pmic_glink_hdr	hdr;
	u32			oem_property_id;
	u32			data_size;
};

struct oem_read_buf_resp_msg {
	struct pmic_glink_hdr	hdr;
	u32			oem_property_id;
	u32			buf[OEM_PROPERTY_DATA_SIZE];
	u32			data_size;
};

struct oem_write_buf_req_msg {
	struct pmic_glink_hdr	hdr;
	u32			oem_property_id;
	u32			buf[OEM_PROPERTY_DATA_SIZE];
	u32			data_size;
};

struct oem_write_buf_resp_msg {
	struct pmic_glink_hdr	hdr;
	u32			ret_code;
};


struct fod_curr {
	u32	fod_array_curr[FOD_CURR_MAX_LEN];
};

struct fod_gain {
	u32	fod_array_gain[FOD_GAIN_MAX_LEN];
};

#if defined(WIRELESS_CPS4035B) || defined(WIRELESS_CPS4019)
struct wls_dump
{
    u32  chip_id;
    u32  mtp_fw_ver;
    u32  irq_status;
    u16  sys_mode;
    u16  op_mode;
    u16  rx_fop;
    u16  rx_vout_mv;
    s16  rx_vrect_mv;
    u16  rx_irect_ma;
    u16  rx_ept;
    u16  rx_ce;
    u32  rx_rp;
    s16  rx_dietemp;
    u16  rx_neg_power;
    s16  tx_iin_ma;
    u16  tx_vin_mv;
    u16  tx_vrect_mv;
    u16  tx_det_rx_power;
    u16  tx_power;
    u16  tx_ept;
    s16  power_loss;
    u16  usb_otg;
    u16  wls_boost;
    u16  wls_icl_ma;
    u16  wls_icl_therm_ma;
};
#else
struct wls_dump
{
    u32  chip_id;
    u32  mtp_fw_ver;
    u32  irq_status;
    u16  sys_mode;
    u16  op_mode;
    u16  rx_fop;
    u16  rx_vout_mv;
    u16  rx_vrect_mv;
    u16  rx_irect_ma;
    u16  rx_neg_power;
    u16  tx_iin_ma;
    u16  tx_vin_mv;
    u16  tx_vrect_mv;
    u16  tx_fod_I;
    u16  tx_fod_II;
    u16  tx_fod_rp;
    u16  tx_det_rx_power;
    u16  tx_power;
    s16  power_loss;
    u16  folio_mode;
    u16  pen_status;
    u16  pen_soc;
    u16  pen_error;
    u16  usb_otg;
    u16  wls_boost;
    u16  wls_icl_ma;
    u16  wls_icl_therm_ma;
};
#endif

struct msb_dev_info
{
    u32  usb_iin;
    u32  usb_vout;
    u32  usb_suspend;
    u32  batt_fcc;
    u32  batt_fv;
    u32  chg_en;
    u32  chg_st;
    u32  chg_fault;
};

struct qti_charger {
	char				*name;
	struct device			*dev;
	struct pmic_glink_client	*client;
	struct completion		read_ack;
	struct completion		write_ack;
	struct mutex			read_lock;
	struct mutex			write_lock;
	struct oem_read_buf_resp_msg	rx_buf;
	atomic_t			rx_valid;
	struct work_struct		setup_work;
	struct work_struct		notify_work;
	struct oem_notify_ind_msg	notify_msg;
	atomic_t			state;
	u32				chrg_taper_cnt;
	struct mmi_battery_info		batt_info;
	struct mmi_charger_info		chg_info;
	struct mmi_charger_cfg		chg_cfg;
	struct mmi_charger_constraint	constraint;
	struct mmi_charger_driver	*driver;
	struct power_supply		*wls_psy;
	struct power_supply		*partner_charger;
	struct thermal_cooling_device	*cdev;
	u32				partner_charger_icl;
	u32				partner_charger_soc;
	u32				*profile_data;
	struct charger_profile_info	profile_info;
	struct lpd_info			lpd_info;
	void				*ipc_log;
	struct fod_curr			rx_fod_curr;
	struct fod_gain			rx_fod_gain;
	u32				tx_mode;
	u32				folio_mode;
	u32				wlc_light_ctl;
	u32				wlc_fan_speed;
	u32				wlc_status;
	u32				wlc_tx_type;
	u32				wlc_tx_power;
	u32				wlc_tx_capability;
	u32				wlc_tx_id;
	u32				wlc_tx_sn;
	bool				*debug_enabled;
	u32				wls_curr_max;
	int				rx_connected;
	u32				rx_dev_mfg;
	u32				rx_dev_type;
	u32				rx_dev_id;
	u32				weak_charge_disable;
	u32				switched_nums;
	bool				mosfet_supported;
	int				mos_en_gpio;
	bool				mosfet_is_enable;

	u32 *thermal_primary_levels;
	u32 thermal_primary_fcc_ua;
	int curr_thermal_primary_level;
	int num_thermal_primary_levels;
	struct thermal_cooling_device *primary_tcd;

	u32 *thermal_secondary_levels;
	u32 thermal_secondary_fcc_ua;
	int curr_thermal_secondary_level;
	int num_thermal_secondary_levels;
	struct thermal_cooling_device *secondary_tcd;

	u32				random_num[SHA256_NUM];
	u8 				sha1_digest[SHA1_DIGEST_SIZE];
	u8 				hmac_digest[SHA256_DIGEST_SIZE];

	struct notifier_block		wls_nb;
	struct dentry		*debug_root;
	struct power_supply		*batt_psy;
};

static struct qti_charger *this_chip = NULL;
static BLOCKING_NOTIFIER_HEAD(qti_chg_notifier_list);

static int find_profile_id(struct qti_charger *chg)
{
	int i;
	int rc;
	int count;
	int profile_id = -EINVAL;
	struct profile_sn_map {
		const char *id;
		const char *sn;
	} *map_table;

	count = of_property_count_strings(chg->dev->of_node, "profile-ids-map");
	if (count <= 0 || (count % 2)) {
		mmi_err(chg, "Invalid profile-ids-map in DT, rc=%d\n", count);
		return -EINVAL;
	}

	map_table = devm_kmalloc_array(chg->dev, count / 2,
					sizeof(struct profile_sn_map),
					GFP_KERNEL);
	if (!map_table)
		return -ENOMEM;

	rc = of_property_read_string_array(chg->dev->of_node, "profile-ids-map",
					(const char **)map_table,
					count);
	if (rc < 0) {
		mmi_err(chg, "Failed to get profile-ids-map, rc=%d\n", rc);
		profile_id = rc;
		goto free_map;
	}

	for (i = 0; i < count / 2 && map_table[i].sn; i++) {
		mmi_info(chg, "profile_ids_map[%d]: id=%s, sn=%s\n", i,
					map_table[i].id, map_table[i].sn);
		if (!strcmp(map_table[i].sn, chg->batt_info.batt_sn))
			profile_id = i;
	}

	if (profile_id >= 0 && profile_id < count / 2) {
		i = profile_id;
		profile_id = 0;
		rc = kstrtou32(map_table[i].id, 0, &profile_id);
		if (rc) {
			mmi_err(chg, "Invalid id: %s, sn: %s\n",
						map_table[i].id,
						map_table[i].sn);
			profile_id = rc;
		} else {
			mmi_info(chg, "profile id: %s(%d), sn: %s\n",
						map_table[i].id,
						profile_id,
						map_table[i].sn);
		}
	} else {
		mmi_warn(chg, "No matched profile id in profile-ids-map\n");
	}

free_map:
	devm_kfree(chg->dev, map_table);

	return profile_id;
}

static int handle_oem_read_ack(struct qti_charger *chg, void *data, size_t len)
{
	if (len != sizeof(chg->rx_buf)) {
		mmi_err(chg, "Incorrect received length %zu expected %lu\n", len,
			sizeof(chg->rx_buf));
		atomic_set(&chg->rx_valid, 0);
		return -EINVAL;
	}

	memcpy(&chg->rx_buf, data, sizeof(chg->rx_buf));
	atomic_set(&chg->rx_valid, 1);
	complete(&chg->read_ack);
	mmi_dbg(chg, "read ack for property: %u\n", chg->rx_buf.oem_property_id);

	return 0;
}

static int handle_oem_write_ack(struct qti_charger *chg, void *data, size_t len)
{
	struct oem_write_buf_resp_msg *msg_ptr;

	if (len != sizeof(*msg_ptr)) {
		mmi_err(chg, "Incorrect received length %zu expected %lu\n", len,
			sizeof(*msg_ptr));
		return -EINVAL;
	}

	msg_ptr = data;
	if (msg_ptr->ret_code) {
		mmi_err(chg, "write ack, ret_code: %u\n", msg_ptr->ret_code);
		return -EINVAL;
	}

	mmi_dbg(chg, "write ack\n");
	complete(&chg->write_ack);

	return 0;
}

static int handle_oem_notification(struct qti_charger *chg, void *data, size_t len)
{
	struct oem_notify_ind_msg *notify_msg = data;
	if (len != sizeof(*notify_msg)) {
		mmi_err(chg, "Incorrect received length %zu expected %lu\n", len,
			sizeof(*notify_msg));
		return -EINVAL;
	}

	mmi_info(chg, "notification: %#x on receiver: %#x\n",
				notify_msg->notification,
				notify_msg->receiver);

	pm_stay_awake(chg->dev);
	memcpy(&chg->notify_msg, notify_msg, sizeof(*notify_msg));
	schedule_work(&chg->notify_work);

	return 0;
}

static int oem_callback(void *priv, void *data, size_t len)
{
	struct pmic_glink_hdr *hdr = data;
	struct qti_charger *chg = priv;

	mmi_dbg(chg, "owner: %u type: %u opcode: 0x%x len:%zu\n", hdr->owner,
		hdr->type, hdr->opcode, len);

	if (hdr->opcode == OEM_READ_BUF_REQ)
		handle_oem_read_ack(chg, data, len);
	else if (hdr->opcode == OEM_WRITE_BUF_REQ)
		handle_oem_write_ack(chg, data, len);
	else if (hdr->opcode == OEM_NOTIFY_IND)
		handle_oem_notification(chg, data, len);
	else
		mmi_err(chg, "Unknown message opcode: %d\n", hdr->opcode);

	return 0;
}

static void oem_state_cb(void *priv, enum pmic_glink_state state)
{
	struct qti_charger *chg = priv;

	mmi_dbg(chg, "state: %d\n", state);

	atomic_set(&chg->state, state);

	switch (state) {
	case PMIC_GLINK_STATE_DOWN:
	case PMIC_GLINK_STATE_UP:
		schedule_work(&chg->setup_work);
		break;
	default:
		break;
	}
}

static int qti_charger_write(struct qti_charger *chg, u32 property,
			       const void *val, size_t val_len)
{
	struct oem_write_buf_req_msg oem_buf = { { 0 } };
	int rc;

	if (val_len > (OEM_PROPERTY_DATA_SIZE * sizeof(u32))) {
		mmi_err(chg, "Incorrect data length %zu for property: %u\n",
						val_len, property);
		return -EINVAL;
	}

	if (atomic_read(&chg->state) == PMIC_GLINK_STATE_DOWN) {
		mmi_err(chg, "ADSP glink state is down\n");
		return -ENOTCONN;
	}

	memset(&oem_buf, 0, sizeof(oem_buf));
	oem_buf.hdr.owner = MSG_OWNER_OEM;
	oem_buf.hdr.type = MSG_TYPE_REQ_RESP;
	oem_buf.hdr.opcode = OEM_WRITE_BUF_REQ;
	oem_buf.oem_property_id = property;
	oem_buf.data_size = val_len;
	memcpy(oem_buf.buf, val, val_len);

	mutex_lock(&chg->write_lock);
	reinit_completion(&chg->write_ack);

	mmi_dbg(chg, "Start data write for property: %u, len=%zu\n",
		property, val_len);

	rc = pmic_glink_write(chg->client, &oem_buf,
					sizeof(oem_buf));
	if (rc < 0) {
		mmi_err(chg, "Error in sending message rc=%d on property: %u\n",
						rc, property);
		goto out;
	}

	rc = wait_for_completion_timeout(&chg->write_ack,
				msecs_to_jiffies(OEM_WAIT_TIME_MS));
	if (!rc) {
		mmi_err(chg, "timed out on property: %u\n", property);
		rc = -ETIMEDOUT;
		goto out;
	} else {
		rc = 0;
		bm_ulog_print_log(OEM_BM_ULOG_SIZE);
	}
out:
	mmi_dbg(chg, "Complete data write for property: %u\n", property);
	mutex_unlock(&chg->write_lock);
	return rc;
}

static int qti_charger_read(struct qti_charger *chg, u32 property,
			       void *val, size_t val_len)
{
	struct oem_read_buf_req_msg oem_buf = { { 0 } };
	int rc;

	if (val_len > (OEM_PROPERTY_DATA_SIZE * sizeof(u32))) {
		mmi_err(chg, "Incorrect data length %zu for property: %u\n",
						val_len, property);
		return -EINVAL;
	}

	if (atomic_read(&chg->state) == PMIC_GLINK_STATE_DOWN) {
		mmi_err(chg, "ADSP glink state is down\n");
		return -ENOTCONN;
	}

	oem_buf.hdr.owner = MSG_OWNER_OEM;
	oem_buf.hdr.type = MSG_TYPE_REQ_RESP;
	oem_buf.hdr.opcode = OEM_READ_BUF_REQ;
	oem_buf.oem_property_id = property;
	oem_buf.data_size = val_len;

	mutex_lock(&chg->read_lock);
	reinit_completion(&chg->read_ack);

	mmi_dbg(chg, "Start data read for property: %u, len=%zu\n",
		property, val_len);

	rc = pmic_glink_write(chg->client, &oem_buf,
					sizeof(oem_buf));
	if (rc < 0) {
		mmi_err(chg, "Error in sending message rc=%d on property: %u\n",
						rc, property);
		goto out;
	}

	rc = wait_for_completion_timeout(&chg->read_ack,
				msecs_to_jiffies(OEM_WAIT_TIME_MS));
	if (!rc) {
		mmi_err(chg, "timed out on property: %u\n", property);
		rc = -ETIMEDOUT;
		goto out;
	} else {
		rc = 0;
	}

	if (!atomic_read(&chg->rx_valid)) {
		rc = -ENODATA;
		goto out;
	}

	if (chg->rx_buf.data_size != val_len) {
		mmi_err(chg, "Invalid data size %u, on property: %u\n",
				chg->rx_buf.data_size, property);
		rc = -ENODATA;
		goto out;
	}

	memcpy(val, chg->rx_buf.buf, val_len);
	atomic_set(&chg->rx_valid, 0);
out:
	mmi_dbg(chg, "Complete data read for property: %u\n", property);
	mutex_unlock(&chg->read_lock);

	return rc;
}

int qti_charger_set_property(u32 property, const void *val, size_t val_len)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return qti_charger_write(chg, property, val, val_len);
}
EXPORT_SYMBOL(qti_charger_set_property);

int qti_charger_get_property(u32 property, void *val, size_t val_len)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return qti_charger_read(chg, property, val, val_len);
}
EXPORT_SYMBOL(qti_charger_get_property);

int qti_charger_register_notifier(struct notifier_block *nb)
{
        return blocking_notifier_chain_register(&qti_chg_notifier_list, nb);
}
EXPORT_SYMBOL(qti_charger_register_notifier);

int qti_charger_unregister_notifier(struct notifier_block *nb)
{
        return blocking_notifier_chain_unregister(&qti_chg_notifier_list, nb);
}
EXPORT_SYMBOL(qti_charger_unregister_notifier);

static int qti_charger_get_batt_info(void *data, struct mmi_battery_info *batt_info)
{
	int rc;
	struct qti_charger *chg = data;
	int batt_status = chg->batt_info.batt_status;
	struct battery_info info;

	rc = qti_charger_read(chg, OEM_PROP_BATT_INFO,
				&info,
				sizeof(struct battery_info));
	if (rc)
		return rc;

	if (chg->chg_cfg.full_charged)
		chg->batt_info.batt_status = POWER_SUPPLY_STATUS_FULL;

	chg->batt_info.batt_ma = info.batt_ua / 1000;
	chg->batt_info.batt_mv = info.batt_uv / 1000;
	chg->batt_info.batt_soc = info.batt_soc / 100;
	chg->batt_info.batt_temp = info.batt_temp / 100;
	chg->batt_info.batt_status = info.batt_status;
	chg->batt_info.batt_full_uah = info.batt_full_uah;
	chg->batt_info.batt_design_uah = info.batt_design_uah;
	chg->batt_info.batt_chg_counter = info.batt_chg_counter;
	chg->batt_info.batt_fv_mv = info.batt_fv_uv / 1000;
	chg->batt_info.batt_fcc_ma = info.batt_fcc_ua / 1000;
	memcpy(batt_info, &chg->batt_info, sizeof(struct mmi_battery_info));

	if (batt_status != chg->batt_info.batt_status) {
		bm_ulog_print_log(OEM_BM_ULOG_SIZE);
	}

	return rc;
}
#if defined(WIRELESS_CPS4035B) || defined(WIRELESS_CPS4019)
void qti_wireless_charge_dump_info(struct qti_charger *chg, struct wls_dump wls_info)
{
	mmi_info(chg, "Wireless dump info -1: CHIP_ID: 0x%04x, MTP_FW_VER: 0x%04x, IRQ STATUS: 0x%04x, "
		"SYS_MODE:  RX/TX %d, OP_MODE:  BPP/EPP 0x%x, RX_FOP: %dkHz, RX_VOUT: %dmV, "
		"RX_VRECT: %dmV, RX_IRECT: %dmV, RX_NEG_POWER: %dw ",
		wls_info.chip_id,
		wls_info.mtp_fw_ver,
		wls_info.irq_status,
		wls_info.sys_mode,
		wls_info.op_mode,
		wls_info.rx_fop,
		wls_info.rx_vout_mv,
		wls_info.rx_vrect_mv,
		wls_info.rx_irect_ma,
		wls_info.rx_neg_power);

	mmi_info(chg, "Wireless dump info -2: TX_IIN: %dmA, TX_VIN: %dmV, TX_VRECT: %dmV, "
		"TX_DET_RX_POWER: %dmW, TX_POWER: %dmW, POWER_LOSS: %dmW, TX_FOD: %d, "
		"RX_CONNECTED: %d, RX_DEV_INFO: 0x%x:0x%x:0x%x, TX_EPT_RSN: 0x%04x, ",
		wls_info.tx_iin_ma,
		wls_info.tx_vin_mv,
		wls_info.tx_vrect_mv,
		wls_info.tx_det_rx_power,
		wls_info.tx_power,
		wls_info.power_loss,
		(wls_info.irq_status & (0x01<<12)) ? 1 : 0,
		chg->rx_connected,
		chg->rx_dev_mfg,
		chg->rx_dev_type,
		chg->rx_dev_id,
		wls_info.tx_ept);

	mmi_info(chg, "Wireless dump info -3: rx_ept: %d, rx_ce: %d, "
		"rx_rp: %d, rx_dietemp: %d, USB_OTG: %d, WLS_BOOST: %d, WLS_ICL_MA: %dmA, WLS_ICL_THERM_MA: %dmA",
		wls_info.rx_ept,
		wls_info.rx_ce,
		wls_info.rx_rp,
		wls_info.rx_dietemp,
		wls_info.usb_otg,
		wls_info.wls_boost,
		wls_info.wls_icl_ma,
		wls_info.wls_icl_therm_ma);


	mmi_info(chg, "Wireless dump info -4: WLC Stand: tx_type %d, tx_power: %d, "
		"fan: %d, light: %d, status: %d",
		chg->wlc_tx_type,
		chg->wlc_tx_power,
		chg->wlc_fan_speed,
		chg->wlc_light_ctl,
		chg->wlc_status);
	
}
#else
void qti_wireless_charge_dump_info(struct qti_charger *chg, struct wls_dump wls_info)
{
	mmi_info(chg, "Wireless dump info -1: CHIP_ID: 0x%04x, MTP_FW_VER: 0x%04x, IRQ STATUS: 0x%04x, "
		"SYS_MODE:  RX/TX %d, OP_MODE:  BPP/EPP 0x%x, RX_FOP: %dkHz, RX_VOUT: %dmV, "
		"RX_VRECT: %dmV, RX_IRECT: %dmV, RX_NEG_POWER: %dw ",
		wls_info.chip_id,
		wls_info.mtp_fw_ver,
		wls_info.irq_status,
		wls_info.sys_mode,
		wls_info.op_mode,
		wls_info.rx_fop,
		wls_info.rx_vout_mv,
		wls_info.rx_vrect_mv,
		wls_info.rx_irect_ma,
		wls_info.rx_neg_power);

	mmi_info(chg, "Wireless dump info -2: TX_IIN: %dmA, TX_VIN: %dmV, TX_VRECT: %dmV, "
		"TX_DET_RX_POWER: %dmW, TX_POWER: %dmW, POWER_LOSS: %dmW, TX_FOD: %d, ",
		wls_info.tx_iin_ma,
		wls_info.tx_vin_mv,
		wls_info.tx_vrect_mv,
		wls_info.tx_det_rx_power,
		wls_info.tx_power,
		wls_info.power_loss,
		(wls_info.irq_status & (0x01<<12)) ? 1 : 0);

	mmi_info(chg, "Wireless dump info -3: FOLIO_MODE: %d, PEN_STATUS: %d, "
		"PEN_SOC: %d, PEN_ERROR: %d, USB_OTG: %d, WLS_BOOST: %d, WLS_ICL_MA: %dmA, WLS_ICL_THERM_MA: %dmA",
		wls_info.folio_mode,
		wls_info.pen_status,
		wls_info.pen_soc,
		wls_info.pen_error,
		wls_info.usb_otg,
		wls_info.wls_boost,
		wls_info.wls_icl_ma,
		wls_info.wls_icl_therm_ma);
}
#endif

#if defined(MSB_DEV)
void qti_msb_dev_info(struct qti_charger *chg, struct msb_dev_info msb_dev)
{
	mmi_info(chg, "msb dev info : usb_iin: %dma, usb_vout: %dmv, usb_suspend: %d, "
		"batt_fcc: %dma, batt_fv: %dmv, chg_en: %d,  chg_fault: 0x%x, chg_st: 0x%x",
		msb_dev.usb_iin,
		msb_dev.usb_vout,
		msb_dev.usb_suspend,
		msb_dev.batt_fcc,
		msb_dev.batt_fv,
		msb_dev.chg_en,
		msb_dev.chg_fault,
		msb_dev.chg_st);
}
#endif

#if defined(SWITCHEDCAP_DUMP)
void qti_switched_dump_info(struct qti_charger *chg, struct switched_dev_info switched_info)
{
	mmi_info(chg, "switchedcap dump info [0x%02x-%d]: chg_en %d, work_mode 0x%x, int_stat 0x%x, "
			"ibat_ma %d, ibus_ma %d, vbus_mv %d, vout_mv %d, vac_mv %d, vbat_mv %d, "
			"vusb_mv %d, vwpc_mv %d, die_temp %d",
			switched_info.chip_id, switched_info.chg_role, switched_info.chg_en, switched_info.work_mode,
			switched_info.int_stat, switched_info.ibat_ma, switched_info.ibus_ma, switched_info.vbus_mv,
			switched_info.vout_mv, switched_info.vac_mv, switched_info.vbat_mv, switched_info.vusb_mv,
			switched_info.vwpc_mv, switched_info.die_temp);
}
#endif

#if defined(FUELGUAGE_DUMP)
void qti_fg_charge_dump_info(struct qti_charger *chg, struct fg_dump fg_info)
{

	mmi_info(chg, "FG dump info: WORK_MODE: 0x%x, SOC: %d, VOLTAGE_MV: %dmV, CURRENT_MA: %dmA, "
		"TEMP: %d, CYCLE_COUNT: %d, REMAINING_CAPACITY: %d, FULL_CAPACITY: %d",
		fg_info.work_mode, fg_info.current_ma, fg_info.voltage_mv, fg_info.soc,
		fg_info.temperature, fg_info.cycle_count,
		fg_info.remaining_capacity, fg_info.full_capacity);

}
#endif

static void qti_encrypt_authentication(struct qti_charger *chg)
{
	int i;
	TRUSTED_SHASH_RESULT trusted_result;
	struct encrypted_data send_data;
	u8 random_num[4] = {0};

	memset(&send_data, 0, sizeof(send_data));
	for (i = 0;i < 4;i++) {
		get_random_bytes(&(random_num[i]),sizeof(*random_num));
		trusted_result.random_num[i] = random_num[i] % 26 + 'a';
		send_data.random_num[i] = trusted_result.random_num[i];
		mmi_info(chg, "encrypt random_num1[%d]: %d, 0x%x \n", i, send_data.random_num[i], send_data.random_num[i]);
	}

	trusted_sha1(trusted_result.random_num, 4, trusted_result.sha1);
	trusted_hmac(trusted_result.random_num, 4, trusted_result.hmac_sha256);

	for (i = 0;i < 4;i++) {
	    send_data.hmac_data[i] = trusted_result.hmac_sha256[3 + (4 * i)] + (trusted_result.hmac_sha256[2 + (4 * i)] << 8) +
	            (trusted_result.hmac_sha256[1 + (4 * i)] << 16) + (trusted_result.hmac_sha256[0 + (4 * i)] << 24);
	    mmi_info(chg, "encrypt hmac_sha256[%d]: 0x%x \n", i, send_data.hmac_data[i]);

	}

	for (i = 0;i < 4;i++) {
	    send_data.sha1_data[i] = trusted_result.sha1[3 + (4 * i)] + (trusted_result.sha1[2 + (4 * i)] << 8) +
	            (trusted_result.sha1[1 + (4 * i)] << 16) + (trusted_result.sha1[0 + (4 * i)] << 24);
	    mmi_info(chg, "encrypt hmac_sha1[%d]: 0x%x \n", i, send_data.sha1_data[i]);
	}

	qti_charger_write(chg, OEM_PROP_ENCRYT_DATA,
				&send_data,
				sizeof(struct encrypted_data));

}

static int qti_charger_get_chg_info(void *data, struct mmi_charger_info *chg_info)
{
	int rc;
	struct qti_charger *chg = data;
	struct charger_info info;
	struct wls_dump wls_info;
#if defined(MSB_DEV)
	struct msb_dev_info msb_dev;
#endif
#if defined(SWITCHEDCAP_DUMP)
	struct switched_dev_info master_switched_info;
	int i = 0;
#endif
#if defined(FUELGUAGE_DUMP)
	struct fg_dump fg_info;
#endif
	int prev_cid = -1;
	int prev_lpd = 0;
	static bool lpd_ulog_triggered = false;
	static bool otg_ulog_triggered = false;

	rc = qti_charger_read(chg, OEM_PROP_CHG_INFO,
				&info,
				sizeof(struct charger_info));
	if (rc)
		return rc;

	prev_cid = chg->lpd_info.lpd_cid;
	prev_lpd = chg->lpd_info.lpd_present;
	chg->lpd_info.lpd_cid = -1;
	rc = qti_charger_read(chg, OEM_PROP_LPD_INFO,
				&chg->lpd_info,
				sizeof(struct lpd_info));
	if (rc) {
		rc = 0;
		memset(&chg->lpd_info, 0, sizeof(struct lpd_info));
		chg->lpd_info.lpd_cid = -1;
	}

	if ((prev_cid != -1 && chg->lpd_info.lpd_cid == -1) ||
            (!prev_lpd && chg->lpd_info.lpd_present)) {
		if (!lpd_ulog_triggered && !otg_ulog_triggered)
			bm_ulog_enable_log(true);
		lpd_ulog_triggered = true;
		mmi_err(chg, "LPD: present=%d, rsbu1=%d, rsbu2=%d, cid=%d\n",
			chg->lpd_info.lpd_present,
			chg->lpd_info.lpd_rsbu1,
			chg->lpd_info.lpd_rsbu2,
			chg->lpd_info.lpd_cid);
	} else if ((chg->lpd_info.lpd_cid != -1 && prev_cid == -1) ||
		   (!chg->lpd_info.lpd_present && prev_lpd)) {
		if (lpd_ulog_triggered && !otg_ulog_triggered)
			bm_ulog_enable_log(false);
		lpd_ulog_triggered = false;
		mmi_warn(chg, "LPD: present=%d, rsbu1=%d, rsbu2=%d, cid=%d\n",
			chg->lpd_info.lpd_present,
			chg->lpd_info.lpd_rsbu1,
			chg->lpd_info.lpd_rsbu2,
			chg->lpd_info.lpd_cid);
	} else {
		mmi_info(chg, "LPD: present=%d, rsbu1=%d, rsbu2=%d, cid=%d\n",
			chg->lpd_info.lpd_present,
			chg->lpd_info.lpd_rsbu1,
			chg->lpd_info.lpd_rsbu2,
			chg->lpd_info.lpd_cid);
	}

	if (info.chrg_otg_enabled && (info.chrg_uv < VBUS_MIN_MV * 1000)) {
		if (!otg_ulog_triggered && !lpd_ulog_triggered)
			bm_ulog_enable_log(true);
		otg_ulog_triggered = true;
		mmi_err(chg, "OTG: vbus collapse, vbus=%duV\n", info.chrg_uv);
	} else if (info.chrg_otg_enabled) {
		if (otg_ulog_triggered && !lpd_ulog_triggered)
			bm_ulog_enable_log(false);
		otg_ulog_triggered = false;
	}

	chg->chg_info.chrg_mv = info.chrg_uv / 1000;
	chg->chg_info.chrg_ma = info.chrg_ua / 1000;
	chg->chg_info.chrg_type = info.chrg_type;
	chg->chg_info.chrg_pmax_mw = info.chrg_pmax_mw;
	if (chg->chg_info.chrg_present != info.chrg_present && !info.chrg_present) {
		qti_encrypt_authentication(chg);
	}
	chg->chg_info.chrg_present = info.chrg_present;
	if (!info.chrg_present && info.chrg_type != 0)
		chg->chg_info.chrg_present = 1;

	chg->chg_info.vbus_present = chg->chg_info.chrg_mv > VBUS_MIN_MV;
	if (chg->wls_psy) {
		union power_supply_propval val;
		rc = power_supply_get_property(chg->wls_psy,
				POWER_SUPPLY_PROP_ONLINE, &val);
		if (!rc && val.intval)
			chg->chg_info.vbus_present = false;
	}
	chg->chg_info.chrg_otg_enabled = info.chrg_otg_enabled;
	chg->chg_info.lpd_present = chg->lpd_info.lpd_present;
	memcpy(chg_info, &chg->chg_info, sizeof(struct mmi_charger_info));

	if (chg->wls_psy){
		qti_charger_read(chg, OEM_PROP_WLS_DUMP_INFO,
					&wls_info,
					sizeof(struct wls_dump));

		qti_wireless_charge_dump_info(chg, wls_info);
	}

#if defined(MSB_DEV)
	qti_charger_read(chg, OEM_PROP_MSB_DEV_INFO,
				&msb_dev,
				sizeof(struct msb_dev_info));
	qti_msb_dev_info(chg, msb_dev);
#endif

#if defined(SWITCHEDCAP_DUMP)
	for (i = 0; i < chg->switched_nums; i++) {
		qti_charger_read(chg, OEM_PROP_MASTER_SWITCHEDCAP_INFO + i,
							&master_switched_info,
							sizeof(struct switched_dev_info));
		qti_switched_dump_info(chg, master_switched_info);
	}
#endif

#if defined(FUELGUAGE_DUMP)
	qti_charger_read(chg, OEM_PROP_FG_DUMP_INFO,
				&fg_info,
				sizeof(struct fg_dump));
	qti_fg_charge_dump_info(chg, fg_info);
#endif

    mmi_info(chg, "Thermal: primary_limit_level = %d, primary_fcc_ma = %d, secondary_limit_level = %d, thermal_secondary_fcc_ma = %d",
            chg->curr_thermal_primary_level, chg->thermal_primary_fcc_ua,
            chg->curr_thermal_secondary_level, chg->thermal_secondary_fcc_ua);
	bm_ulog_print_log(OEM_BM_ULOG_SIZE);

	return rc;
}

static int qti_charger_get_partner_prop(struct qti_charger *chg, enum power_supply_property prop, u32 *data)
{
	int rc;
	union power_supply_propval propval;
	static const char *partner_psy_name = NULL;

	if (NULL == partner_psy_name) {
		rc = of_property_read_string(chg->dev->of_node,
					"mmi,partner_psy_name", &partner_psy_name);
		if (rc) {
			mmi_err(chg, "Failed get the partner psy name");
			partner_psy_name = "";
			return rc;
		}
	} else if (!strlen(partner_psy_name)) {
		return 0;
	}

	if (!chg->partner_charger) {
		chg->partner_charger = power_supply_get_by_name(partner_psy_name);
		if (!chg->partner_charger)
			return -ENODEV;
	}

	rc = power_supply_get_property(chg->partner_charger, prop, &propval);
	if (rc < 0) {
		mmi_err(chg, "get property %d failed, rc=%d\n", prop, rc);
		return rc;
	}
	*data = propval.intval;
	return rc;
}

static int qti_charger_config_charge(void *data, struct mmi_charger_cfg *config)
{
	int rc;
	u32 value;
	struct qti_charger *chg = data;

	/* configure the charger if changed */
	if (config->target_fv != chg->chg_cfg.target_fv) {
		value = config->target_fv * 1000;
		rc = qti_charger_write(chg, OEM_PROP_CHG_FV,
					&value,
					sizeof(value));
		if (!rc)
			chg->chg_cfg.target_fv = config->target_fv;
	}
	if (config->target_fcc != chg->chg_cfg.target_fcc) {
		value = config->target_fcc * 1000;
		rc = qti_charger_write(chg, OEM_PROP_CHG_FCC,
					&value,
					sizeof(value));
		if (!rc)
			chg->chg_cfg.target_fcc = config->target_fcc;
	}
	if (config->charger_suspend != chg->chg_cfg.charger_suspend) {
		value = config->charger_suspend;
		rc = qti_charger_write(chg, OEM_PROP_CHG_SUSPEND,
					&value,
					sizeof(value));
		if (!rc)
			chg->chg_cfg.charger_suspend = config->charger_suspend;
	}
	if (config->charging_disable != chg->chg_cfg.charging_disable) {
		value = config->charging_disable;
		rc = qti_charger_write(chg, OEM_PROP_CHG_DISABLE,
					&value,
					sizeof(value));
		if (!rc)
			chg->chg_cfg.charging_disable = config->charging_disable;
	}

	if (config->taper_kickoff != chg->chg_cfg.taper_kickoff) {
		chg->chg_cfg.taper_kickoff = config->taper_kickoff;
		chg->chrg_taper_cnt = 0;
	}

	if (config->full_charged != chg->chg_cfg.full_charged) {
		chg->chg_cfg.full_charged = config->full_charged;
	}

	if (config->chrg_iterm != chg->chg_cfg.chrg_iterm) {
		value = config->chrg_iterm;
		rc = qti_charger_write(chg, OEM_PROP_CHG_ITERM,
					&value,
					sizeof(value));
		if (!rc)
			chg->chg_cfg.chrg_iterm = config->chrg_iterm;
	}
	if (config->fg_iterm != chg->chg_cfg.fg_iterm) {
		value = config->fg_iterm;
		rc = qti_charger_write(chg, OEM_PROP_CHG_FG_ITERM,
					&value,
					sizeof(value));
		if (!rc)
			chg->chg_cfg.fg_iterm = config->fg_iterm;
	}

	if (config->charging_reset != chg->chg_cfg.charging_reset) {
		if (config->charging_reset) {
			value = 1;
			rc = qti_charger_write(chg, OEM_PROP_CHG_DISABLE,
						&value,
						sizeof(value));
			msleep(200);
			value = 0;
			rc = qti_charger_write(chg, OEM_PROP_CHG_DISABLE,
						&value,
						sizeof(value));
		}
		chg->chg_cfg.charging_reset = config->charging_reset;
	}

	rc = qti_charger_get_partner_prop(chg, POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT, &value);
	if (!rc && chg->partner_charger_icl != value) {
		rc = qti_charger_write(chg, OEM_PROP_CHG_PARTNER_ICL,
					&value,
					sizeof(value));
		if (!rc)
			chg->partner_charger_icl = value;
	}

	rc = qti_charger_get_partner_prop(chg, POWER_SUPPLY_PROP_CAPACITY, &value);
	if (!rc && chg->partner_charger_soc != value) {
		rc = qti_charger_write(chg, OEM_PROP_CHG_PARTNER_SOC,
					&value,
					sizeof(value));
		if (!rc)
			chg->partner_charger_soc = value;
	}

	return 0;
}

#define TAPER_COUNT 2
static bool qti_charger_is_charge_tapered(void *data, int tapered_ma)
{
	bool is_tapered = false;
	struct qti_charger *chg = data;

	if (abs(chg->batt_info.batt_ma) <= tapered_ma) {
		if (chg->chrg_taper_cnt >= TAPER_COUNT) {
			is_tapered = true;
			chg->chrg_taper_cnt = 0;
		} else
			chg->chrg_taper_cnt++;
	} else
		chg->chrg_taper_cnt = 0;

	return is_tapered;
}

static bool qti_charger_is_charge_halt(void *data)
{
	struct qti_charger *chg = data;

	if (chg->batt_info.batt_status == POWER_SUPPLY_STATUS_NOT_CHARGING ||
	    chg->batt_info.batt_status == POWER_SUPPLY_STATUS_FULL)
		return true;

	return false;
}

static void qti_charger_set_constraint(void *data,
			struct mmi_charger_constraint *constraint)
{
	int rc;
	u32 value;
	struct qti_charger *chg = data;

	if (constraint->demo_mode != chg->constraint.demo_mode) {
		value = constraint->demo_mode;
		rc = qti_charger_write(chg, OEM_PROP_DEMO_MODE,
					&value,
					sizeof(value));
		if (!rc)
			chg->constraint.demo_mode = constraint->demo_mode;
	}

	if (constraint->factory_version != chg->constraint.factory_version) {
		value = constraint->factory_version;
		rc = qti_charger_write(chg, OEM_PROP_FACTORY_VERSION,
					&value,
					sizeof(value));
		if (!rc)
			chg->constraint.factory_version = constraint->factory_version;
	}

	if (constraint->factory_mode != chg->constraint.factory_mode) {
		value = constraint->factory_mode;
		rc = qti_charger_write(chg, OEM_PROP_FACTORY_MODE,
					&value,
					sizeof(value));
		if (!rc)
			chg->constraint.factory_mode = constraint->factory_mode;
	}

	if (constraint->dcp_pmax != chg->constraint.dcp_pmax) {
		value = constraint->dcp_pmax;
		rc = qti_charger_write(chg, OEM_PROP_CHG_BC_PMAX,
					&value,
					sizeof(value));
		if (!rc)
			chg->constraint.dcp_pmax = constraint->dcp_pmax;
	}

	if (constraint->hvdcp_pmax != chg->constraint.hvdcp_pmax) {
		value = constraint->hvdcp_pmax;
		rc = qti_charger_write(chg, OEM_PROP_CHG_QC_PMAX,
					&value,
					sizeof(value));
		if (!rc)
			chg->constraint.hvdcp_pmax = constraint->hvdcp_pmax;
	}

	if (constraint->pd_pmax != chg->constraint.pd_pmax) {
		value = constraint->pd_pmax;
		rc = qti_charger_write(chg, OEM_PROP_CHG_PD_PMAX,
					&value,
					sizeof(value));
		if (!rc)
			chg->constraint.pd_pmax = constraint->pd_pmax;
	}

	if (chg->wls_psy){
		if (constraint->wls_pmax != chg->constraint.wls_pmax) {
			value = constraint->wls_pmax;
			rc = qti_charger_write(chg, OEM_PROP_CHG_WLS_PMAX,
						&value,
						sizeof(value));
			if (!rc)
				chg->constraint.wls_pmax = constraint->wls_pmax;
		}
	}
}

static int qti_charger_write_profile(struct qti_charger *chg)
{
	int rc;
	char *data;
	int offset;
	int max_size = OEM_PROPERTY_DATA_SIZE * sizeof(u32);

	rc = qti_charger_write(chg, OEM_PROP_CHG_PROFILE_INFO,
				&chg->profile_info,
				sizeof(struct charger_profile_info));
	if (rc) {
		mmi_err(chg, "qti charger write profile info failed, rc=%d\n", rc);
		return rc;
	}

	if (!chg->profile_data)
		return 0;

	offset = 0;
	data = (char *)chg->profile_data;
	while (offset < chg->profile_info.data_size) {
		if ((chg->profile_info.data_size - offset) > max_size) {
			rc = qti_charger_write(chg,
					OEM_PROP_CHG_PROFILE_DATA,
					data + offset,
					max_size);
			offset += max_size;
		} else {
			rc = qti_charger_write(chg,
					OEM_PROP_CHG_PROFILE_DATA,
					data + offset,
					chg->profile_info.data_size - offset);
			offset += chg->profile_info.data_size - offset;
		}
		if (rc) {
			mmi_err(chg, "qti charger write profile data failed, rc=%d\n", rc);
			break;
		}
	}

	return rc;
}

static ssize_t tcmd_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	unsigned long mode;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &mode);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", mode);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_TCMD,
				&mode,
				sizeof(mode));

	return r ? r : count;
}

static ssize_t tcmd_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_TCMD,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", data);
}


static DEVICE_ATTR(tcmd, 0664,
		tcmd_show,
		tcmd_store);

static ssize_t force_pmic_icl_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	unsigned long pmic_icl;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &pmic_icl);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", pmic_icl);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_PMIC_ICL,
				&pmic_icl,
				sizeof(pmic_icl));

	return r ? r : count;
}

static ssize_t force_pmic_icl_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_PMIC_ICL,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", data);
}


static DEVICE_ATTR(force_pmic_icl, 0664,
		force_pmic_icl_show,
		force_pmic_icl_store);

static ssize_t force_wls_en_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	unsigned long wls_en;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &wls_en);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", wls_en);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_EN,
				&wls_en,
				sizeof(wls_en));

	return r ? r : count;
}

static ssize_t force_wls_en_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_EN,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", data);
}

static DEVICE_ATTR(force_wls_en, 0664,
		force_wls_en_show,
		force_wls_en_store);

static ssize_t force_usb_suspend_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	unsigned long usb_suspend;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &usb_suspend);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", usb_suspend);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_USB_SUSPEND,
				&usb_suspend,
				sizeof(usb_suspend));

	return r ? r : count;
}

static ssize_t force_usb_suspend_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_USB_SUSPEND,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", data);
}

static DEVICE_ATTR(force_usb_suspend, 0664,
		force_usb_suspend_show,
		force_usb_suspend_store);

static ssize_t force_wls_volt_max_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	unsigned long wls_volt_max;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &wls_volt_max);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", wls_volt_max);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_VOLT_MAX,
				&wls_volt_max,
				sizeof(wls_volt_max));

	return r ? r : count;
}

static ssize_t force_wls_volt_max_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_VOLT_MAX,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", data);
}

static DEVICE_ATTR(force_wls_volt_max, 0664,
		force_wls_volt_max_show,
		force_wls_volt_max_store);

static ssize_t force_wls_curr_max_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	unsigned long wls_curr_max;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &wls_curr_max);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", wls_curr_max);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_CURR_MAX,
				&wls_curr_max,
				sizeof(wls_curr_max));

	return r ? r : count;
}

static ssize_t force_wls_curr_max_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_CURR_MAX,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", data);
}

static DEVICE_ATTR(force_wls_curr_max, 0664,
		force_wls_curr_max_show,
		force_wls_curr_max_store);

static ssize_t wireless_chip_id_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	int data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_CHIP_ID,
				&data,
				sizeof(int));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "0x%04x\n", data);
}

static DEVICE_ATTR(wireless_chip_id, S_IRUGO,
		wireless_chip_id_show,
		NULL);

static int fod_gain_store(struct qti_charger *chip, const char *buf,
	u32 *fod_array)
{
	int i = 0, ret = 0, sum = 0;
	char *buffer;
	unsigned int temp;

	buffer = (char *)buf;

	for (i = 0; i < FOD_GAIN_MAX_LEN; i++) {
		ret = sscanf((const char *)buffer, "%x,%s", &temp, buffer);
		fod_array[i] = temp;
		sum++;
		if (ret != 2)
			break;
	}

	if (sum != FOD_GAIN_MAX_LEN) {
		pr_err("QTI: fod_gain array len err %d\n", sum);
		return -ENODEV;
	}

	ret = qti_charger_write(chip, OEM_PROP_WLS_RX_FOD_GAIN,
				fod_array,
				sizeof(struct fod_gain));
	if (ret) {
		mmi_err(chip, "qti charger write wls rx fod gain failed, rc=%d\n", ret);
		return ret;
	}


	return sum;
}

static ssize_t wls_fod_gain_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	fod_gain_store(chg, buf, chg->rx_fod_gain.fod_array_gain);
	return count;
}


static ssize_t wls_fod_gain_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int count = 0, i = 0;
	struct qti_charger *chg = dev_get_drvdata(dev);

	for (i = 0; i < FOD_GAIN_MAX_LEN; i++) {
		count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE,
				"0x%02x ", chg->rx_fod_gain.fod_array_gain[i]);
		if (i == FOD_GAIN_MAX_LEN - 1)
			count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE, "\n");
	}

	return count;
}

static DEVICE_ATTR(wls_fod_gain, 0664,
		wls_fod_gain_show,
		wls_fod_gain_store);

static int fod_curr_store(struct qti_charger *chip, const char *buf,
	u32 *fod_array)
{
	int i = 0, ret = 0, sum = 0;
	char *buffer;
	unsigned int temp;

	buffer = (char *)buf;

	for (i = 0; i < FOD_CURR_MAX_LEN; i++) {
		ret = sscanf((const char *)buffer, "%x,%s", &temp, buffer);
		fod_array[i] = temp;
		sum++;
		if (ret != 2)
			break;
	}

	if (sum != FOD_CURR_MAX_LEN) {
		pr_err("QTI: fod_curr array len err %d\n", sum);
		return -ENODEV;
	}

	ret = qti_charger_write(chip, OEM_PROP_WLS_RX_FOD_CURR,
				fod_array,
				sizeof(struct fod_curr));
	if (ret) {
		mmi_err(chip, "qti charger write wls rx fod curr failed, rc=%d\n", ret);
		return ret;
	}

	return sum;
}

static ssize_t wls_fod_curr_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	fod_curr_store(chg, buf, chg->rx_fod_curr.fod_array_curr);
	return count;
}

static ssize_t wls_fod_curr_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int count = 0, i = 0;
	struct qti_charger *chg = dev_get_drvdata(dev);

	for (i = 0; i < FOD_CURR_MAX_LEN; i++) {
		count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE,
				"0x%02x ", chg->rx_fod_curr.fod_array_curr[i]);
		if (i == FOD_CURR_MAX_LEN - 1)
			count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE, "\n");
	}

	return count;
}

static DEVICE_ATTR(wls_fod_curr, 0664,
		wls_fod_curr_show,
		wls_fod_curr_store);

static ssize_t batt_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int battsn_nums = 0, count = 0, i = 0;
	int rc;

	struct qti_charger *chg = dev_get_drvdata(dev);
	struct profile_sn_map {
		const char *id;
		const char *sn;
	} *map_table;

	battsn_nums = of_property_count_strings(chg->dev->of_node, "profile-ids-map");
	if (battsn_nums <= 0 || (battsn_nums % 2)) {
		mmi_err(chg, "Invalid profile-ids-map in DT, rc=%d\n", battsn_nums);
		return -EINVAL;
	}

	map_table = devm_kmalloc_array(chg->dev, battsn_nums / 2,
					sizeof(struct profile_sn_map),
					GFP_KERNEL);
	if (!map_table)
		return -ENOMEM;

	rc = of_property_read_string_array(chg->dev->of_node, "profile-ids-map",
					(const char **)map_table,
					battsn_nums);
	if (rc < 0) {
		mmi_err(chg, "Failed to get profile-ids-map, rc=%d\n", rc);
		goto free_map;
	}

	count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE, "%d", battsn_nums / 2);

	for (i = 0; i < battsn_nums / 2 && map_table[i].sn; i++) {
		count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE,
				"%s", map_table[i].sn);
	}
	count += scnprintf(buf+count, CHG_SHOW_MAX_SIZE, "\n");

free_map:
	devm_kfree(chg->dev, map_table);

	return count;
}

static DEVICE_ATTR_RO(batt_id);

static ssize_t addr_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	u32 addr;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtou32(buf, 0, &addr);
	if (r) {
		mmi_err(chg, "Invalid reg_address = 0x%x\n", addr);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_REG_ADDRESS,
				&addr,
				sizeof(addr));

	return r ? r : count;
}

static DEVICE_ATTR_WO(addr);

static ssize_t data_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long r;
	u32 data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtou32(buf, 0, &data);
	if (r) {
		mmi_err(chg, "Invalid reg_data = 0x%x\n", data);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_REG_DATA,
				&data,
				sizeof(data));

	return r ? r : count;
}

static ssize_t data_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 data;
	struct qti_charger *chg = dev_get_drvdata(dev);

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_REG_DATA,
				&data,
				sizeof(data));

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%x\n", data);
}

static DEVICE_ATTR(data, 0664,
		data_show,
		data_store);

static ssize_t tx_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long tx_mode;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &tx_mode);
	if (r) {
		pr_err("Invalid tx_mode = %lu\n", tx_mode);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_TX_MODE,
				&tx_mode,
				sizeof(tx_mode));
	chg->tx_mode = tx_mode;
	if (chg->wls_psy)
		sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "tx_mode");

	return r ? r : count;
}

static ssize_t tx_mode_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
#ifndef SKIP_QTI_CHARGER_CONFIRMAION
	u32 tx_mode = 0;
#endif
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}
#ifdef SKIP_QTI_CHARGER_CONFIRMAION
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->tx_mode);
#else
	qti_charger_read(chg, OEM_PROP_WLS_TX_MODE,
				&tx_mode,
				sizeof(tx_mode));

	chg->tx_mode = tx_mode;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", tx_mode);
#endif
}

static DEVICE_ATTR(tx_mode, S_IRUGO|S_IWUSR, tx_mode_show, tx_mode_store);

static ssize_t tx_mode_vout_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct qti_charger *chg = this_chip;
	struct wls_dump wls_info;
	u32 tx_vout = 0;
	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_DUMP_INFO,
				&wls_info,
				sizeof(struct wls_dump));

	tx_vout = wls_info.tx_vrect_mv;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", tx_vout);
}

static DEVICE_ATTR(tx_mode_vout, S_IRUGO,
		tx_mode_vout_show,
		NULL);

static ssize_t wlc_light_ctl_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long wlc_light_ctl;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &wlc_light_ctl);
	if (r) {
		pr_err("Invalid wlc_light_ctl = %lu\n", wlc_light_ctl);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_WLC_LIGHT_CTL,
				&wlc_light_ctl,
				sizeof(wlc_light_ctl));
	chg->wlc_light_ctl = wlc_light_ctl;
	if (chg->wls_psy)
		sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "wlc_light_ctl");

	return r ? r : count;
}

static ssize_t wlc_light_ctl_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("PEN: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->wlc_light_ctl);
}
static DEVICE_ATTR(wlc_light_ctl, S_IRUGO|S_IWUSR, wlc_light_ctl_show, wlc_light_ctl_store);


static ssize_t wlc_fan_speed_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long wlc_fan_speed;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &wlc_fan_speed);
	if (r) {
		pr_err("Invalid wlc_fan_speed = %lu\n", wlc_fan_speed);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_WLC_FAN_SPEED,
				&wlc_fan_speed,
				sizeof(wlc_fan_speed));
	chg->wlc_fan_speed = wlc_fan_speed;
	if (chg->wls_psy)
		sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "wlc_fan_speed");

	return r ? r : count;
}

static ssize_t wlc_fan_speed_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("PEN: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->wlc_fan_speed);
}
static DEVICE_ATTR(wlc_fan_speed, S_IRUGO|S_IWUSR, wlc_fan_speed_show, wlc_fan_speed_store);

static ssize_t wlc_tx_type_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 type = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_WLC_TX_TYPE,
				&type,
				sizeof(type));

	chg->wlc_tx_type = type;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", type);
}

static DEVICE_ATTR(wlc_tx_type, S_IRUGO,
		wlc_tx_type_show,
		NULL);

static ssize_t wlc_tx_power_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 power = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_WLC_TX_POWER,
				&power,
				sizeof(power));

	chg->wlc_tx_power = power;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", power);
}

static DEVICE_ATTR(wlc_tx_power, S_IRUGO,
		wlc_tx_power_show,
		NULL);

static ssize_t wlc_tx_capability_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 capability = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_WLC_TX_CAPABILITY,
				&capability,
				sizeof(capability));

	chg->wlc_tx_capability = capability;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", capability);
}

static DEVICE_ATTR(wlc_tx_capability, S_IRUGO,
		wlc_tx_capability_show,
		NULL);

static ssize_t wlc_tx_id_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 id = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_WLC_TX_ID,
				&id,
				sizeof(id));

	chg->wlc_tx_id = id;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", id);
}

static DEVICE_ATTR(wlc_tx_id, S_IRUGO,
		wlc_tx_id_show,
		NULL);

static ssize_t wlc_tx_sn_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 sn = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_WLC_TX_SN,
				&sn,
				sizeof(sn));

	chg->wlc_tx_sn = sn;
	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", sn);
}

static DEVICE_ATTR(wlc_tx_sn, S_IRUGO,
		wlc_tx_sn_show,
		NULL);

static ssize_t rx_connected_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->rx_connected);
}

static DEVICE_ATTR(rx_connected, S_IRUGO,
		rx_connected_show,
		NULL);

static ssize_t rx_dev_manufacturing_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 rx_dev_mfg = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_RX_DEV_MFG,
				&rx_dev_mfg,
				sizeof(rx_dev_mfg));

	chg->rx_dev_mfg= rx_dev_mfg;

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%#x\n", chg->rx_dev_mfg);
}
static DEVICE_ATTR(rx_dev_manufacturing, S_IRUGO,
		rx_dev_manufacturing_show,
		NULL);

static ssize_t rx_dev_type_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 rx_dev_type = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_RX_DEV_TYPE,
				&rx_dev_type,
				sizeof(rx_dev_type));

	chg->rx_dev_type = rx_dev_type;

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%#x\n", chg->rx_dev_type);
}
static DEVICE_ATTR(rx_dev_type, S_IRUGO,
		rx_dev_type_show,
		NULL);

static ssize_t rx_dev_id_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u32 rx_dev_id = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	qti_charger_read(chg, OEM_PROP_WLS_RX_DEV_ID,
				&rx_dev_id,
				sizeof(rx_dev_id));

	chg->rx_dev_id = rx_dev_id;

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%#x\n", chg->rx_dev_id);
}
static DEVICE_ATTR(rx_dev_id, S_IRUGO,
		rx_dev_id_show,
		NULL);


static ssize_t wlc_st_changed_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->wlc_status);
}

static DEVICE_ATTR(wlc_st_changed, S_IRUGO,
		wlc_st_changed_show,
		NULL);

static ssize_t wls_input_current_limit_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long wls_curr_max;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &wls_curr_max);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", wls_curr_max);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_CURR_MAX,
				&wls_curr_max,
				sizeof(wls_curr_max));

	chg->wls_curr_max = wls_curr_max;
	return r ? r : count;
}

static ssize_t wls_input_current_limit_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->wls_curr_max);
}
static DEVICE_ATTR(wls_input_current_limit, S_IRUGO|S_IWUSR, wls_input_current_limit_show, wls_input_current_limit_store);

static ssize_t wls_weak_charge_disable_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long weak_charge_disable;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &weak_charge_disable);
	if (r) {
		mmi_err(chg, "Invalid TCMD = %lu\n", weak_charge_disable);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_WEAK_CHARGE_CTRL,
				&weak_charge_disable,
				sizeof(weak_charge_disable));

	chg->weak_charge_disable = weak_charge_disable;
	return r ? r : count;
}

static ssize_t wls_weak_charge_disable_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("PEN: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->weak_charge_disable);
}

static DEVICE_ATTR(wls_weak_charge_disable, S_IRUGO|S_IWUSR, wls_weak_charge_disable_show, wls_weak_charge_disable_store);

static ssize_t folio_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long folio_mode;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &folio_mode);
	if (r) {
		pr_err("Invalid folio_mode = %lu\n", folio_mode);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_WLS_FOLIO_MODE,
				&folio_mode,
				sizeof(folio_mode));
	chg->folio_mode = folio_mode;

	return r ? r : count;
}

static ssize_t folio_mode_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("PEN: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->folio_mode);
}
static DEVICE_ATTR(folio_mode, S_IRUGO|S_IWUSR, folio_mode_show, folio_mode_store);

static ssize_t thermal_primary_charge_control_limit_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long charge_primary_limit_level;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	if (!chg->num_thermal_primary_levels)
		return 0;

	if (chg->num_thermal_primary_levels < 0) {
		pr_err("Incorrect num_thermal_primary_levels\n");
		return -EINVAL;
	}

	r = kstrtoul(buf, 0, &charge_primary_limit_level);
	if (r) {
		pr_err("Invalid charge_primary_limit_level = %lu\n", charge_primary_limit_level);
		return -EINVAL;
	}

	if (charge_primary_limit_level < 0 || charge_primary_limit_level > chg->num_thermal_primary_levels) {
		pr_err("Invalid charge_primary_limit_level: %lu\n", charge_primary_limit_level);
		return -EINVAL;
	}

	chg->thermal_primary_fcc_ua = chg->thermal_primary_levels[charge_primary_limit_level];
	chg->curr_thermal_primary_level = charge_primary_limit_level;
	pr_info("charge_primary_limit_level = %lu, thermal_primary_fcc_ma = %d",
			charge_primary_limit_level, chg->thermal_primary_fcc_ua);

	r = qti_charger_write(chg, OEM_PROP_THERM_PRIMARY_CHG_CONTROL,
				&chg->thermal_primary_fcc_ua,
				sizeof(chg->thermal_primary_fcc_ua));

	return r ? r : count;
}

static ssize_t thermal_primary_charge_control_limit_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("PEN: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->curr_thermal_primary_level );
}
static DEVICE_ATTR(thermal_primary_charge_control_limit, S_IRUGO|S_IWUSR, thermal_primary_charge_control_limit_show, thermal_primary_charge_control_limit_store);

static ssize_t thermal_primary_charge_control_limit_max_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->num_thermal_primary_levels);
}
static DEVICE_ATTR(thermal_primary_charge_control_limit_max, S_IRUGO, thermal_primary_charge_control_limit_max_show, NULL);


static ssize_t thermal_secondary_charge_control_limit_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long charge_secondary_limit_level;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	if (!chg->num_thermal_secondary_levels)
		return 0;

	if (chg->num_thermal_secondary_levels < 0) {
		pr_err("Incorrect num_thermal_psecondary_levels\n");
		return -EINVAL;
	}

	r = kstrtoul(buf, 0, &charge_secondary_limit_level);
	if (r) {
		pr_err("Invalid charge_secondary_limit_level = %lu\n", charge_secondary_limit_level);
		return -EINVAL;
	}

	if (charge_secondary_limit_level < 0 || charge_secondary_limit_level > chg->num_thermal_secondary_levels) {
		pr_err("Invalid charge_secondary_limit_level: %lu\n", charge_secondary_limit_level);
		return -EINVAL;
	}

	chg->thermal_secondary_fcc_ua = chg->thermal_secondary_levels[charge_secondary_limit_level];
	chg->curr_thermal_secondary_level = charge_secondary_limit_level;
	pr_info("charge_secondary_limit_level = %lu, thermal_secondary_fcc_ma = %d",
			charge_secondary_limit_level, chg->thermal_secondary_fcc_ua);

	r = qti_charger_write(chg, OEM_PROP_THERM_SECONDARY_CHG_CONTROL,
				&chg->thermal_secondary_fcc_ua,
				sizeof(chg->thermal_secondary_fcc_ua));

	return r ? r : count;
}

static ssize_t thermal_secondary_charge_control_limit_show(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("PEN: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->curr_thermal_secondary_level );
}
static DEVICE_ATTR(thermal_secondary_charge_control_limit, S_IRUGO|S_IWUSR, thermal_secondary_charge_control_limit_show, thermal_secondary_charge_control_limit_store);

static ssize_t thermal_secondary_charge_control_limit_max_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->num_thermal_secondary_levels);
}
static DEVICE_ATTR(thermal_secondary_charge_control_limit_max, S_IRUGO, thermal_secondary_charge_control_limit_max_show, NULL);

static ssize_t cid_status_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	return scnprintf(buf, CHG_SHOW_MAX_SIZE, "%d\n", chg->lpd_info.lpd_cid);
}
static DEVICE_ATTR(cid_status, S_IRUGO, cid_status_show, NULL);

static ssize_t typec_reset_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	int r;
	unsigned int reset = 0;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtou32(buf, 0, &reset);
	if (r) {
		pr_err("Invalid typec_reset = %d\n", reset);
		return -EINVAL;
	}

	if (reset)
		mmi_warn(chg, "typec_reset triggered\n");
	else
		return count;

	r = qti_charger_write(chg, OEM_PROP_TYPEC_RESET,
			&reset,
			sizeof(reset));

	return r ? r : count;
}
static DEVICE_ATTR(typec_reset, S_IWUSR|S_IWGRP, NULL, typec_reset_store);

static ssize_t fg_operation_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	unsigned long r;
	unsigned long fg_operation_cmd;
	struct qti_charger *chg = this_chip;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return -ENODEV;
	}

	r = kstrtoul(buf, 0, &fg_operation_cmd);
	if (r) {
		pr_err("Invalid fg_operation_cmd = %lu\n", fg_operation_cmd);
		return -EINVAL;
	}

	r = qti_charger_write(chg, OEM_PROP_FG_OPERATION,
			&fg_operation_cmd,
			sizeof(fg_operation_cmd));

	return r ? r : count;
}
static DEVICE_ATTR(fg_operation, S_IWUSR|S_IWGRP, NULL, fg_operation_store);

//ATTRIBUTE_GROUPS(qti_charger);
#define TX_INT_FOD      (0x01<<12)
#if defined(WIRELESS_CPS4035B) || defined(WIRELESS_CPS4019)
static int show_wls_dump_info(struct seq_file *m, void *data)
{
	struct qti_charger *chip = m->private;
	struct wls_dump wls_info;

	qti_charger_read(chip, OEM_PROP_WLS_DUMP_INFO,
				&wls_info,
				sizeof(struct wls_dump));

	seq_printf(m, "CHIP_ID: 0x%04x\n", wls_info.chip_id);

	seq_printf(m, "MTP_FW_VER: 0x%04x\n", wls_info.mtp_fw_ver);

	seq_printf(m, "IRQ STATUS: 0x%04x\n", wls_info.irq_status);

	seq_printf(m, "SYS_MODE:  RX/TX %d\n", wls_info.sys_mode);

	seq_printf(m, "OP_MODE:  BPP/EPP/Moto50W 0x%x\n", wls_info.op_mode);

	seq_printf(m, "RX_FOP:   %dkHz\n", wls_info.rx_fop);

	seq_printf(m, "RX_VOUT: %dmV\n",  wls_info.rx_vout_mv);

	seq_printf(m, "RX_VRECT: %dmV\n",  wls_info.rx_vrect_mv);

	seq_printf(m, "RX_IRECT: %dmA\n",  wls_info.rx_irect_ma);

	seq_printf(m, "RX_EPT: 0x%04x\n",  wls_info.rx_ept);

	seq_printf(m, "RX_CE: %d\n",  wls_info.rx_ce);

	seq_printf(m, "RX_RP: %d\n",  wls_info.rx_rp);

	seq_printf(m, "RX_DieTemp: %dC\n",  wls_info.rx_dietemp);

	seq_printf(m, "RX_NEG_POWER: %dw\n",  wls_info.rx_neg_power);

	seq_printf(m, "TX_IIN: %dmA\n",  wls_info.tx_iin_ma);

	seq_printf(m, "TX_VIN: %dmV\n",  wls_info.tx_vin_mv);

	seq_printf(m, "TX_VRECT: %dmV\n",  wls_info.tx_vrect_mv);

	seq_printf(m, "TX_DET_RX_POWER: %dmW\n",  wls_info.tx_det_rx_power);

	seq_printf(m, "TX_POWER: %dmW\n",  wls_info.tx_power);

	seq_printf(m, "TX_EPT_RSN: 0x%04x\n",  wls_info.tx_ept);

	seq_printf(m, "POWER_LOSS: %dmW\n",  wls_info.power_loss);

	seq_printf(m, "TX_FOD: %d\n",  (wls_info.irq_status & TX_INT_FOD) ? 1 : 0);

	seq_printf(m, "USB_OTG: %d\n",  wls_info.usb_otg);

	seq_printf(m, "WLS_BOOST: %d\n",  wls_info.wls_boost);

	seq_printf(m, "WLS_ICL_MA: %d\n",  wls_info.wls_icl_ma);

	seq_printf(m, "WLS_ICL_THERM_MA: %d\n",  wls_info.wls_icl_therm_ma);

	return 0;
}
#else
static int show_wls_dump_info(struct seq_file *m, void *data)
{
	struct qti_charger *chip = m->private;
	struct wls_dump wls_info;

	qti_charger_read(chip, OEM_PROP_WLS_DUMP_INFO,
				&wls_info,
				sizeof(struct wls_dump));

	seq_printf(m, "CHIP_ID: 0x%04x\n", wls_info.chip_id);

	seq_printf(m, "MTP_FW_VER: 0x%04x\n", wls_info.mtp_fw_ver);

	seq_printf(m, "IRQ STATUS: 0x%04x\n", wls_info.irq_status);

	seq_printf(m, "SYS_MODE:  RX/TX %d\n", wls_info.sys_mode);

	seq_printf(m, "OP_MODE:  BPP/EPP 0x%x\n", wls_info.op_mode);

	seq_printf(m, "RX_FOP:   %dkHz\n", wls_info.rx_fop);

	seq_printf(m, "RX_VOUT: %dmV\n",  wls_info.rx_vout_mv);

	seq_printf(m, "RX_VRECT: %dmV\n",  wls_info.rx_vrect_mv);

	seq_printf(m, "RX_IRECT: %dmV\n",  wls_info.rx_irect_ma);

	seq_printf(m, "RX_NEG_POWER: %dw\n",  wls_info.rx_neg_power);

	seq_printf(m, "TX_IIN: %dmA\n",  wls_info.tx_iin_ma);

	seq_printf(m, "TX_VIN: %dmV\n",  wls_info.tx_vin_mv);

	seq_printf(m, "TX_VRECT: %dmV\n",  wls_info.tx_vrect_mv);

	seq_printf(m, "TX_FOD_I: %d\n",  wls_info.tx_fod_I);

	seq_printf(m, "TX_FOD_II: %d\n",  wls_info.tx_fod_II);

	seq_printf(m, "TX_FOD_RP: %d\n",  wls_info.tx_fod_rp);

	seq_printf(m, "TX_DET_RX_POWER: %dmW\n",  wls_info.tx_det_rx_power);

	seq_printf(m, "TX_POWER: %dmW\n",  wls_info.tx_power);

	seq_printf(m, "POWER_LOSS: %dmW\n",  wls_info.power_loss);

	seq_printf(m, "TX_FOD: %d\n",  (wls_info.irq_status & TX_INT_FOD) ? 1 : 0);

	seq_printf(m, "FOLIO_MODE: %d\n",  wls_info.folio_mode);

	seq_printf(m, "PEN_STATUS: %d\n",  wls_info.pen_status);

	seq_printf(m, "PEN_SOC: %d\n",  wls_info.pen_soc);

	seq_printf(m, "PEN_ERROR: %d\n",  wls_info.pen_error);

	seq_printf(m, "USB_OTG: %d\n",  wls_info.usb_otg);

	seq_printf(m, "WLS_BOOST: %d\n",  wls_info.wls_boost);

	seq_printf(m, "WLS_ICL_MA: %d\n",  wls_info.wls_icl_ma);

	seq_printf(m, "WLS_ICL_THERM_MA: %d\n",  wls_info.wls_icl_therm_ma);

	return 0;
}
#endif

static int wls_dump_info_debugfs_open(struct inode *inode, struct file *file)
{
	struct qti_charger *chip = inode->i_private;

	return single_open(file, show_wls_dump_info, chip);
}

static const struct file_operations wls_dump_info_debugfs_ops = {
	.owner		= THIS_MODULE,
	.open		= wls_dump_info_debugfs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void create_debugfs_entries(struct qti_charger *chip)
{
	struct dentry *ent;

	chip->debug_root = debugfs_create_dir("qti_glink_charger", NULL);
	if (!chip->debug_root) {
		mmi_err(chip, "Couldn't create debug dir\n");
		return;
	}

	ent = debugfs_create_file("wls_dump_info", S_IFREG | S_IRUGO,
				  chip->debug_root, chip,
				  &wls_dump_info_debugfs_ops);
	if (!ent)
		mmi_err(chip, "Couldn't create wls_dump_info debug file\n");
}


static int wireless_charger_notify_callback(struct notifier_block *nb,
		unsigned long event, void *data)
{
	struct qti_charger_notify_data *notify_data = data;
	struct qti_charger *chg = container_of(nb, struct qti_charger, wls_nb);

	if (notify_data->receiver != OEM_NOTIFY_RECEIVER_WLS_CHG) {
		pr_err("Skip mis-matched receiver: %#x\n", notify_data->receiver);
		return 0;
	}

        switch (event) {
        case NOTIFY_EVENT_WLS_RX_CONNECTED:
	/* RX connected update */
		if (notify_data->data[0] != chg->rx_connected) {
			if (chg->wls_psy) {
				pr_info("report rx_connected %d\n", notify_data->data[0]);
				sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "rx_connected");
			}
		}
		chg->rx_connected = notify_data->data[0];
	            break;
        case NOTIFY_EVENT_WLS_RX_OVERTEMP:
		break;
        case NOTIFY_EVENT_WLS_CHANGE:
		if (notify_data->data[0] != chg->tx_mode) {
			if (chg->wls_psy) {
				pr_info("report tx_mode %d\n", notify_data->data[0]);
				sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "tx_mode");
			}
		}
		break;
        case NOTIFY_EVENT_WLS_WLC_CHANGE:
	/* WLC status update */
		if (notify_data->data[0] != chg->wlc_status) {
			chg->wlc_status = notify_data->data[0];
			if (chg->wls_psy) {
				pr_info("report wlc_st_changed %d\n", notify_data->data[0]);
				sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "wlc_st_changed");
			}
		}
		break;
        case NOTIFY_EVENT_WLS_RX_DEV_INFO_UPDATE:
	/* RX dev info update */
		if (notify_data->data[0] != chg->rx_dev_mfg) {
			if (chg->wls_psy) {
				pr_info("report rx_dev_mfg %#x\n", notify_data->data[0]);
				sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "rx_dev_manufacturing");
			}
			chg->rx_dev_mfg = notify_data->data[0];
		}
		if (notify_data->data[1] != chg->rx_dev_type) {
			if (chg->wls_psy) {
				pr_info("report rx_dev_type %#x\n", notify_data->data[1]);
				sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "rx_dev_type");
			}
			chg->rx_dev_type = notify_data->data[1];
		}
		if (notify_data->data[2] != chg->rx_dev_id) {
			if (chg->wls_psy) {
				pr_info("report rx_dev_id %#x\n", notify_data->data[2]);
				sysfs_notify(&chg->wls_psy->dev.parent->kobj, NULL, "rx_dev_id");
			}
			chg->rx_dev_id = notify_data->data[2];
		}
		break;
        default:
		pr_err("Unknown wireless event: %#lx\n", event);
                break;
        }

	if (chg->wls_psy) {
		pr_info("wireless charger notify, event %lu\n", event);
		power_supply_changed(chg->wls_psy);
	}

        return 0;
}

static void wireless_psy_init(struct qti_charger *chg)
{
	int rc;

	if (chg->wls_psy)
		return;

	chg->wls_psy = power_supply_get_by_name("wireless");
	if (!chg->wls_psy) {
		pr_err("No pen power supply found\n");
		return;
	}
	pr_info("wireless power supply is found\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_tx_mode);
        if (rc)
		pr_err("couldn't create wireless tx mode\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_tx_mode_vout);
        if (rc)
		pr_err("couldn't create wireless tx mode vout\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_rx_connected);
        if (rc)
		pr_err("couldn't create wireless rx_connected\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_rx_dev_manufacturing);
        if (rc)
		pr_err("couldn't create wireless rx_dev_manufacturing\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_rx_dev_type);
        if (rc)
		pr_err("couldn't create wireless rx_dev_type\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_rx_dev_id);
        if (rc)
		pr_err("couldn't create wireless rx_dev_id\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wls_input_current_limit);
        if (rc)
		pr_err("couldn't create wireless input current limit error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_folio_mode);
        if (rc)
		pr_err("couldn't create wireless folio mode error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_light_ctl);
        if (rc)
		pr_err("couldn't create wireless wlc light control error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_fan_speed);
        if (rc)
		pr_err("couldn't create wireless wlc fan speed error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_type);
        if (rc)
		pr_err("couldn't create wireless wlc tx type error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_power);
        if (rc)
		pr_err("couldn't create wireless wlc tx power capacity error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_capability);
        if (rc)
		pr_err("couldn't create wireless wlc tx capability error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_id);
        if (rc)
		pr_err("couldn't create wireless wlc tx id error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_sn);
        if (rc)
		pr_err("couldn't create wireless wlc tx sn error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_st_changed);
        if (rc)
		pr_err("couldn't create wireless wlc status changed error\n");

	rc = device_create_file(chg->wls_psy->dev.parent,
				&dev_attr_wls_weak_charge_disable);
        if (rc)
		pr_err("couldn't create wireless wlc weak charge disable error\n");
	chg->wls_nb.notifier_call = wireless_charger_notify_callback;
	rc = qti_charger_register_notifier(&chg->wls_nb);
	if (rc)
		pr_err("Failed to register notifier, rc=%d\n", rc);
}

static void wireless_psy_deinit(struct qti_charger *chg)
{
	if (!chg->wls_psy)
		return;

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_tx_mode);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_tx_mode_vout);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_rx_connected);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wls_input_current_limit);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_folio_mode);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_light_ctl);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_fan_speed);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_type);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_power);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_capability);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_id);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_tx_sn);

	device_remove_file(chg->wls_psy->dev.parent,
				&dev_attr_wlc_st_changed);

	qti_charger_unregister_notifier(&chg->wls_nb);

	power_supply_put(chg->wls_psy);
	chg->wls_psy = NULL;
}

/* Battery presence detection threshold on battery temperature */
#define BPD_TEMP_THRE -3000
static int battery_psy_get_prop(struct power_supply *psy,
		enum power_supply_property prop,
		union power_supply_propval *pval)
{
	int rc;
	struct battery_info info = {0};
	struct qti_charger *chg = power_supply_get_drvdata(psy);

	pval->intval = -ENODATA;

	rc = qti_charger_read(chg, OEM_PROP_BATT_INFO, &info,
				sizeof(struct battery_info));
	if (rc)
		return rc;

	switch (prop) {
	case POWER_SUPPLY_PROP_STATUS:
		pval->intval = info.batt_status;
		break;
	case POWER_SUPPLY_PROP_PRESENT:
		pval->intval = info.batt_temp > BPD_TEMP_THRE? 1 : 0;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		pval->intval = info.batt_uv;
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		pval->intval = info.batt_ua;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
		pval->intval = info.batt_soc / 100;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		pval->intval = info.batt_temp / 10;
		break;
	case POWER_SUPPLY_PROP_CHARGE_FULL:
		pval->intval = info.batt_full_uah;
		break;
	case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
		pval->intval = info.batt_design_uah;
		break;
	case POWER_SUPPLY_PROP_CHARGE_COUNTER:
		pval->intval = info.batt_chg_counter;
		break;
	default:
		break;
	}

	return rc;
}

static int battery_psy_set_prop(struct power_supply *psy,
		enum power_supply_property prop,
		const union power_supply_propval *pval)
{
	struct qti_charger *chg = power_supply_get_drvdata(psy);

	switch (prop) {
	default:
		mmi_err(chg, "Not supported property: %d\n", prop);
		return -EINVAL;
	}

	return 0;
}

static enum power_supply_property battery_props[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN,
	POWER_SUPPLY_PROP_CHARGE_FULL,
	POWER_SUPPLY_PROP_CHARGE_COUNTER,
};

static const struct power_supply_desc batt_psy_desc = {
	.name			= "main_battery",
	.type			= POWER_SUPPLY_TYPE_MAINS,
	.properties		= battery_props,
	.num_properties		= ARRAY_SIZE(battery_props),
	.get_property		= battery_psy_get_prop,
	.set_property		= battery_psy_set_prop,
};

static int mmi_get_bootarg_dt(char *key, char **value, char *prop, char *spl_flag)
{
	const char *bootargs_tmp = NULL;
	char *idx = NULL;
	char *kvpair = NULL;
	int err = 1;
	struct device_node *n = of_find_node_by_path("/chosen");
	size_t bootargs_tmp_len = 0;
	char *bootargs_str = NULL;

	if (n == NULL)
		goto err;

	if (of_property_read_string(n, prop, &bootargs_tmp) != 0)
		goto putnode;

	bootargs_tmp_len = strlen(bootargs_tmp);
	if (!bootargs_str) {
		/* The following operations need a non-const
		 * version of bootargs
		 */
		bootargs_str = kzalloc(bootargs_tmp_len + 1, GFP_KERNEL);
		if (!bootargs_str)
			goto putnode;
	}
	strlcpy(bootargs_str, bootargs_tmp, bootargs_tmp_len + 1);

	idx = strnstr(bootargs_str, key, strlen(bootargs_str));
	if (idx) {
		kvpair = strsep(&idx, " ");
		if (kvpair)
			if (strsep(&kvpair, "=")) {
				*value = strsep(&kvpair, spl_flag);
				if (*value)
					err = 0;
			}
	}

putnode:
	of_node_put(n);
err:
	return err;
}

static int mmi_get_bootarg(char *key, char **value)
{
#ifdef CONFIG_BOOT_CONFIG
	return mmi_get_bootarg_dt(key, value, "mmi,bootconfig", "\n");
#else
	return mmi_get_bootarg_dt(key, value, "bootargs", " ");
#endif
}

static int mmi_get_sku_type(struct qti_charger *chg, u8 *sku_type)
{
	char *s = NULL;
	char androidboot_radio_str[RADIO_MAX_LEN];

	if (mmi_get_bootarg("androidboot.radio=", &s) == 0) {
		if (s != NULL) {
			strlcpy(androidboot_radio_str, s, RADIO_MAX_LEN);
			if (!strncmp("PRC", androidboot_radio_str, 3)) {
				*sku_type = MMI_CHARGER_SKU_PRC;
			} else if (!strncmp("ROW", androidboot_radio_str, 3)) {
				*sku_type = MMI_CHARGER_SKU_ROW;
			} else if (!strncmp("NA", androidboot_radio_str, 2)) {
				*sku_type = MMI_CHARGER_SKU_NA;
			} else if (!strncmp("VZW", androidboot_radio_str, 3)) {
				*sku_type = MMI_CHARGER_SKU_VZW;
			} else if (!strncmp("JPN", androidboot_radio_str, 3)) {
				*sku_type = MMI_CHARGER_SKU_JPN;
			} else if (!strncmp("ITA", androidboot_radio_str, 3)) {
				*sku_type = MMI_CHARGER_SKU_ITA;
			} else if (!strncmp("NAE", androidboot_radio_str, 3)) {
				*sku_type = MMI_CHARGER_SKU_NAE;
			} else if (!strncmp("SUPERSET", androidboot_radio_str, 8)) {
				*sku_type = MMI_CHARGER_SKU_SUPERSET;
			} else {
				*sku_type = 0;
			}
			mmi_info(chg, "SKU type: %s, 0x%02x\n", androidboot_radio_str, *sku_type);
			return 0;
		} else {
			mmi_err(chg, "Could not get SKU type\n");
			return -1;
		}
	} else {
		mmi_err(chg, "Could not get radio bootarg\n");
		return -1;
	}
}

static int mmi_get_hw_revision(struct qti_charger *chg, u16 *hw_rev)
{
	char *s = NULL;
	char androidboot_hwrev_str[RADIO_MAX_LEN];
	int ret;

	if (mmi_get_bootarg("androidboot.hwrev=", &s) == 0) {
		if (s != NULL) {
			strlcpy(androidboot_hwrev_str, s, RADIO_MAX_LEN);
			ret = kstrtou16(androidboot_hwrev_str, 16, hw_rev);
			if (ret < 0) {
				mmi_info(chg, "kstrtou16 error: %d \n", ret);
				return -1;
			}
			mmi_info(chg, "HW revision: 0x%x\n", *hw_rev);
			return 0;
		} else {
			mmi_err(chg, "Could not get HW  revision\n");
			return -1;
		}
	} else {
		mmi_err(chg, "Could not get hwrev bootarg\n");
		return -1;
	}
}

static inline int primary_get_max_charge_cntl_limit(struct thermal_cooling_device *tcd,
                    unsigned long *state)
{
    struct qti_charger* chg = tcd->devdata;

    *state = chg->num_thermal_primary_levels;

    return 0;
}

static inline int primary_get_cur_charge_cntl_limit(struct thermal_cooling_device *tcd,
                    unsigned long *state)
{
    struct qti_charger* chg = tcd->devdata;

    *state = chg->curr_thermal_primary_level;

    return 0;
}

static int primary_set_cur_charge_cntl_limit(struct thermal_cooling_device *tcd,
                    unsigned long state)
{
    char buf[32] = {0};

    sprintf(buf, "%ld", state);

    return thermal_primary_charge_control_limit_store(NULL, NULL, buf, strlen(buf));
}

static const struct thermal_cooling_device_ops primary_charge_ops = {
    .get_max_state = primary_get_max_charge_cntl_limit,
    .get_cur_state = primary_get_cur_charge_cntl_limit,
    .set_cur_state = primary_set_cur_charge_cntl_limit,
};

static inline int secondary_get_max_charge_cntl_limit(struct thermal_cooling_device *tcd,
                    unsigned long *state)
{
    struct qti_charger* chg = tcd->devdata;

    *state = chg->num_thermal_secondary_levels;

    return 0;
}

static inline int secondary_get_cur_charge_cntl_limit(struct thermal_cooling_device *tcd,
                    unsigned long *state)
{
    struct qti_charger* chg = tcd->devdata;

    *state = chg->curr_thermal_secondary_level;

    return 0;
}

static int secondary_set_cur_charge_cntl_limit(struct thermal_cooling_device *tcd,
                    unsigned long state)
{
    char buf[32] = {0};

    sprintf(buf, "%ld", state);

    return thermal_secondary_charge_control_limit_store(NULL, NULL, buf, strlen(buf));
}

static const struct thermal_cooling_device_ops secondary_charge_ops = {
    .get_max_state = secondary_get_max_charge_cntl_limit,
    .get_cur_state = secondary_get_cur_charge_cntl_limit,
    .set_cur_state = secondary_set_cur_charge_cntl_limit,
};

/*************************
 * USB   COOLER   START  *
 *************************/
static bool mmi_is_softbank_sku(struct qti_charger *chg)
{
	char *s = NULL;
	bool is_softbank = false;
	char androidboot_carrier_str[RADIO_MAX_LEN];

	if (mmi_get_bootarg("androidboot.carrier=", &s) == 0) {
		mmi_info(chg, "Get bootarg androidboot.hardware.sku success");
		if (s != NULL) {
			strlcpy(androidboot_carrier_str, s, RADIO_MAX_LEN);
			mmi_info(chg, "carrier: %s", androidboot_carrier_str);
			if (!strncmp("softbank", androidboot_carrier_str, 8)) {
				is_softbank = true;
			}
		}
	}
	return is_softbank;
}
static int usb_therm_set_mosfet(struct qti_charger *chg, bool enable)
{
	int rc = 0;
	u32 value = 0;
	/*set typec mosfet output*/
	mmi_info(chg, "%s,set mos en: %d, chrg_type: %d, mosfet_is_enable: %d",__func__,enable,chg->chg_info.chrg_type, chg->mosfet_is_enable);
	if(enable == true && chg->mosfet_is_enable == false){
		value = 1;
		rc = qti_charger_write(chg, OEM_PROP_CHG_DISABLE,
					&value, sizeof(value));
		value = 1;
		rc = qti_charger_write(chg, OEM_PROP_CHG_SUSPEND,
					&value, sizeof(value));
		udelay(100);
		if ((chg->chg_info.chrg_type != POWER_SUPPLY_USB_TYPE_SDP)&&
		    (chg->chg_info.chrg_type !=POWER_SUPPLY_USB_TYPE_CDP) &&
		    (gpio_is_valid(chg->mos_en_gpio))) {
			gpio_direction_output(chg->mos_en_gpio, enable);
			mmi_info(chg, "%s,open mos en: %d %d",__func__,enable,rc);
		}
		chg->mosfet_is_enable = true;
	}
	else if (enable == false && chg->mosfet_is_enable == true){
		if(gpio_is_valid(chg->mos_en_gpio)) {
			gpio_direction_output(chg->mos_en_gpio, enable);
		}
		udelay(100);
		value = 0;
		rc = qti_charger_write(chg, OEM_PROP_CHG_DISABLE,
					&value, sizeof(value));
		value = 0;
		rc = qti_charger_write(chg, OEM_PROP_CHG_SUSPEND,
					&value, sizeof(value));
		chg->mosfet_is_enable = false;
		mmi_info(chg, "%s,close mos en: %d %d",__func__,enable,rc);
	} else {
		mmi_info(chg, "%s,ignore the usb_therm settings",__func__);
	}

	return rc;
}

static int usb_therm_get_mosfet(struct qti_charger *chg)
{
	int ret = 0;

	/*get typec mosfet output*/
	if (gpio_is_valid(chg->mos_en_gpio)) {
//		mmi_err(chip, "%s,get mos en.",__func__);
		return gpio_get_value(chg->mos_en_gpio);
	} else {
		return chg->mosfet_is_enable;
	}

	return ret;
}


static int usb_therm_get_max_state(struct thermal_cooling_device *cdev,
	unsigned long *state)
{
	*state = 1;

	return 0;
}

static int usb_therm_get_cur_state(struct thermal_cooling_device *cdev,
	unsigned long *state)
{
	struct qti_charger *chg = cdev->devdata;

	*state = usb_therm_get_mosfet(chg);

	return 0;
}

static int usb_therm_set_cur_state(struct thermal_cooling_device *cdev,
	unsigned long state)
{
	struct qti_charger *chg = cdev->devdata;
	if (state) {
		mmi_info(chg, "Enable typec mosfet.");
		usb_therm_set_mosfet(chg, true);
	} else {
		mmi_info(chg, "Disable typec mosfet.");
		usb_therm_set_mosfet(chg, false);
	}

	return 0;
}

static const struct thermal_cooling_device_ops usb_therm_ops = {
	.get_max_state = usb_therm_get_max_state,
	.get_cur_state = usb_therm_get_cur_state,
	.set_cur_state = usb_therm_set_cur_state,
};

static int qti_charger_init_usb_therm_cooler(struct qti_charger *chg, u16 hwrev)
{
	int ret;
	u32 support_gpio_hwrev=0x0;
	/* Register thermal zone cooling device */
	chg->cdev = thermal_of_cooling_device_register(dev_of_node(chg->dev),
		"usb_therm_cooler", chg, &usb_therm_ops);

	if (IS_ERR(chg->cdev)) {
		mmi_err(chg, "Cooling register failed for usb_therm, ret:%ld\n",
			PTR_ERR(chg->cdev));
		return PTR_ERR(chg->cdev);
	}
	mmi_info(chg, "Cooling register success for usb_therm.");

	if (of_property_read_u32(chg->dev->of_node, "mmi,support-gpio-hwrev", &support_gpio_hwrev)) {
		support_gpio_hwrev=0x0;
	}

	/*typec mosfet outout en control*/
	chg->mos_en_gpio = -1;
	if (hwrev >= support_gpio_hwrev) {
		chg->mos_en_gpio = of_get_named_gpio(chg->dev->of_node, "mmi,mos-en-gpio", 0);
	}
	mmi_info(chg, "support_gpio_hwrev=0x%x hwrev=0x%x mos_en_gpio=%d",support_gpio_hwrev, hwrev, chg->mos_en_gpio);
	if (gpio_is_valid(chg->mos_en_gpio))
	{
		ret = gpio_request(chg->mos_en_gpio, "mmi mos en pin");
		if (ret) {
			mmi_err(chg, "%s: %d gpio(mos en) request failed.", __func__, chg->mos_en_gpio);
			return ret;
		}

		gpio_direction_output(chg->mos_en_gpio, 0);//default enable mos charge
	}

	chg->mosfet_is_enable = false;
	return 0;
}

static void thermal_charge_control_init(struct qti_charger *chg)
{
	struct power_supply		*battery_psy;
	int rc;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return;
	}

	battery_psy = power_supply_get_by_name("battery");
	if (!battery_psy) {
		pr_err("No battery power supply found\n");
		return;
	}

	rc = device_create_file(&battery_psy->dev,
				&dev_attr_thermal_primary_charge_control_limit);
	if (rc) {
		pr_err("couldn't create thermal_primary_charge_control_limit\n");
	}

	rc = device_create_file(&battery_psy->dev,
				&dev_attr_thermal_primary_charge_control_limit_max);
	if (rc) {
		pr_err("couldn't create thermal_primary_charge_control_limit_max\n");
	}

	rc = device_create_file(&battery_psy->dev,
				&dev_attr_thermal_secondary_charge_control_limit);
	if (rc) {
		pr_err("couldn't create thermal_secondary_charge_control_limit\n");
	}

	rc = device_create_file(&battery_psy->dev,
				&dev_attr_thermal_secondary_charge_control_limit_max);
	if (rc) {
		pr_err("couldn't create thermal_secondary_charge_control_limit_max\n");
	}

	chg->primary_tcd = thermal_cooling_device_register("primary_charge", chg, &primary_charge_ops);
	if (IS_ERR_OR_NULL(chg->primary_tcd)) {
		rc = PTR_ERR_OR_ZERO(chg->primary_tcd);
		dev_err(chg->dev, "Failed to register thermal cooling device rc=%d\n", rc);
	}

	chg->secondary_tcd = thermal_cooling_device_register("secondary_charge", chg, &secondary_charge_ops);
	if (IS_ERR_OR_NULL(chg->secondary_tcd)) {
		rc = PTR_ERR_OR_ZERO(chg->secondary_tcd);
		dev_err(chg->dev, "Failed to register thermal cooling device rc=%d\n", rc);
	}
}

static void thermal_charge_control_deinit(struct qti_charger *chg)
{
	struct power_supply		*battery_psy;

	if (!chg) {
		pr_err("QTI: chip not valid\n");
		return;
	}

	battery_psy = power_supply_get_by_name("battery");
	if (!battery_psy) {
		pr_err("No battery power supply found\n");
		return;
	}

	device_remove_file(battery_psy->dev.parent,
				&dev_attr_thermal_primary_charge_control_limit);

	device_remove_file(battery_psy->dev.parent,
				&dev_attr_thermal_primary_charge_control_limit_max);

	device_remove_file(battery_psy->dev.parent,
				&dev_attr_thermal_secondary_charge_control_limit);

	device_remove_file(battery_psy->dev.parent,
				&dev_attr_thermal_secondary_charge_control_limit_max);

	thermal_cooling_device_unregister(chg->primary_tcd);
	thermal_cooling_device_unregister(chg->secondary_tcd);
}

static int qti_charger_init(struct qti_charger *chg)
{
	int rc;
	u32 value;
	struct mmi_charger_driver *driver;
	u8 sku_type = 0;
	u16 hw_rev = 0;

	if (chg->driver) {
		mmi_warn(chg, "qti charger has already inited\n");
		return 0;
	}

	value = mmi_is_factory_mode();
	rc = qti_charger_write(chg, OEM_PROP_FACTORY_MODE,
					&value,
					sizeof(value));
	if (rc) {
		mmi_err(chg, "qti charger set factory mode failed, rc=%d\n", rc);
		return rc;
	}
	chg->constraint.factory_mode = value;

	value = mmi_is_factory_version();
	rc = qti_charger_write(chg, OEM_PROP_FACTORY_VERSION,
					&value,
					sizeof(value));
	if (rc) {
		mmi_err(chg, "qti charger set factory ver failed, rc=%d\n", rc);
		return rc;
	}
	chg->constraint.factory_version = value;

	//set SKU type
	if ((rc = mmi_get_sku_type(chg, &sku_type)) == 0) {
		rc = qti_charger_write(chg, OEM_PROP_SKU_TYPE,
						&sku_type,
						sizeof(sku_type));
		if (rc) {
			mmi_err(chg, "qti charger set SKU type failed, rc=%d\n", rc);
		}
	} else {
		mmi_err(chg, "Fail to get sku type\n");
		return rc;
	}
	//set HW revision
	if ((rc = mmi_get_hw_revision(chg, &hw_rev)) == 0) {
		rc = qti_charger_write(chg, OEM_PROP_HW_REVISION,
						&hw_rev,
						sizeof(hw_rev));
		if (rc) {
			mmi_err(chg, "qti charger set HW revision failed, rc=%d\n", rc);
		}
	} else {
		mmi_err(chg, "Fail to get HW revision\n");
		return rc;
	}

	rc = qti_charger_write_profile(chg);
	if (rc) {
		mmi_err(chg, "qti charger set profile data failed, rc=%d\n", rc);
		return rc;
	}

	if (of_property_read_bool(chg->dev->of_node,
				"mmi,main-battery-enabled")) {
		struct power_supply_config psy_cfg = {};
		psy_cfg.drv_data = chg;
		psy_cfg.of_node = chg->dev->of_node;
		chg->batt_psy = devm_power_supply_register(chg->dev,
						&batt_psy_desc,
						&psy_cfg);
		if (IS_ERR(chg->batt_psy)) {
			rc = PTR_ERR(chg->batt_psy);
			chg->batt_psy = NULL;
			mmi_err(chg, "Failed to register main psy, rc=%d\n", rc);
			return rc;
		}
	}
	
	if (chg->mosfet_supported && !chg->constraint.factory_version && mmi_is_softbank_sku(chg)) {
		rc = qti_charger_init_usb_therm_cooler(chg, hw_rev);
		if (rc < 0) {
			mmi_err(chg, "Couldn't initialize usb therm cooler rc=%d.", rc);
			//goto cleanup;
		}
	}

	driver = devm_kzalloc(chg->dev,
				sizeof(struct mmi_charger_driver),
				GFP_KERNEL);
	if (!driver)
		return -ENOMEM;

	/* init driver */
	driver->name = chg->name;
	driver->dev = chg->dev;
	driver->data = chg;
	driver->get_batt_info = qti_charger_get_batt_info;
	driver->get_chg_info = qti_charger_get_chg_info;
	driver->config_charge = qti_charger_config_charge;
	driver->is_charge_tapered = qti_charger_is_charge_tapered;
	driver->is_charge_halt = qti_charger_is_charge_halt;
	driver->set_constraint = qti_charger_set_constraint;
	chg->driver = driver;
	chg->lpd_info.lpd_cid = -1;

	/* register driver to mmi charger */
	rc = mmi_register_charger_driver(driver);
	if (rc) {
		mmi_err(chg, "qti charger init failed, rc=%d\n", rc);
	} else {
		mmi_info(chg, "qti charger init successfully\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_tcmd);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create tcmd\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_force_pmic_icl);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create force_pmic_icl\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_force_wls_en);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create force_wls_en\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_force_usb_suspend);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create force_usb_suspend\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_force_wls_volt_max);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create force_wls_volt_max\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_force_wls_curr_max);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create force_wls_curr_max\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_wireless_chip_id);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create wireless_chip_id\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_addr);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create addr\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_data);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create data\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_wls_fod_curr);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create wls_fod_curr\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_wls_fod_gain);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create wls_fod_gain\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_batt_id);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create batt_id\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_cid_status);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create cid_status\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_typec_reset);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create typec_reset\n");
	}

	rc = device_create_file(chg->dev,
				&dev_attr_fg_operation);
	if (rc) {
		mmi_err(chg,
			   "Couldn't create fg_operation\n");
	}

	bm_ulog_print_mask_log(BM_ALL, BM_LOG_LEVEL_INFO, OEM_BM_ULOG_SIZE);

	wireless_psy_init(chg);
	thermal_charge_control_init(chg);

	create_debugfs_entries(chg);
	trusted_shash_alloc();
	return 0;
}

static void qti_charger_shutdown(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct qti_charger *chg= dev_get_drvdata(dev);

	mmi_info(chg, "qti_charger_shutdown\n");

	return;
}

static void qti_charger_deinit(struct qti_charger *chg)
{
	int rc;

	if (!chg->driver) {
		mmi_info(chg, "qti charger has not inited yet\n");
		return;
	}

	device_remove_file(chg->dev, &dev_attr_fg_operation);
	device_remove_file(chg->dev, &dev_attr_typec_reset);
	device_remove_file(chg->dev, &dev_attr_cid_status);
	device_remove_file(chg->dev, &dev_attr_tcmd);
	device_remove_file(chg->dev, &dev_attr_force_pmic_icl);
	device_remove_file(chg->dev, &dev_attr_force_wls_en);
	device_remove_file(chg->dev, &dev_attr_force_usb_suspend);
	device_remove_file(chg->dev, &dev_attr_force_wls_volt_max);
	device_remove_file(chg->dev, &dev_attr_force_wls_curr_max);
	device_remove_file(chg->dev, &dev_attr_wireless_chip_id);
	device_remove_file(chg->dev, &dev_attr_wls_fod_curr);
	device_remove_file(chg->dev, &dev_attr_wls_fod_gain);
	device_remove_file(chg->dev, &dev_attr_batt_id);
	device_remove_file(chg->dev, &dev_attr_addr);
	device_remove_file(chg->dev, &dev_attr_data);

	wireless_psy_deinit(chg);
	thermal_charge_control_deinit(chg);
	trusted_shash_release();
	if (chg->debug_root)
		debugfs_remove_recursive(chg->debug_root);

	/* unregister driver from mmi charger */
	rc = mmi_unregister_charger_driver(chg->driver);
	if (rc) {
		mmi_err(chg, "qti charger deinit failed, rc=%d\n", rc);
	} else {
		devm_kfree(chg->dev, chg->driver);
		chg->driver = NULL;
	}
}

static void qti_charger_setup_work(struct work_struct *work)
{
	struct qti_charger *chg = container_of(work,
				struct qti_charger, setup_work);
	enum pmic_glink_state state;

	state = atomic_read(&chg->state);
	if (state == PMIC_GLINK_STATE_UP) {
		mmi_info(chg, "ADSP glink state is up\n");
		qti_charger_init(chg);
	} else if (state == PMIC_GLINK_STATE_DOWN) {
		mmi_err(chg, "ADSP glink state is down\n");
		memset(&chg->chg_cfg, 0, sizeof(struct mmi_charger_cfg));
		memset(&chg->constraint, 0, sizeof(struct mmi_charger_constraint));
	}
}

static void qti_charger_notify_work(struct work_struct *work)
{
	unsigned long notification;
	struct qti_charger_notify_data notify_data;
	struct qti_charger *chg = container_of(work,
				struct qti_charger, notify_work);

	notification = chg->notify_msg.notification;
	notify_data.receiver = chg->notify_msg.receiver;
	memcpy(notify_data.data, chg->notify_msg.data,
				sizeof(u32) * MAX_OEM_NOTIFY_DATA_LEN);
	blocking_notifier_call_chain(&qti_chg_notifier_list,
				notification,
				&notify_data);
	pm_relax(chg->dev);
}

static int qti_charger_parse_dt(struct qti_charger *chg)
{
	int rc;
	int i, j;
	int n = 0;
	int bk_num;
	int bk_size;
	char bk_buf[128];
	int byte_len;
	const char *df_sn = NULL, *dev_sn = NULL;
	struct device_node *node;
	int len;
	u32 prev, val;

	node = chg->dev->of_node;
	dev_sn = mmi_get_battery_serialnumber();
	if (!dev_sn) {
		rc = of_property_read_string(node, "mmi,df-serialnum",
						&df_sn);
		if (!rc && df_sn) {
			mmi_info(chg, "Default Serial Number %s\n", df_sn);
		} else {
			mmi_err(chg, "No Default Serial Number defined\n");
			df_sn = BATT_SN_UNKNOWN;
		}
		strcpy(chg->batt_info.batt_sn, df_sn);
	} else {
		strcpy(chg->batt_info.batt_sn, dev_sn);
	}

	chg->profile_info.profile_id = find_profile_id(chg);
	if (chg->profile_info.profile_id < 0)
		chg->profile_info.profile_id = BATT_DEFAULT_ID;

	rc = of_property_read_u32(node, "mmi,chrg-iterm-ma",
				  &chg->profile_info.chrg_iterm);
	if (rc) {
		chg->profile_info.chrg_iterm = 300000;
	} else {
		chg->profile_info.chrg_iterm *= 1000;
	}

	rc = of_property_read_u32(node, "mmi,fg-iterm-ma",
				  &chg->profile_info.fg_iterm);
	if (rc) {
		chg->profile_info.fg_iterm =
			chg->profile_info.chrg_iterm + 50000;
	} else {
		chg->profile_info.fg_iterm *= 1000;
	}

	rc = of_property_read_u32(node, "mmi,vfloat-comp-uv",
				  &chg->profile_info.vfloat_comp_uv);
	if (rc)
		chg->profile_info.vfloat_comp_uv = 0;

	rc = of_property_read_u32(node, "mmi,max-fv-mv",
				  &chg->profile_info.max_fv_uv);
	if (rc)
		chg->profile_info.max_fv_uv = 4400;
	chg->profile_info.max_fv_uv *= 1000;

	rc = of_property_read_u32(node, "mmi,max-fcc-ma",
				  &chg->profile_info.max_fcc_ua);
	if (rc)
		chg->profile_info.max_fcc_ua = 4000;
	chg->profile_info.max_fcc_ua *= 1000;

	rc = of_property_read_u32(node, "mmi,demo-fv-mv",
				  &chg->profile_info.demo_fv_uv);
	if (rc)
		chg->profile_info.demo_fv_uv = 4000;
	chg->profile_info.demo_fv_uv *= 1000;

	rc = of_property_read_u32(node, "mmi,profile-data-block-size",
				  &chg->profile_info.data_bk_size);
	if (rc)
		chg->profile_info.data_bk_size = 4;
	chg->profile_info.data_bk_size *= 4;

	chg->profile_info.data_size = 0;
	if (of_find_property(node, "mmi,profile-data", &byte_len)) {
		if (byte_len % chg->profile_info.data_bk_size) {
			mmi_err(chg, "DT error wrong profile data\n");
			chg->profile_info.data_bk_size = 0;
			return -ENODEV;
		}
		bk_num = byte_len / chg->profile_info.data_bk_size;
		chg->profile_data = (u32 *)devm_kzalloc(chg->dev, byte_len,
							GFP_KERNEL);
		if (chg->profile_data == NULL) {
			chg->profile_info.data_bk_size = 0;
			return -ENOMEM;
		}

		rc = of_property_read_u32_array(node,
				"mmi,profile-data",
				chg->profile_data,
				byte_len / sizeof(u32));
		if (rc < 0) {
			mmi_err(chg, "Couldn't read profile data, rc = %d\n", rc);
			devm_kfree(chg->dev, chg->profile_data);
			chg->profile_data = NULL;
			chg->profile_info.data_bk_size = 0;
			return rc;
		}

		chg->profile_info.data_size = byte_len;
		mmi_info(chg, "profile data: block size: %d, num: %d\n",
				chg->profile_info.data_bk_size, bk_num);
		bk_size = chg->profile_info.data_bk_size / 4;
		for (i = 0; i < bk_num; i++) {
			memset(bk_buf, '\0', sizeof(bk_buf));
			n = sprintf(bk_buf, "block%d:", i);
			for (j = 0; j < bk_size; j++) {
				n += sprintf(bk_buf + n, " %d",
					chg->profile_data[i * bk_size + j]);
			}
			mmi_info(chg, "%s\n", bk_buf);
		}
	}

	rc = of_property_read_u32(node, "mmi,switched-nums",
				  &chg->switched_nums);
	if (rc) {
		chg->switched_nums = 1;
	}

	chg->mosfet_supported = of_property_read_bool(node, "mmi,usb-mosfet-supported");

	rc = of_property_count_elems_of_size(node, "mmi,thermal-primary-mitigation",
							sizeof(u32));
	if (rc <= 0) {
		return 0;
	}

	len = rc;
	prev = chg->profile_info.max_fcc_ua;

	for (i = 0; i < len; i++) {
		rc = of_property_read_u32_index(node,
					"mmi,thermal-primary-mitigation",
					i, &val);
		if (rc < 0) {
			pr_err("failed to get thermal-primary-mitigation[%d], ret=%d\n", i, rc);
			return rc;
		}
		pr_info("thermal-primary-mitigation[%d], val=%d, prev=%d\n", i, val, prev);
		if (val > prev) {
			pr_err("Thermal primary levels should be in descending order\n");
			chg->num_thermal_primary_levels = -EINVAL;
			return 0;
		}
		prev = val;
	}

	chg->thermal_primary_levels = devm_kcalloc(chg->dev, len + 1,
					sizeof(*chg->thermal_primary_levels),
					GFP_KERNEL);
	if (!chg->thermal_primary_levels)
		return -ENOMEM;

	rc = of_property_read_u32_array(node, "mmi,thermal-primary-mitigation",
						&chg->thermal_primary_levels[1], len);
	if (rc < 0) {
		pr_err("Error in reading mmi,thermal-primary-mitigation, rc=%d\n", rc);
		return rc;
	}
	chg->num_thermal_primary_levels = len;
	chg->thermal_primary_fcc_ua = chg->profile_info.max_fcc_ua;
	chg->thermal_primary_levels[0] = chg->thermal_primary_levels[1];

	pr_info("Parse mmi,thermal-primary-mitigation successfully, num_primary_levels %d\n", chg->num_thermal_primary_levels);

	rc = of_property_count_elems_of_size(node, "mmi,thermal-secondary-mitigation",
							sizeof(u32));
	if (rc <= 0) {
		return 0;
	}

	len = rc;
	prev = chg->profile_info.max_fcc_ua;

	for (i = 0; i < len; i++) {
		rc = of_property_read_u32_index(node,
					"mmi,thermal-secondary-mitigation",
					i, &val);
		if (rc < 0) {
			pr_err("failed to get thermal-secondary-mitigation[%d], ret=%d\n", i, rc);
			return rc;
		}
		pr_info("thermal-secondary-mitigation[%d], val=%d, prev=%d\n", i, val, prev);
		if (val > prev) {
			pr_err("Thermal secondary levels should be in descending order\n");
			chg->num_thermal_secondary_levels = -EINVAL;
			return 0;
		}
		prev = val;
	}

	chg->thermal_secondary_levels = devm_kcalloc(chg->dev, len + 1,
					sizeof(*chg->thermal_secondary_levels),
					GFP_KERNEL);
	if (!chg->thermal_secondary_levels)
		return -ENOMEM;

	rc = of_property_read_u32_array(node, "mmi,thermal-secondary-mitigation",
						&chg->thermal_secondary_levels[1], len);
	if (rc < 0) {
		pr_err("Error in reading mmi,thermal-secondary-mitigation, rc=%d\n", rc);
		return rc;
	}
	chg->num_thermal_secondary_levels = len;
	chg->thermal_secondary_fcc_ua = chg->profile_info.max_fcc_ua;
	chg->thermal_secondary_levels[0] = chg->thermal_secondary_levels[1];

	pr_info("Parse mmi,thermal-secondary-mitigation successfully, num_secondary_levels %d\n", chg->num_thermal_secondary_levels);
	return 0;
}

static int qti_charger_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pmic_glink_client_data client_data;
	struct qti_charger *chg;
	int rc;

	chg = devm_kzalloc(dev, sizeof(*chg), GFP_KERNEL);
	if (!chg)
		return -ENOMEM;

	INIT_WORK(&chg->setup_work, qti_charger_setup_work);
	INIT_WORK(&chg->notify_work, qti_charger_notify_work);
	mutex_init(&chg->read_lock);
	mutex_init(&chg->write_lock);
	init_completion(&chg->read_ack);
	init_completion(&chg->write_ack);
	atomic_set(&chg->rx_valid, 0);
	atomic_set(&chg->state, PMIC_GLINK_STATE_UP);
	platform_set_drvdata(pdev, chg);
	chg->dev = dev;
	chg->name = "qti_glink_charger";

	chg->debug_enabled = &debug_enabled;
	chg->ipc_log = ipc_log_context_create(MMI_LOG_PAGES, MMI_LOG_DIR, 0);
	if (!chg->ipc_log)
		mmi_warn(chg, "Error in creating ipc_log_context\n");

	rc = qti_charger_parse_dt(chg);
	if (rc) {
		mmi_err(chg, "dt paser failed, rc=%d\n", rc);
		return rc;
	}

	client_data.id = MSG_OWNER_OEM;
	client_data.name = "oem";
	client_data.msg_cb = oem_callback;
	client_data.priv = chg;
	client_data.state_cb = oem_state_cb;

	chg->client = pmic_glink_register_client(dev, &client_data);
	if (IS_ERR(chg->client)) {
		rc = PTR_ERR(chg->client);
		if (rc != -EPROBE_DEFER)
			mmi_err(chg, "Error in registering with pmic_glink rc=%d\n",
				rc);
		return rc;
	}

	this_chip = chg;
	device_init_wakeup(chg->dev, true);
	qti_charger_init(chg);
	return 0;
}

static int qti_charger_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct qti_charger *chg= dev_get_drvdata(dev);
	int rc;

	qti_charger_deinit(chg);
	rc = pmic_glink_unregister_client(chg->client);
	if (rc < 0)
		mmi_err(chg, "pmic_glink_unregister_client failed rc=%d\n",
			rc);

	return rc;
}

static const struct of_device_id qti_charger_match_table[] = {
	{.compatible = "mmi,qti-glink-charger"},
	{},
};

static struct platform_driver qti_charger_driver = {
	.driver	= {
		.name = "qti_glink_charger",
		.of_match_table = qti_charger_match_table,
	},
	.probe	= qti_charger_probe,
	.remove	= qti_charger_remove,
	.shutdown = qti_charger_shutdown,
};

module_platform_driver(qti_charger_driver);

MODULE_DESCRIPTION("QTI Glink Charger Driver");
MODULE_LICENSE("GPL v2");
