// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/firmware.h>

#include "cam_sensor_cmn_header.h"
#include "cam_ois_core.h"
#include "cam_ois_soc.h"
#include "cam_sensor_util.h"
#include "cam_debug_util.h"
#include "cam_res_mgr_api.h"
#include "cam_common_util.h"
#include "cam_packet_util.h"

#define OIS_COEF_CHUNK_SIZE (256)
#define DW9784_IF_SIZE (512)

extern int dw9781c_check_fw_download(struct camera_io_master * io_master_info, const uint8_t *fwData, uint32_t fwSize);
extern void dw9781_post_firmware_download(struct camera_io_master * io_master_info, const uint8_t *fwData, uint32_t fwSize);
extern int dw9784_check_fw_download(struct camera_io_master * io_master_info, const uint8_t *fwData, uint32_t fwSize);
extern void dw9784_post_firmware_download(struct camera_io_master * io_master_info);
extern int dw9784_check_if_download(struct camera_io_master * io_master_info);

#ifdef CONFIG_MOT_OIS_SEM1217S_DRIVER
extern int32_t sem1217s_fw_update(struct cam_ois_ctrl_t *o_ctrl, const struct firmware *fw);
#endif

#ifdef CONFIG_MOT_DONGWOON_OIS_AF_DRIFT
int m_ois_init = 0;

int cam_ois_get_init_info(void)
{
	return m_ois_init;
}

static void cam_ois_set_init_info(int value)
{
	m_ois_init = value;
}
#endif

#if defined(CONFIG_MOT_OIS_SEM1217S_DRIVER) || defined(CONFIG_MOT_OIS_DW9784_DRIVER)
int g_ois_init_finished = 0;
#endif

int32_t cam_ois_construct_default_power_setting(
	struct cam_sensor_power_ctrl_t *power_info)
{
	int rc = 0;

	power_info->power_setting_size = 1;
	power_info->power_setting =
		kzalloc(sizeof(struct cam_sensor_power_setting),
			GFP_KERNEL);
	if (!power_info->power_setting)
		return -ENOMEM;

	power_info->power_setting[0].seq_type = SENSOR_VAF;
	power_info->power_setting[0].seq_val = CAM_VAF;
	power_info->power_setting[0].config_val = 1;
	power_info->power_setting[0].delay = 2;

	power_info->power_down_setting_size = 1;
	power_info->power_down_setting =
		kzalloc(sizeof(struct cam_sensor_power_setting),
			GFP_KERNEL);
	if (!power_info->power_down_setting) {
		rc = -ENOMEM;
		goto free_power_settings;
	}

	power_info->power_down_setting[0].seq_type = SENSOR_VAF;
	power_info->power_down_setting[0].seq_val = CAM_VAF;
	power_info->power_down_setting[0].config_val = 0;

	return rc;

free_power_settings:
	kfree(power_info->power_setting);
	power_info->power_setting = NULL;
	power_info->power_setting_size = 0;
	return rc;
}


/**
 * cam_ois_get_dev_handle - get device handle
 * @o_ctrl:     ctrl structure
 * @arg:        Camera control command argument
 *
 * Returns success or failure
 */
static int cam_ois_get_dev_handle(struct cam_ois_ctrl_t *o_ctrl,
	void *arg)
{
	struct cam_sensor_acquire_dev    ois_acq_dev;
	struct cam_create_dev_hdl        bridge_params;
	struct cam_control              *cmd = (struct cam_control *)arg;

	if (o_ctrl->bridge_intf.device_hdl != -1) {
		CAM_ERR(CAM_OIS, "Device is already acquired");
		return -EFAULT;
	}
	if (copy_from_user(&ois_acq_dev, u64_to_user_ptr(cmd->handle),
		sizeof(ois_acq_dev)))
		return -EFAULT;

	bridge_params.session_hdl = ois_acq_dev.session_handle;
	bridge_params.ops = &o_ctrl->bridge_intf.ops;
	bridge_params.v4l2_sub_dev_flag = 0;
	bridge_params.media_entity_flag = 0;
	bridge_params.priv = o_ctrl;
	bridge_params.dev_id = CAM_OIS;

	ois_acq_dev.device_handle =
		cam_create_device_hdl(&bridge_params);
	if (ois_acq_dev.device_handle <= 0) {
		CAM_ERR(CAM_OIS, "Can not create device handle");
		return -EFAULT;
	}
	o_ctrl->bridge_intf.device_hdl = ois_acq_dev.device_handle;
	o_ctrl->bridge_intf.session_hdl = ois_acq_dev.session_handle;

	CAM_DBG(CAM_OIS, "Device Handle: %d", ois_acq_dev.device_handle);
	if (copy_to_user(u64_to_user_ptr(cmd->handle), &ois_acq_dev,
		sizeof(struct cam_sensor_acquire_dev))) {
		CAM_ERR(CAM_OIS, "ACQUIRE_DEV: copy to user failed");
		return -EFAULT;
	}
	return 0;
}

static int cam_ois_power_up(struct cam_ois_ctrl_t *o_ctrl)
{
	int                                     rc = 0;
	struct cam_hw_soc_info                 *soc_info = &o_ctrl->soc_info;
	struct cam_ois_soc_private             *soc_private;
	struct cam_sensor_power_ctrl_t         *power_info;
	struct completion                      *i3c_probe_completion = NULL;

	soc_private = (struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;

#ifdef CONFIG_DONGWOON_OIS_VSYNC
	o_ctrl->prev_timestamp = 0;
	o_ctrl->curr_timestamp = 0;
	o_ctrl->is_first_vsync = 1;
	o_ctrl->is_video_mode  = false;
	o_ctrl->is_need_eis_data  = false;
#endif

	power_info = &soc_private->power_info;

	if ((power_info->power_setting == NULL) &&
		(power_info->power_down_setting == NULL)) {
		CAM_INFO(CAM_OIS,
			"Using default power settings");
		rc = cam_ois_construct_default_power_setting(power_info);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Construct default ois power setting failed.");
			return rc;
		}
	}

	/* Parse and fill vreg params for power up settings */
	rc = msm_camera_fill_vreg_params(
		soc_info,
		power_info->power_setting,
		power_info->power_setting_size);
	if (rc) {
		CAM_ERR(CAM_OIS,
			"failed to fill vreg params for power up rc:%d", rc);
		return rc;
	}

	/* Parse and fill vreg params for power down settings*/
	rc = msm_camera_fill_vreg_params(
		soc_info,
		power_info->power_down_setting,
		power_info->power_down_setting_size);
	if (rc) {
		CAM_ERR(CAM_OIS,
			"failed to fill vreg params for power down rc:%d", rc);
		return rc;
	}

	power_info->dev = soc_info->dev;

	if (o_ctrl->io_master_info.master_type == I3C_MASTER)
		i3c_probe_completion = cam_ois_get_i3c_completion(o_ctrl->soc_info.index);

	rc = cam_sensor_core_power_up(power_info, soc_info, i3c_probe_completion);
	if (rc) {
		CAM_ERR(CAM_OIS, "failed in ois power up rc %d", rc);
		return rc;
	}

	CAM_INFO(CAM_OIS, "OIS Power up successfully");

	rc = camera_io_init(&o_ctrl->io_master_info);
	if (rc) {
		CAM_ERR(CAM_OIS, "cci_init failed: rc: %d", rc);
		goto cci_failure;
	}

	return rc;
cci_failure:
	if (cam_sensor_util_power_down(power_info, soc_info))
		CAM_ERR(CAM_OIS, "Power Down failed");

	return rc;
}

/**
 * cam_ois_power_down - power down OIS device
 * @o_ctrl:     ctrl structure
 *
 * Returns success or failure
 */
static int cam_ois_power_down(struct cam_ois_ctrl_t *o_ctrl)
{
	int32_t                         rc = 0;
	struct cam_sensor_power_ctrl_t  *power_info;
	struct cam_hw_soc_info          *soc_info =
		&o_ctrl->soc_info;
	struct cam_ois_soc_private *soc_private;

	if (!o_ctrl) {
		CAM_ERR(CAM_OIS, "failed: o_ctrl %pK", o_ctrl);
		return -EINVAL;
	}

	soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	power_info = &soc_private->power_info;
	soc_info = &o_ctrl->soc_info;

	if (!power_info) {
		CAM_ERR(CAM_OIS, "failed: power_info %pK", power_info);
		return -EINVAL;
	}

	rc = cam_sensor_util_power_down(power_info, soc_info);
	if (rc) {
		CAM_ERR(CAM_OIS, "power down the core is failed:%d", rc);
		return rc;
	}

	CAM_INFO(CAM_OIS, "OIS power down successed");

#ifdef CONFIG_MOT_DONGWOON_OIS_AF_DRIFT
	if (o_ctrl->af_drift_supported == true) {
		cam_ois_set_init_info(0);
	}
#endif

#if defined(CONFIG_MOT_OIS_SEM1217S_DRIVER) || defined(CONFIG_MOT_OIS_DW9784_DRIVER)
	if (o_ctrl->af_ois_use_same_ic == true) {
		g_ois_init_finished = 0;
	}
#endif

	camera_io_release(&o_ctrl->io_master_info);
	o_ctrl->cam_ois_state = CAM_OIS_ACQUIRE;

	return rc;
}

static int cam_ois_update_time(struct i2c_settings_array *i2c_set)
{
	struct i2c_settings_list *i2c_list;
	int32_t rc = 0;
	uint32_t size = 0;
	uint32_t i = 0;
	uint64_t qtime_ns = 0;

	if (i2c_set == NULL) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	rc = cam_sensor_util_get_current_qtimer_ns(&qtime_ns);
	if (rc < 0) {
		CAM_ERR(CAM_OIS,
			"Failed to get current qtimer value: %d",
			rc);
		return rc;
	}

	list_for_each_entry(i2c_list,
		&(i2c_set->list_head), list) {
		if (i2c_list->op_code ==  CAM_SENSOR_I2C_WRITE_SEQ) {
			size = i2c_list->i2c_settings.size;
#ifdef CONFIG_MOT_OIS_DW9784_DRIVER
			if (size * (uint32_t)(i2c_list->i2c_settings.data_type) != 8) {
				CAM_ERR(CAM_OIS, "Invalid write time settings");
				return -EINVAL;
			}
			switch (i2c_list->i2c_settings.data_type) {
			case CAMERA_SENSOR_I2C_TYPE_BYTE:
				for (i = 0; i < size; i++) {
					CAM_DBG(CAM_OIS, "time: reg_data[%d]: 0x%x",
						i, (qtime_ns & 0xFF));
					i2c_list->i2c_settings.reg_setting[i].reg_data =
						(qtime_ns & 0xFF);
					qtime_ns >>= 8;
				}

				break;
			case CAMERA_SENSOR_I2C_TYPE_WORD:
				for (i = 0; i < size; i++) {
					uint16_t  data = (qtime_ns & 0xFFFF);

					i2c_list->i2c_settings.reg_setting[size-i-1].reg_data =
						data;

					qtime_ns >>= 16;

					CAM_DBG(CAM_OIS, "time: reg_data[%d]: 0x%x",
							size-i-1, data);
				}

				break;
			default:
				CAM_ERR(CAM_OIS, "Unsupported reg data type");
				return -EINVAL;
			}
#else
			/* qtimer is 8 bytes so validate here*/
			if (size < 8) {
				CAM_ERR(CAM_OIS, "Invalid write time settings");
				return -EINVAL;
			}
			for (i = 0; i < size; i++) {
				CAM_DBG(CAM_OIS, "time: reg_data[%d]: 0x%x",
					i, (qtime_ns & 0xFF));
				i2c_list->i2c_settings.reg_setting[i].reg_data =
					(qtime_ns & 0xFF);
				qtime_ns >>= 8;
			}
#endif

		}
	}

	return rc;
}

static int cam_ois_apply_settings(struct cam_ois_ctrl_t *o_ctrl,
	struct i2c_settings_array *i2c_set)
{
	struct i2c_settings_list *i2c_list;
	int32_t rc = 0;
	uint32_t i, size;

	if (o_ctrl == NULL || i2c_set == NULL) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	if (i2c_set->is_settings_valid != 1) {
		CAM_ERR(CAM_OIS, " Invalid settings");
		return -EINVAL;
	}

	list_for_each_entry(i2c_list,
		&(i2c_set->list_head), list) {
		if (i2c_list->op_code ==  CAM_SENSOR_I2C_WRITE_RANDOM) {
			rc = camera_io_dev_write(&(o_ctrl->io_master_info),
				&(i2c_list->i2c_settings));
			if (rc < 0) {
				CAM_ERR(CAM_OIS,
					"Failed in Applying i2c wrt settings");
				return rc;
			}
#ifdef CONFIG_DONGWOON_OIS_VSYNC
			if (strstr(o_ctrl->ois_name, "dw9784")) {
				if (i2c_list->i2c_settings.reg_setting[0].reg_addr == 0x7013 &&
					i2c_list->i2c_settings.reg_setting[0].reg_data == 0x8001) /*0x7013=0x8001 means movie mode*/
					o_ctrl->is_video_mode = true;
				else if (i2c_list->i2c_settings.reg_setting[0].reg_addr == 0x7013 &&
					i2c_list->i2c_settings.reg_setting[0].reg_data == 0x8000) /*0x7013=0x8000 means still mode*/
					o_ctrl->is_video_mode = false;
			}
#endif
		} else if (i2c_list->op_code == CAM_SENSOR_I2C_WRITE_SEQ) {
			rc = camera_io_dev_write_continuous(
				&(o_ctrl->io_master_info),
				&(i2c_list->i2c_settings),
				CAM_SENSOR_I2C_WRITE_SEQ);
			if (rc < 0) {
				CAM_ERR(CAM_OIS,
					"Failed to seq write I2C settings: %d",
					rc);
				return rc;
			}
		} else if (i2c_list->op_code == CAM_SENSOR_I2C_POLL) {
			size = i2c_list->i2c_settings.size;
			for (i = 0; i < size; i++) {
				rc = camera_io_dev_poll(
				&(o_ctrl->io_master_info),
				i2c_list->i2c_settings.reg_setting[i].reg_addr,
				i2c_list->i2c_settings.reg_setting[i].reg_data,
				i2c_list->i2c_settings.reg_setting[i].data_mask,
				i2c_list->i2c_settings.addr_type,
				i2c_list->i2c_settings.data_type,
				i2c_list->i2c_settings.reg_setting[i].delay);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
						"i2c poll apply setting Fail");
					return rc;
				}
			}
		}
	}

	return rc;
}

static int cam_ois_slaveInfo_pkt_parser(struct cam_ois_ctrl_t *o_ctrl,
	uint32_t *cmd_buf, size_t len)
{
	int32_t rc = 0;
	struct cam_cmd_ois_info *ois_info;

	if (!o_ctrl || !cmd_buf || len < sizeof(struct cam_cmd_ois_info)) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	ois_info = (struct cam_cmd_ois_info *)cmd_buf;
	if (o_ctrl->io_master_info.master_type == CCI_MASTER) {
		o_ctrl->io_master_info.cci_client->i2c_freq_mode =
			ois_info->i2c_freq_mode;
		o_ctrl->io_master_info.cci_client->sid =
			ois_info->slave_addr >> 1;
		o_ctrl->ois_fw_flag = ois_info->ois_fw_flag;
#ifdef CONFIG_MOT_OIS_EARLY_UPGRADE_FW
		o_ctrl->ois_early_fw_flag = ois_info->ois_early_fw_flag;
#endif
		o_ctrl->ois_preprog_flag = ois_info->ois_preprog_flag;
		o_ctrl->ois_precoeff_flag = ois_info->ois_precoeff_flag;
		o_ctrl->is_ois_calib = ois_info->is_ois_calib;
		o_ctrl->ois_postcalib_flag = ois_info->ois_postcalib_flag;
		o_ctrl->ois_fw_txn_data_sz = ois_info->ois_fw_txn_data_sz;
		o_ctrl->ois_fw_inc_addr = ois_info->ois_fw_inc_addr;
		o_ctrl->ois_fw_addr_type = ois_info->ois_fw_addr_type;
		o_ctrl->ois_fw_data_type = ois_info->ois_fw_data_type;
		memcpy(o_ctrl->ois_name, ois_info->ois_name, OIS_NAME_LEN);
		o_ctrl->ois_name[OIS_NAME_LEN - 1] = '\0';
		o_ctrl->io_master_info.cci_client->retries = 3;
		o_ctrl->io_master_info.cci_client->id_map = 0;
		memcpy(&(o_ctrl->opcode), &(ois_info->opcode),
			sizeof(struct cam_ois_opcode));
		CAM_DBG(CAM_OIS, "Slave addr: 0x%x Freq Mode: %d",
			ois_info->slave_addr, ois_info->i2c_freq_mode);
	} else if (o_ctrl->io_master_info.master_type == I2C_MASTER) {
		o_ctrl->io_master_info.client->addr = ois_info->slave_addr;
		CAM_DBG(CAM_OIS, "Slave addr: 0x%x", ois_info->slave_addr);
	} else {
		CAM_ERR(CAM_OIS, "Invalid Master type : %d",
			o_ctrl->io_master_info.master_type);
		rc = -EINVAL;
	}

	return rc;
}

static int cam_ois_fw_prog_download(struct cam_ois_ctrl_t *o_ctrl)
{
	uint16_t                           total_bytes = 0;
	uint8_t                           *ptr = NULL;
	int32_t                            rc = 0, total_idx, packet_idx;
	uint32_t                           txn_data_size, txn_regsetting_size;
	const struct firmware             *fw = NULL;
	const char                        *fw_name_prog = NULL;
	char                               name_prog[32] = {0};
	struct device                     *dev = &(o_ctrl->pdev->dev);
	struct cam_sensor_i2c_reg_setting  i2c_reg_setting;
	void                              *vaddr = NULL;
#ifdef CONFIG_MOT_OIS_SEM1217S_DRIVER
	int i = 0;
#endif

	if (!o_ctrl) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	snprintf(name_prog, 32, "%s.prog", o_ctrl->ois_name);

	/* cast pointer as const pointer*/
	fw_name_prog = name_prog;

	/* Load FW */
	rc = request_firmware(&fw, fw_name_prog, dev);
	if (rc) {
		CAM_ERR(CAM_OIS, "Failed to locate %s", fw_name_prog);
		return rc;
	}

	if (strstr(o_ctrl->ois_name, "dw9781")) {
		if (!dw9781c_check_fw_download(&(o_ctrl->io_master_info), fw->data, fw->size)) {
			CAM_INFO(CAM_OIS, "Skip firmware download.");
			release_firmware(fw);
			return 0;
		}
		CAM_INFO(CAM_OIS, "Firmware download started.");
	}else if (strstr(o_ctrl->ois_name, "dw9784")) {
		if (!dw9784_check_fw_download(&(o_ctrl->io_master_info), fw->data, fw->size)) {
			CAM_INFO(CAM_OIS, "Skip firmware download.");
			release_firmware(fw);
			return 0;
		}
		CAM_INFO(CAM_OIS, "Firmware download started.");
	}

#ifdef CONFIG_MOT_OIS_SEM1217S_DRIVER
	if (strstr(o_ctrl->ois_name, "sem1217")) {
		mutex_lock(&o_ctrl->sem1217s_mutex);
		for (i = 0; i < 3; i++) {
			rc = sem1217s_fw_update(o_ctrl, fw);
			if (rc == 0) {
				CAM_INFO(CAM_OIS, "FW upgrade checked success");
				break;
			}
			CAM_WARN(CAM_OIS, "FW upgrade checked try again, i %d, rc %d", i, rc);
		}

		if (rc != 0) {
			CAM_ERR(CAM_OIS, "FW upgrade checked failed");
		}

		release_firmware(fw);
		mutex_unlock(&o_ctrl->sem1217s_mutex);
		return rc;
	}
#endif

	total_bytes = fw->size;
	if(o_ctrl->ois_fw_txn_data_sz == 0)
		txn_data_size = 256;
	else
		txn_data_size = o_ctrl->ois_fw_txn_data_sz;

	i2c_reg_setting.addr_type = o_ctrl->ois_fw_addr_type;
	i2c_reg_setting.data_type = o_ctrl->ois_fw_data_type;
	i2c_reg_setting.delay = 0;
	txn_regsetting_size = sizeof(struct cam_sensor_i2c_reg_array) * txn_data_size;
	vaddr = vmalloc(txn_regsetting_size);
	if (!vaddr) {
		CAM_ERR(CAM_OIS, "Failed in allocating i2c_array");
		release_firmware(fw);
		return -ENOMEM;
	}

	CAM_DBG(CAM_OIS, "FW prog size:%d.", total_bytes);
	CAM_DBG(CAM_OIS, "fw len: %d, addr_type: %d, data_type: %d, chunck: %d, ois_fw_data_type:%d", total_bytes,
	                 i2c_reg_setting.addr_type,
	                 i2c_reg_setting.data_type,
	                 txn_data_size,
	                 o_ctrl->ois_fw_data_type);

	i2c_reg_setting.reg_setting = (struct cam_sensor_i2c_reg_array *) (
		vaddr);

	for (total_idx = 0, ptr = (uint8_t *)fw->data; total_idx < total_bytes;) {
		for (packet_idx = 0;
			(packet_idx < (txn_data_size/o_ctrl->ois_fw_data_type)) && (total_idx + (packet_idx*o_ctrl->ois_fw_data_type) < total_bytes);
			packet_idx ++, ptr += o_ctrl->ois_fw_data_type)
		{
			int regAddrOffset = 0;
			if(o_ctrl->ois_fw_inc_addr == 1)
				regAddrOffset = total_idx/o_ctrl->ois_fw_data_type + packet_idx;
			if (strstr(o_ctrl->ois_name, "dw9784") && total_idx >= total_bytes - DW9784_IF_SIZE) {
				i2c_reg_setting.reg_setting[packet_idx].reg_addr = o_ctrl->opcode.prog + regAddrOffset - (total_bytes - DW9784_IF_SIZE)/2;
				i2c_reg_setting.reg_setting[packet_idx].reg_data = (uint32_t)(*ptr << 8) | *(ptr+1);
				i2c_reg_setting.reg_setting[packet_idx].delay = 0;
				i2c_reg_setting.reg_setting[packet_idx].data_mask = 0;
				CAM_DBG(CAM_OIS, "IF OIS_FW Reg:[0x%04x]: 0x%04x P:0x%x",
				    i2c_reg_setting.reg_setting[packet_idx].reg_addr,
				    i2c_reg_setting.reg_setting[packet_idx].reg_data,
				    (ptr-(uint8_t *)fw->data));
			} else {
				i2c_reg_setting.reg_setting[packet_idx].reg_addr =
					o_ctrl->opcode.prog + regAddrOffset;
				if (o_ctrl->ois_fw_data_type == CAMERA_SENSOR_I2C_TYPE_WORD) {
					i2c_reg_setting.reg_setting[packet_idx].reg_data = (uint32_t)(*ptr << 8) | *(ptr+1);
				} else {
					i2c_reg_setting.reg_setting[packet_idx].reg_data = *ptr;
				}
				i2c_reg_setting.reg_setting[packet_idx].delay = 0;
				i2c_reg_setting.reg_setting[packet_idx].data_mask = 0;
				CAM_DBG(CAM_OIS, "OIS_FW Reg:[0x%04x]: 0x%04x P:0x%x",
				    i2c_reg_setting.reg_setting[packet_idx].reg_addr,
				    i2c_reg_setting.reg_setting[packet_idx].reg_data,
				    (ptr-(uint8_t *)fw->data));
			}
		}
		i2c_reg_setting.size = packet_idx;
		if (o_ctrl->ois_fw_inc_addr == 1) {
			if (strstr(o_ctrl->ois_name, "dw9784") && total_idx == total_bytes - DW9784_IF_SIZE){
				rc = dw9784_check_if_download(&(o_ctrl->io_master_info));
				if (rc < 0) {
					CAM_ERR(CAM_OIS, "dw9784 check if download fail");
					goto release_firmware;
				}
			}
			rc = camera_io_dev_write_continuous(&(o_ctrl->io_master_info),
				&i2c_reg_setting, CAM_SENSOR_I2C_WRITE_SEQ);
		} else {
			rc = camera_io_dev_write_continuous(&(o_ctrl->io_master_info),
				&i2c_reg_setting, CAM_SENSOR_I2C_WRITE_BURST);
		}
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS FW(prog) size(%d) download failed. %d",
				total_bytes, rc);
			goto release_firmware;
		}
		total_idx += packet_idx*o_ctrl->ois_fw_data_type;
		CAM_DBG(CAM_OIS, "packet_idx: %d, total_idx: %d", packet_idx, total_idx);
	}

	if (strstr(o_ctrl->ois_name, "dw9781")) {
		dw9781_post_firmware_download(&(o_ctrl->io_master_info), fw->data, fw->size);
	} else if (strstr(o_ctrl->ois_name, "dw9784")) {
		dw9784_post_firmware_download(&(o_ctrl->io_master_info));
	}

release_firmware:
	vfree(vaddr);
	vaddr = NULL;
	txn_regsetting_size = 0;
	release_firmware(fw);

	return rc;
}

static int cam_ois_fw_coeff_download(struct cam_ois_ctrl_t *o_ctrl)
{
	uint16_t                           total_bytes = 0;
	uint8_t                           *ptr = NULL;
	int32_t                            rc = 0, total_idx, packet_idx;
	uint32_t                           txn_data_size, txn_regsetting_size;
	const struct firmware             *fw = NULL;
	const char                        *fw_name_coeff = NULL;
	char                               name_coeff[32] = {0};
	struct device                     *dev = &(o_ctrl->pdev->dev);
	struct cam_sensor_i2c_reg_setting  i2c_reg_setting;
	void                              *vaddr = NULL;

	if (!o_ctrl) {
		CAM_ERR(CAM_OIS, "Invalid Args");
		return -EINVAL;
	}

	if (strstr(o_ctrl->ois_name, "dw9781") || strstr(o_ctrl->ois_name, "dw9784")) {
		CAM_DBG(CAM_OIS, "not need download coeff fw!");
		return 0;
	}

#ifdef CONFIG_MOT_OIS_SEM1217S_DRIVER
	if (strstr(o_ctrl->ois_name, "sem1217")) {
		CAM_DBG(CAM_OIS, "not need download coeff fw for %s.", o_ctrl->ois_name);
		return 0;
	}
#endif

	snprintf(name_coeff, 32, "%s.coeff", o_ctrl->ois_name);
	fw_name_coeff = name_coeff;

	rc = request_firmware(&fw, fw_name_coeff, dev);
	if (rc) {
		CAM_ERR(CAM_OIS, "Failed to locate %s", fw_name_coeff);
		return rc;
	}

	total_bytes = fw->size;
	if(o_ctrl->ois_fw_txn_data_sz == 0)
		txn_data_size = OIS_COEF_CHUNK_SIZE;
	else
		txn_data_size = o_ctrl->ois_fw_txn_data_sz;

	i2c_reg_setting.addr_type = o_ctrl->ois_fw_addr_type;
	i2c_reg_setting.data_type = o_ctrl->ois_fw_data_type;
	i2c_reg_setting.delay = 0;
	txn_regsetting_size = sizeof(struct cam_sensor_i2c_reg_array) * txn_data_size;
	vaddr = vmalloc(txn_regsetting_size);
	if (!vaddr) {
		CAM_ERR(CAM_OIS, "Failed in allocating i2c_array");
		release_firmware(fw);
		return -ENOMEM;
	}

	CAM_DBG(CAM_OIS, "FW coeff size:%d", total_bytes);
	CAM_DBG(CAM_OIS, "Coeff size:%d, chunk:%d addr_inc:%d, addr_type:%d, data_type:%d",
	                 txn_regsetting_size, txn_data_size, o_ctrl->ois_fw_inc_addr,
	                 o_ctrl->ois_fw_addr_type, o_ctrl->ois_fw_data_type);

	i2c_reg_setting.reg_setting = (struct cam_sensor_i2c_reg_array *) (
		vaddr);

	for (total_idx = 0, ptr = (uint8_t *)fw->data; total_idx < total_bytes;) {
		for(packet_idx = 0;
			(packet_idx < txn_data_size) && (total_idx + packet_idx < total_bytes);
			packet_idx++, ptr++)
		{
			int regAddrOffset = 0;
			if(o_ctrl->ois_fw_inc_addr == 1)
				regAddrOffset = total_idx + packet_idx;

			i2c_reg_setting.reg_setting[packet_idx].reg_addr =
				o_ctrl->opcode.coeff + regAddrOffset;
			i2c_reg_setting.reg_setting[packet_idx].reg_data = *ptr;
			i2c_reg_setting.reg_setting[packet_idx].delay = 0;
			i2c_reg_setting.reg_setting[packet_idx].data_mask = 0;
		}
		i2c_reg_setting.size = packet_idx;
		rc = camera_io_dev_write_continuous(&(o_ctrl->io_master_info),
			&i2c_reg_setting, CAM_SENSOR_I2C_WRITE_BURST);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS FW(coeff) size(%d) download failed rc: %d",
				total_bytes, rc);
			goto release_firmware;
		}
		total_idx += packet_idx;
	}
	CAM_DBG(CAM_OIS, "FW coeff download done");

release_firmware:
	vfree(vaddr);
	vaddr = NULL;
	txn_regsetting_size = 0;
	release_firmware(fw);

	return rc;
}

/**
 * cam_ois_pkt_parse - Parse csl packet
 * @o_ctrl:     ctrl structure
 * @arg:        Camera control command argument
 *
 * Returns success or failure
 */
static int cam_ois_pkt_parse(struct cam_ois_ctrl_t *o_ctrl, void *arg)
{
	int32_t                         rc = 0;
	int32_t                         i = 0;
	uint32_t                        total_cmd_buf_in_bytes = 0;
	struct common_header           *cmm_hdr = NULL;
	uintptr_t                       generic_ptr;
	struct cam_control             *ioctl_ctrl = NULL;
	struct cam_config_dev_cmd       dev_config;
	struct i2c_settings_array      *i2c_reg_settings = NULL;
	struct cam_cmd_buf_desc        *cmd_desc = NULL;
	uintptr_t                       generic_pkt_addr;
	size_t                          pkt_len;
	size_t                          remain_len = 0;
	struct cam_packet              *csl_packet = NULL;
	size_t                          len_of_buff = 0;
	uint32_t                       *offset = NULL, *cmd_buf;
	struct cam_ois_soc_private     *soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	struct cam_sensor_power_ctrl_t  *power_info = &soc_private->power_info;

	ioctl_ctrl = (struct cam_control *)arg;
	if (copy_from_user(&dev_config,
		u64_to_user_ptr(ioctl_ctrl->handle),
		sizeof(dev_config)))
		return -EFAULT;
	rc = cam_mem_get_cpu_buf(dev_config.packet_handle,
		&generic_pkt_addr, &pkt_len);
	if (rc) {
		CAM_ERR(CAM_OIS,
			"error in converting command Handle Error: %d", rc);
		return rc;
	}

	remain_len = pkt_len;
	if ((sizeof(struct cam_packet) > pkt_len) ||
		((size_t)dev_config.offset >= pkt_len -
		sizeof(struct cam_packet))) {
		CAM_ERR(CAM_OIS,
			"Inval cam_packet strut size: %zu, len_of_buff: %zu",
			 sizeof(struct cam_packet), pkt_len);
		cam_mem_put_cpu_buf(dev_config.packet_handle);
		return -EINVAL;
	}

	remain_len -= (size_t)dev_config.offset;
	csl_packet = (struct cam_packet *)
		(generic_pkt_addr + (uint32_t)dev_config.offset);

	if (cam_packet_util_validate_packet(csl_packet,
		remain_len)) {
		CAM_ERR(CAM_OIS, "Invalid packet params");
		cam_mem_put_cpu_buf(dev_config.packet_handle);
		return -EINVAL;
	}

	switch (csl_packet->header.op_code & 0xFFFFFF) {
	case CAM_OIS_PACKET_OPCODE_INIT:
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);

		CAM_DBG(CAM_OIS, "num_cmd_buf %d",
			csl_packet->num_cmd_buf);

		/* Loop through multiple command buffers */
		for (i = 0; i < csl_packet->num_cmd_buf; i++) {
			total_cmd_buf_in_bytes = cmd_desc[i].length;
			if (!total_cmd_buf_in_bytes)
				continue;

			rc = cam_mem_get_cpu_buf(cmd_desc[i].mem_handle,
				&generic_ptr, &len_of_buff);
			if (rc < 0) {
				CAM_ERR(CAM_OIS, "Failed to get cpu buf : 0x%x",
					cmd_desc[i].mem_handle);
				cam_mem_put_cpu_buf(dev_config.packet_handle);
				return rc;
			}
			cmd_buf = (uint32_t *)generic_ptr;
			if (!cmd_buf) {
				CAM_ERR(CAM_OIS, "invalid cmd buf");
				cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
				cam_mem_put_cpu_buf(dev_config.packet_handle);
				return -EINVAL;
			}

			if ((len_of_buff < sizeof(struct common_header)) ||
				(cmd_desc[i].offset > (len_of_buff -
				sizeof(struct common_header)))) {
				CAM_ERR(CAM_OIS,
					"Invalid length for sensor cmd");
				cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
				cam_mem_put_cpu_buf(dev_config.packet_handle);
				return -EINVAL;
			}
			remain_len = len_of_buff - cmd_desc[i].offset;
			cmd_buf += cmd_desc[i].offset / sizeof(uint32_t);
			cmm_hdr = (struct common_header *)cmd_buf;

			switch (cmm_hdr->cmd_type) {
			case CAMERA_SENSOR_CMD_TYPE_I2C_INFO:
				rc = cam_ois_slaveInfo_pkt_parser(
					o_ctrl, cmd_buf, remain_len);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"Failed in parsing slave info");
					cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
					cam_mem_put_cpu_buf(dev_config.packet_handle);
					return rc;
				}
				break;
			case CAMERA_SENSOR_CMD_TYPE_PWR_UP:
			case CAMERA_SENSOR_CMD_TYPE_PWR_DOWN:
				CAM_DBG(CAM_OIS,
					"Received power settings buffer");
				rc = cam_sensor_update_power_settings(
					cmd_buf,
					total_cmd_buf_in_bytes,
					power_info, remain_len);
				if (rc) {
					CAM_ERR(CAM_OIS,
					"Failed: parse power settings");
					cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
					cam_mem_put_cpu_buf(dev_config.packet_handle);
					return rc;
				}
				break;
			default:
			if (o_ctrl->i2c_init_data.is_settings_valid == 0) {
				CAM_DBG(CAM_OIS,
				"Received init/config settings");
				i2c_reg_settings =
					&(o_ctrl->i2c_init_data);
				i2c_reg_settings->is_settings_valid = 1;
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					&o_ctrl->io_master_info,
					i2c_reg_settings,
					&cmd_desc[i], 1, NULL);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"init parsing failed: %d", rc);
					cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
					cam_mem_put_cpu_buf(dev_config.packet_handle);
					return rc;
				}
			} else if (((o_ctrl->ois_preprog_flag) != 0) &&
				o_ctrl->i2c_preprog_data.is_settings_valid == 0) {
				CAM_DBG(CAM_OIS, "Received PreProg Settings");
				i2c_reg_settings = &(o_ctrl->i2c_preprog_data);
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					&o_ctrl->io_master_info,
					i2c_reg_settings,
					&cmd_desc[i], 1, NULL);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"preprog parsing failed: %d", rc);
					return rc;
				}
			} else if (((o_ctrl->ois_precoeff_flag) != 0) &&
				o_ctrl->i2c_precoeff_data.is_settings_valid == 0) {
				CAM_DBG(CAM_OIS, "Received PreCoeff Settings");
				i2c_reg_settings = &(o_ctrl->i2c_precoeff_data);
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					&o_ctrl->io_master_info,
					i2c_reg_settings,
					&cmd_desc[i], 1, NULL);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"precoeff parsing failed: %d", rc);
					return rc;
				}
			} else if ((o_ctrl->is_ois_calib != 0) &&
				(o_ctrl->i2c_calib_data.is_settings_valid ==
				0)) {
				CAM_DBG(CAM_OIS,
					"Received calib settings");
				i2c_reg_settings = &(o_ctrl->i2c_calib_data);
				i2c_reg_settings->is_settings_valid = 1;
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					&o_ctrl->io_master_info,
					i2c_reg_settings,
					&cmd_desc[i], 1, NULL);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
						"Calib parsing failed: %d", rc);
					cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
					cam_mem_put_cpu_buf(dev_config.packet_handle);
					return rc;
				}
			} else if (o_ctrl->i2c_fwinit_data.is_settings_valid == 0) {
				CAM_DBG(CAM_OIS, "received fwinit settings");
				i2c_reg_settings =
					&(o_ctrl->i2c_fwinit_data);
				i2c_reg_settings->is_settings_valid = 1;
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					&o_ctrl->io_master_info,
					i2c_reg_settings,
					&cmd_desc[i], 1, NULL);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"fw init parsing failed: %d", rc);
					return rc;
				}
			} else if (((o_ctrl->ois_postcalib_flag) != 0) &&
				o_ctrl->i2c_postcalib_data.is_settings_valid == 0) {
				CAM_DBG(CAM_OIS, "Received PostCalib Settings");
				i2c_reg_settings = &(o_ctrl->i2c_postcalib_data);
				i2c_reg_settings->request_id = 0;
				rc = cam_sensor_i2c_command_parser(
					&o_ctrl->io_master_info,
					i2c_reg_settings,
					&cmd_desc[i], 1, NULL);
				if (rc < 0) {
					CAM_ERR(CAM_OIS,
					"postcalib parsing failed: %d", rc);
					return rc;
				}
			}
			break;
			}
			cam_mem_put_cpu_buf(cmd_desc[i].mem_handle);
		}

		if (o_ctrl->cam_ois_state != CAM_OIS_CONFIG) {
			rc = cam_ois_power_up(o_ctrl);
			if (rc) {
				CAM_ERR(CAM_OIS, " OIS Power up failed");
				cam_mem_put_cpu_buf(dev_config.packet_handle);
				return rc;
			}
		}

		if (o_ctrl->i2c_fwinit_data.is_settings_valid == 1) {
			rc = cam_ois_apply_settings(o_ctrl,
				&o_ctrl->i2c_fwinit_data);
			if ((rc == -EAGAIN) &&
				(o_ctrl->io_master_info.master_type == CCI_MASTER)) {
				CAM_WARN(CAM_OIS,
					"CCI HW is restting: Reapplying fwinit settings");
				usleep_range(1000, 1010);
				rc = cam_ois_apply_settings(o_ctrl,
					&o_ctrl->i2c_fwinit_data);
			}
			if (rc) {
				CAM_ERR(CAM_OIS,
					"Cannot apply fwinit data %d",
					rc);
				goto pwr_dwn;
			} else {
				CAM_DBG(CAM_OIS, "OIS fwinit settings success");
			}
		}

		if (o_ctrl->ois_preprog_flag && o_ctrl->ois_fw_flag) {
			rc = cam_ois_apply_settings(o_ctrl,
				&o_ctrl->i2c_preprog_data);
			if (rc) {
				CAM_ERR(CAM_OIS, "Cannot apply preprog settings");
				goto pwr_dwn;
			}
		}

		if (o_ctrl->ois_fw_flag) {
			rc = cam_ois_fw_prog_download(o_ctrl);
			if (rc) {
				CAM_ERR(CAM_OIS, "Failed OIS FW Download");
				goto pwr_dwn;
			}
		}

		if (o_ctrl->ois_precoeff_flag) {
			rc = cam_ois_apply_settings(o_ctrl,
				&o_ctrl->i2c_precoeff_data);
			if (rc) {
				CAM_ERR(CAM_OIS, "Cannot apply precoeff settings");
				goto pwr_dwn;
			}
		}

		if (o_ctrl->is_ois_calib) {
			rc = cam_ois_fw_coeff_download(o_ctrl);
			if (rc) {
				CAM_ERR(CAM_OIS, "Failed OIS COEFF FW Download");
				goto pwr_dwn;
			}
		}

		rc = cam_ois_apply_settings(o_ctrl, &o_ctrl->i2c_init_data);
		if ((rc == -EAGAIN) &&
			(o_ctrl->io_master_info.master_type == CCI_MASTER)) {
			CAM_WARN(CAM_OIS,
				"CCI HW is restting: Reapplying INIT settings");
			usleep_range(1000, 1010);
			rc = cam_ois_apply_settings(o_ctrl,
				&o_ctrl->i2c_init_data);
		}
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Cannot apply Init settings: rc = %d",
				rc);
			goto pwr_dwn;
		} else {
			CAM_DBG(CAM_OIS, "apply Init settings success");
		}

#ifdef CONFIG_MOT_DONGWOON_OIS_AF_DRIFT
		if (o_ctrl->af_drift_supported == true) {
			cam_ois_set_init_info(1);
		}
#endif

#if defined(CONFIG_MOT_OIS_SEM1217S_DRIVER) || defined(CONFIG_MOT_OIS_DW9784_DRIVER)
		if (o_ctrl->af_ois_use_same_ic == true) {
			g_ois_init_finished = 1;
		}
#endif

		if (o_ctrl->is_ois_calib) {
			rc = cam_ois_apply_settings(o_ctrl,
				&o_ctrl->i2c_calib_data);
			if ((rc == -EAGAIN) &&
				(o_ctrl->io_master_info.master_type == CCI_MASTER)) {
				CAM_WARN(CAM_OIS,
					"CCI HW is restting: Reapplying calib settings");
				usleep_range(1000, 1010);
				rc = cam_ois_apply_settings(o_ctrl,
					&o_ctrl->i2c_calib_data);
			}
			if (rc) {
				CAM_ERR(CAM_OIS, "Cannot apply calib data");
				goto pwr_dwn;
			} else {
				CAM_DBG(CAM_OIS, "apply calib data settings success");
			}
		}

		o_ctrl->cam_ois_state = CAM_OIS_CONFIG;
		if (o_ctrl->ois_postcalib_flag) {
			CAM_DBG(CAM_OIS, "starting post calib data");
			rc = cam_ois_apply_settings(o_ctrl,
			&o_ctrl->i2c_postcalib_data);
			if (rc) {
				CAM_ERR(CAM_OIS, "Cannot apply post calib data");
				goto pwr_dwn;
			}
		}

		rc = delete_request(&o_ctrl->i2c_fwinit_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting fwinit data: rc: %d", rc);
			rc = 0;
		}

		rc = delete_request(&o_ctrl->i2c_init_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting Init data: rc: %d", rc);
			rc = 0;
		}
		rc = delete_request(&o_ctrl->i2c_preprog_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting PreProg data: rc: %d", rc);
			rc = 0;
		}
		rc = delete_request(&o_ctrl->i2c_precoeff_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting PreCoeff data: rc: %d", rc);
			rc = 0;
		}
		rc = delete_request(&o_ctrl->i2c_calib_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting Calibration data: rc: %d", rc);
			rc = 0;
		}
		rc = delete_request(&o_ctrl->i2c_postcalib_data);
		if (rc < 0) {
			CAM_WARN(CAM_OIS,
				"Fail deleting PostCalib data: rc: %d", rc);
			rc = 0;
		}
		break;
#ifdef CONFIG_MOT_OIS_EARLY_UPGRADE_FW
	case CAM_OIS_PACKET_OPCODE_OIS_FW_UPGRADE:
	{
		CAM_INFO(CAM_OIS, "CAM_OIS_PACKET_OPCODE_OIS_FW_UPGRADE");
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);

		CAM_INFO(CAM_OIS, "num_cmd_buf %d", csl_packet->num_cmd_buf);

		/* Loop through multiple command buffers */
		for (i = 0; i < csl_packet->num_cmd_buf; i++) {
			total_cmd_buf_in_bytes = cmd_desc[i].length;
			if (!total_cmd_buf_in_bytes)
				continue;

			rc = cam_mem_get_cpu_buf(cmd_desc[i].mem_handle,
				&generic_ptr, &len_of_buff);
			if (rc < 0) {
				CAM_ERR(CAM_OIS, "Failed to get cpu buf : 0x%x",
					cmd_desc[i].mem_handle);
				return rc;
			}
			cmd_buf = (uint32_t *)generic_ptr;
			if (!cmd_buf) {
				CAM_ERR(CAM_OIS, "invalid cmd buf");
				return -EINVAL;
			}

			if ((len_of_buff < sizeof(struct common_header)) ||
				(cmd_desc[i].offset > (len_of_buff -
				sizeof(struct common_header)))) {
				CAM_ERR(CAM_OIS, "Invalid length for sensor cmd");
				return -EINVAL;
			}
			remain_len = len_of_buff - cmd_desc[i].offset;
			cmd_buf += cmd_desc[i].offset / sizeof(uint32_t);
			cmm_hdr = (struct common_header *)cmd_buf;

			switch (cmm_hdr->cmd_type) {
			case CAMERA_SENSOR_CMD_TYPE_I2C_INFO:
			CAM_INFO(CAM_OIS, "CAMERA_SENSOR_CMD_TYPE_I2C_INFO");
				rc = cam_ois_slaveInfo_pkt_parser(
					o_ctrl, cmd_buf, remain_len);
				if (rc < 0) {
					CAM_ERR(CAM_OIS, "Failed in parsing slave info");
					return rc;
				}
				break;
			case CAMERA_SENSOR_CMD_TYPE_PWR_UP:
			case CAMERA_SENSOR_CMD_TYPE_PWR_DOWN:
				CAM_INFO(CAM_OIS, "Received power settings buffer");
				rc = cam_sensor_update_power_settings(
					cmd_buf,
					total_cmd_buf_in_bytes,
					power_info, remain_len);
				if (rc) {
					CAM_ERR(CAM_OIS, "Failed: parse power settings");
					return rc;
				}
				break;
			default:
				CAM_INFO(CAM_OIS, "default cmd %d", cmm_hdr->cmd_type);
				break;
			}
		}

		if (o_ctrl->cam_ois_state != CAM_OIS_CONFIG) {
			rc = cam_ois_power_up(o_ctrl);
			if (rc) {
				CAM_ERR(CAM_OIS, " OIS Power up failed");
				return rc;
			}
			o_ctrl->cam_ois_state = CAM_OIS_CONFIG;
		}

		CAM_INFO(CAM_OIS, "ois_fw_flag %d, ois_early_fw_flag %d", o_ctrl->ois_fw_flag, o_ctrl->ois_early_fw_flag);
		if (o_ctrl->ois_early_fw_flag == 1) {
			CAM_INFO(CAM_OIS, "OIS early fw update enabled");
			rc = cam_ois_fw_prog_download(o_ctrl);
			return rc;
		}
	}
	break;
#endif
	case CAM_OIS_PACKET_OPCODE_OIS_CONTROL:
		if (o_ctrl->cam_ois_state < CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Not in right state to control OIS: %d",
				o_ctrl->cam_ois_state);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

#ifdef CONFIG_DONGWOON_OIS_VSYNC
		o_ctrl->is_need_eis_data  = false;
#endif

		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);
		i2c_reg_settings = &(o_ctrl->i2c_mode_data);
		i2c_reg_settings->is_settings_valid = 1;
		i2c_reg_settings->request_id = 0;
		rc = cam_sensor_i2c_command_parser(&o_ctrl->io_master_info,
			i2c_reg_settings,
			cmd_desc, 1, NULL);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS pkt parsing failed: %d", rc);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		rc = cam_ois_apply_settings(o_ctrl, i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "Cannot apply mode settings");
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		rc = delete_request(i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Fail deleting Mode data: rc: %d", rc);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}
		break;
#ifdef CONFIG_MOT_OIS_AF_DRIFT
	case CAM_OIS_PACKET_OPCODE_AF_DRIFT:
		if (o_ctrl->cam_ois_state < CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Not in right state to control OIS: %d",
				o_ctrl->cam_ois_state);
			return rc;
		}
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);
		i2c_reg_settings = &(o_ctrl->i2c_af_drift_data);
		i2c_reg_settings->is_settings_valid = 1;
		i2c_reg_settings->request_id = 0;
		rc = cam_sensor_i2c_command_parser(&o_ctrl->io_master_info,
			i2c_reg_settings,
			cmd_desc, 1, NULL);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS pkt parsing failed: %d", rc);
			return rc;
		}

		rc = cam_ois_apply_settings(o_ctrl, i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "Cannot apply mode settings");
			return rc;
		}

		rc = delete_request(i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Fail deleting Mode data: rc: %d", rc);
			return rc;
		}
		break;
#endif
#ifdef CONFIG_MOT_OIS_AFTER_SALES_SERVICE
	case CAM_OIS_PACKET_OPCODE_OIS_GYRO_OFFSET:
		if (o_ctrl->cam_ois_state < CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Not in right state to control OIS: %d",
				o_ctrl->cam_ois_state);
			return rc;
		}
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);
		i2c_reg_settings = &(o_ctrl->i2c_gyro_data);
		i2c_reg_settings->is_settings_valid = 1;
		i2c_reg_settings->request_id = 0;
		rc = cam_sensor_i2c_command_parser(&o_ctrl->io_master_info,
			i2c_reg_settings,
			cmd_desc, 1, NULL);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS pkt parsing failed: %d", rc);
			return rc;
		}

		rc = cam_ois_apply_settings(o_ctrl, i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "Cannot apply gyro offset settings");
			return rc;
		}

		rc = delete_request(i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Fail deleting gyro offset data: rc: %d", rc);
			return rc;
		}
		break;
#endif
	case CAM_OIS_PACKET_OPCODE_READ: {
		uint64_t qtime_ns;
		struct cam_buf_io_cfg *io_cfg;
		struct i2c_settings_array i2c_read_settings;

#ifdef CONFIG_DONGWOON_OIS_VSYNC
		unsigned long rem_jiffies = 0;
		uint8_t *read_buff = NULL;
		int packet_cnt = 0;
		uint32_t buff_length = 0, read_length = 0;
		struct i2c_settings_list *i2c_list;
#endif

		if (o_ctrl->cam_ois_state < CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Not in right state to read OIS: %d",
				o_ctrl->cam_ois_state);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}
		CAM_DBG(CAM_OIS, "number of I/O configs: %d:",
			csl_packet->num_io_configs);
		if (csl_packet->num_io_configs == 0) {
			CAM_ERR(CAM_OIS, "No I/O configs to process");
			rc = -EINVAL;
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

#ifdef CONFIG_DONGWOON_OIS_VSYNC
		o_ctrl->is_need_eis_data  = true;
#endif

		INIT_LIST_HEAD(&(i2c_read_settings.list_head));

		io_cfg = (struct cam_buf_io_cfg *) ((uint8_t *)
			&csl_packet->payload +
			csl_packet->io_configs_offset);

		/* validate read data io config */
		if (io_cfg == NULL) {
			CAM_ERR(CAM_OIS, "I/O config is invalid(NULL)");
			rc = -EINVAL;
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);
		i2c_read_settings.is_settings_valid = 1;
		i2c_read_settings.request_id = 0;
		rc = cam_sensor_i2c_command_parser(&o_ctrl->io_master_info,
			&i2c_read_settings,
			cmd_desc, 1, &io_cfg[0]);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS read pkt parsing failed: %d", rc);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

#ifdef CONFIG_DONGWOON_OIS_VSYNC
		list_for_each_entry(i2c_list,
			&(i2c_read_settings.list_head), list) {
			if (i2c_list->op_code == CAM_SENSOR_I2C_READ_SEQ) {
				read_buff     = i2c_list->i2c_settings.read_buff;
				buff_length   = i2c_list->i2c_settings.read_buff_len;
				read_length   = i2c_list->i2c_settings.size;

				CAM_DBG(CAM_OIS, "buff_length = %d, read_length = %d", buff_length, read_length);

				if (read_length > buff_length || buff_length < (PACKET_BYTE*MAX_PACKET)) {
					CAM_ERR(CAM_SENSOR, "Invalid buffer size, readLen: %d, bufLen: %d", read_length, buff_length);
					delete_request(&i2c_read_settings);
					return -EINVAL;
				}

				// block hal LensPositionThread and wait ois data from vsync irq, max wait 120 ms
				rem_jiffies = wait_for_completion_timeout(&o_ctrl->vsync_completion,
										msecs_to_jiffies(120));
				if (rem_jiffies == 0) {
					CAM_ERR(CAM_OIS, "Wait ois data completion timeout 120 ms");
					delete_request(&i2c_read_settings);
					return -ETIMEDOUT;
				}

				mutex_lock(&(o_ctrl->vsync_mutex));

				// ois vsync SOF qtime timestamp
				qtime_ns = o_ctrl->prev_timestamp;
				packet_cnt = o_ctrl->packet_count;

				if (csl_packet->num_io_configs > 1 &&
					qtime_ns != 0 &&
					packet_cnt > 0 &&
					packet_cnt <= MAX_PACKET) {
					rc = cam_sensor_util_write_qtimer_to_io_buffer(qtime_ns, &io_cfg[1]);
					if (rc < 0) {
						CAM_ERR(CAM_OIS, "write qtimer failed rc: %d", rc);
						delete_request(&i2c_read_settings);
						mutex_unlock(&(o_ctrl->vsync_mutex));
						return rc;
					}
				} else {
					CAM_ERR(CAM_OIS, "csl_packet->num_io_configs = %d, qtime_ns = %lld, packet_cnt = %d",
							csl_packet->num_io_configs, qtime_ns, packet_cnt);
					delete_request(&i2c_read_settings);
					mutex_unlock(&(o_ctrl->vsync_mutex));
					return rc;
				}

				// copy ois vsync data to hal buff
				if ((packet_cnt*PACKET_BYTE) <= buff_length &&
					(packet_cnt*PACKET_BYTE) <= o_ctrl->ois_data_size)
					memcpy((void *)read_buff, (void *)o_ctrl->ois_data, packet_cnt*PACKET_BYTE);

				mutex_unlock(&(o_ctrl->vsync_mutex));
			}
		}
#else
		rc = cam_sensor_util_get_current_qtimer_ns(&qtime_ns);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "failed to get qtimer rc:%d");
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		rc = cam_sensor_i2c_read_data(
			&i2c_read_settings,
			&o_ctrl->io_master_info);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "cannot read data rc: %d", rc);
			delete_request(&i2c_read_settings);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		if (csl_packet->num_io_configs > 1) {
			rc = cam_sensor_util_write_qtimer_to_io_buffer(
				qtime_ns, &io_cfg[1]);
			if (rc < 0) {
				CAM_ERR(CAM_OIS,
					"write qtimer failed rc: %d", rc);
				delete_request(&i2c_read_settings);
				cam_mem_put_cpu_buf(dev_config.packet_handle);
				return rc;
			}
		}
#endif

		rc = delete_request(&i2c_read_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Failed in deleting the read settings");
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}
		break;
	}
	case CAM_OIS_PACKET_OPCODE_WRITE_TIME: {
		if (o_ctrl->cam_ois_state < CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_ERR(CAM_OIS,
				"Not in right state to write time to OIS: %d",
				o_ctrl->cam_ois_state);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}
		offset = (uint32_t *)&csl_packet->payload;
		offset += (csl_packet->cmd_buf_offset / sizeof(uint32_t));
		cmd_desc = (struct cam_cmd_buf_desc *)(offset);
		i2c_reg_settings = &(o_ctrl->i2c_time_data);
		i2c_reg_settings->is_settings_valid = 1;
		i2c_reg_settings->request_id = 0;
		rc = cam_sensor_i2c_command_parser(&o_ctrl->io_master_info,
			i2c_reg_settings,
			cmd_desc, 1, NULL);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "OIS pkt parsing failed: %d", rc);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		rc = cam_ois_update_time(i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "Cannot update time");
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

		rc = cam_ois_apply_settings(o_ctrl, i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS, "Cannot apply mode settings");
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}

#ifdef CONFIG_MOT_OIS_DW9784_ACTIVE_OIS
		mdelay(1);
#endif

		rc = delete_request(i2c_reg_settings);
		if (rc < 0) {
			CAM_ERR(CAM_OIS,
				"Fail deleting Mode data: rc: %d", rc);
			cam_mem_put_cpu_buf(dev_config.packet_handle);
			return rc;
		}
		break;
	}
	default:
		CAM_ERR(CAM_OIS, "Invalid Opcode: %d",
			(csl_packet->header.op_code & 0xFFFFFF));
		cam_mem_put_cpu_buf(dev_config.packet_handle);
		return -EINVAL;
	}

	if (!rc) {
		cam_mem_put_cpu_buf(dev_config.packet_handle);
		return rc;
	}
pwr_dwn:
	cam_mem_put_cpu_buf(dev_config.packet_handle);
	//cam_ois_power_down(o_ctrl); /* ois will pown down in CAM_RELEASE_DEV when closed camera */
	return rc;
}

void cam_ois_shutdown(struct cam_ois_ctrl_t *o_ctrl)
{
	int rc = 0;
	struct cam_ois_soc_private *soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	struct cam_sensor_power_ctrl_t *power_info = &soc_private->power_info;

	if (o_ctrl->cam_ois_state == CAM_OIS_INIT)
		return;

	if (o_ctrl->cam_ois_state >= CAM_OIS_CONFIG) {
		rc = cam_ois_power_down(o_ctrl);
		if (rc < 0)
			CAM_ERR(CAM_OIS, "OIS Power down failed");
	}

	if (o_ctrl->cam_ois_state >= CAM_OIS_ACQUIRE) {
		rc = cam_destroy_device_hdl(o_ctrl->bridge_intf.device_hdl);
		if (rc < 0)
			CAM_ERR(CAM_OIS, "destroying the device hdl");
		o_ctrl->bridge_intf.device_hdl = -1;
		o_ctrl->bridge_intf.link_hdl = -1;
		o_ctrl->bridge_intf.session_hdl = -1;
	}

	if (o_ctrl->i2c_fwinit_data.is_settings_valid == 1)
		delete_request(&o_ctrl->i2c_fwinit_data);

	if (o_ctrl->i2c_mode_data.is_settings_valid == 1)
		delete_request(&o_ctrl->i2c_mode_data);

#ifdef CONFIG_MOT_OIS_AF_DRIFT
	if (o_ctrl->i2c_af_drift_data.is_settings_valid == 1)
		delete_request(&o_ctrl->i2c_af_drift_data);
#endif

#ifdef CONFIG_MOT_OIS_AFTER_SALES_SERVICE
	if (o_ctrl->i2c_gyro_data.is_settings_valid == 1)
		delete_request(&o_ctrl->i2c_gyro_data);
#endif

	if (o_ctrl->i2c_calib_data.is_settings_valid == 1)
		delete_request(&o_ctrl->i2c_calib_data);

	if (o_ctrl->i2c_init_data.is_settings_valid == 1)
		delete_request(&o_ctrl->i2c_init_data);

	kfree(power_info->power_setting);
	kfree(power_info->power_down_setting);
	power_info->power_setting = NULL;
	power_info->power_down_setting = NULL;
	power_info->power_down_setting_size = 0;
	power_info->power_setting_size = 0;

	o_ctrl->cam_ois_state = CAM_OIS_INIT;
}

/**
 * cam_ois_driver_cmd - Handle ois cmds
 * @e_ctrl:     ctrl structure
 * @arg:        Camera control command argument
 *
 * Returns success or failure
 */
int cam_ois_driver_cmd(struct cam_ois_ctrl_t *o_ctrl, void *arg)
{
	int                              rc = 0;
	struct cam_ois_query_cap_t       ois_cap = {0};
	struct cam_control              *cmd = (struct cam_control *)arg;
	struct cam_ois_soc_private      *soc_private = NULL;
	struct cam_sensor_power_ctrl_t  *power_info = NULL;

	if (!o_ctrl || !cmd) {
		CAM_ERR(CAM_OIS, "Invalid arguments");
		return -EINVAL;
	}

	if (cmd->handle_type != CAM_HANDLE_USER_POINTER) {
		CAM_ERR(CAM_OIS, "Invalid handle type: %d",
			cmd->handle_type);
		return -EINVAL;
	}

	soc_private =
		(struct cam_ois_soc_private *)o_ctrl->soc_info.soc_private;
	power_info = &soc_private->power_info;

	mutex_lock(&(o_ctrl->ois_mutex));
	switch (cmd->op_code) {
	case CAM_QUERY_CAP:
		ois_cap.slot_info = o_ctrl->soc_info.index;

		if (copy_to_user(u64_to_user_ptr(cmd->handle),
			&ois_cap,
			sizeof(struct cam_ois_query_cap_t))) {
			CAM_ERR(CAM_OIS, "Failed Copy to User");
			rc = -EFAULT;
			goto release_mutex;
		}
		CAM_DBG(CAM_OIS, "ois_cap: ID: %d", ois_cap.slot_info);
		break;
	case CAM_ACQUIRE_DEV:
		rc = cam_ois_get_dev_handle(o_ctrl, arg);
		if (rc) {
			CAM_ERR(CAM_OIS, "Failed to acquire dev");
			goto release_mutex;
		}

		o_ctrl->cam_ois_state = CAM_OIS_ACQUIRE;
		break;
	case CAM_START_DEV:
		if (o_ctrl->cam_ois_state != CAM_OIS_CONFIG) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
			"Not in right state for start : %d",
			o_ctrl->cam_ois_state);
			goto release_mutex;
		}

		o_ctrl->cam_ois_state = CAM_OIS_START;
		break;
	case CAM_CONFIG_DEV:
		rc = cam_ois_pkt_parse(o_ctrl, arg);
		if (rc) {
			CAM_ERR(CAM_OIS, "Failed in ois pkt Parsing");
			goto release_mutex;
		}
		break;
	case CAM_RELEASE_DEV:
		if (o_ctrl->cam_ois_state == CAM_OIS_START) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
				"Cant release ois: in start state");
			goto release_mutex;
		}

		if (o_ctrl->cam_ois_state == CAM_OIS_CONFIG) {
			rc = cam_ois_power_down(o_ctrl);
			if (rc < 0) {
				CAM_ERR(CAM_OIS, "OIS Power down failed");
				goto release_mutex;
			}
		}

		if (o_ctrl->bridge_intf.device_hdl == -1) {
			CAM_ERR(CAM_OIS, "link hdl: %d device hdl: %d",
				o_ctrl->bridge_intf.device_hdl,
				o_ctrl->bridge_intf.link_hdl);
			rc = -EINVAL;
			goto release_mutex;
		}
		rc = cam_destroy_device_hdl(o_ctrl->bridge_intf.device_hdl);
		if (rc < 0)
			CAM_ERR(CAM_OIS, "destroying the device hdl");
		o_ctrl->bridge_intf.device_hdl = -1;
		o_ctrl->bridge_intf.link_hdl = -1;
		o_ctrl->bridge_intf.session_hdl = -1;
		o_ctrl->cam_ois_state = CAM_OIS_INIT;

		kfree(power_info->power_setting);
		kfree(power_info->power_down_setting);
		power_info->power_setting = NULL;
		power_info->power_down_setting = NULL;
		power_info->power_down_setting_size = 0;
		power_info->power_setting_size = 0;

		if (o_ctrl->i2c_mode_data.is_settings_valid == 1)
			delete_request(&o_ctrl->i2c_mode_data);

#ifdef CONFIG_MOT_OIS_AF_DRIFT
		if (o_ctrl->i2c_af_drift_data.is_settings_valid == 1)
			delete_request(&o_ctrl->i2c_af_drift_data);
#endif

#ifdef CONFIG_MOT_OIS_AFTER_SALES_SERVICE
		if (o_ctrl->i2c_gyro_data.is_settings_valid == 1)
			delete_request(&o_ctrl->i2c_gyro_data);
#endif

		if (o_ctrl->i2c_calib_data.is_settings_valid == 1)
			delete_request(&o_ctrl->i2c_calib_data);

		if (o_ctrl->i2c_init_data.is_settings_valid == 1)
			delete_request(&o_ctrl->i2c_init_data);

		if (o_ctrl->i2c_fwinit_data.is_settings_valid == 1)
			delete_request(&o_ctrl->i2c_fwinit_data);

		break;
	case CAM_STOP_DEV:
		if (o_ctrl->cam_ois_state != CAM_OIS_START) {
			rc = -EINVAL;
			CAM_WARN(CAM_OIS,
			"Not in right state for stop : %d",
			o_ctrl->cam_ois_state);
		}
#ifdef CONFIG_DONGWOON_OIS_VSYNC
		o_ctrl->is_first_vsync = 1;
#endif

		o_ctrl->cam_ois_state = CAM_OIS_CONFIG;
		break;
	default:
		CAM_INFO(CAM_OIS, "invalid opcode %d", cmd->op_code);
		goto release_mutex;
	}
release_mutex:
	mutex_unlock(&(o_ctrl->ois_mutex));
	return rc;
}
