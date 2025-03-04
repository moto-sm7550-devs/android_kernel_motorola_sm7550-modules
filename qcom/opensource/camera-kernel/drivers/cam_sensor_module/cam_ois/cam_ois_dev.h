/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#ifndef _CAM_OIS_DEV_H_
#define _CAM_OIS_DEV_H_

#include <linux/i2c.h>
#include <linux/gpio.h>
#include <media/v4l2-event.h>
#include <media/v4l2-subdev.h>
#include <media/v4l2-ioctl.h>
#include <media/cam_sensor.h>
#include <cam_sensor_i2c.h>
#include <cam_sensor_spi.h>
#include <cam_sensor_io.h>
#include <cam_cci_dev.h>
#include <cam_req_mgr_util.h>
#include <cam_req_mgr_interface.h>
#include <cam_mem_mgr.h>
#include <cam_subdev.h>
#include "cam_soc_util.h"
#include "cam_context.h"

#define DEFINE_MSM_MUTEX(mutexname) \
	static struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)

#define OIS_DRIVER_I2C "cam-i2c-ois"
#define OIS_DRIVER_I3C "i3c_camera_ois"


#ifdef CONFIG_DONGWOON_OIS_VSYNC

#define PACKET_ADDR 0x70B0
#define PACKET_BYTE 62
#define MAX_PACKET 5
#define MAX_SAMPLE 50

#define READ_COUNT 6
#define DATA_READY_ADDR 0x70DA
#define DATA_READY 0x0001

#endif


enum cam_ois_state {
	CAM_OIS_INIT,
	CAM_OIS_ACQUIRE,
	CAM_OIS_CONFIG,
	CAM_OIS_START,
};

/**
 * struct cam_ois_i2c_info_t - I2C info
 * @slave_addr      :   slave address
 * @i2c_freq_mode   :   i2c frequency mode
 *
 */
struct cam_ois_i2c_info_t {
	uint16_t slave_addr;
	uint8_t i2c_freq_mode;
};

/**
 * struct cam_ois_soc_private - ois soc private data structure
 * @ois_name        :   ois name
 * @i2c_info        :   i2c info structure
 * @power_info      :   ois power info
 *
 */
struct cam_ois_soc_private {
	const char *ois_name;
	struct cam_ois_i2c_info_t i2c_info;
	struct cam_sensor_power_ctrl_t power_info;
};

/**
 * struct cam_ois_intf_params - bridge interface params
 * @device_hdl   : Device Handle
 * @session_hdl  : Session Handle
 * @ops          : KMD operations
 * @crm_cb       : Callback API pointers
 */
struct cam_ois_intf_params {
	int32_t device_hdl;
	int32_t session_hdl;
	int32_t link_hdl;
	struct cam_req_mgr_kmd_ops ops;
	struct cam_req_mgr_crm_cb *crm_cb;
};

/**
 * struct cam_ois_ctrl_t - OIS ctrl private data
 * @device_name     :   ois device_name
 * @pdev            :   platform device
 * @ois_mutex       :   ois mutex
 * @soc_info        :   ois soc related info
 * @io_master_info  :   Information about the communication master
 * @cci_i2c_master  :   I2C structure
 * @v4l2_dev_str    :   V4L2 device structure
 * @is_i3c_device   :   A Flag to indicate whether this OIS is I3C Device or not.
 * @bridge_intf     :   bridge interface params
 * @i2c_fwinit_data :   ois i2c firmware init settings
 * @i2c_init_data   :   ois i2c init settings
 * @i2c_mode_data   :   ois i2c mode settings
 * @i2c_preprog_data    :   ois i2c preprog settings
 * @i2c_precoeff_data   :   ois i2c precoeff settings
 * @i2c_postcalib_data  :   ois i2c postcalib settings
 * @i2c_time_data   :   ois i2c time write settings
 * @i2c_calib_data  :   ois i2c calib settings
 * @ois_device_type :   ois device type
 * @cam_ois_state   :   ois_device_state
 * @ois_fw_flag     :   flag for firmware download
 * @ois_preprog_flag    :   flag for preprog reg settings
 * @ois_precoeff_flag   :   flag for precoeff reg settings
 * @is_ois_calib    :   flag for Calibration data
 * @ois_postcalib_flag  :   flag for postcalib reg settings
 * @opcode          :   ois opcode
 * @ois_fw_inc_addr     :   flag to increment address when sending fw
 * @ois_fw_addr_type    :   address type of fw
 * @ois_fw_txn_data_sz  :   num data bytes per i2c txn when sending fw
 * @device_name     :   Device name
 *
 */
struct cam_ois_ctrl_t {
	char device_name[CAM_CTX_DEV_NAME_MAX_LENGTH];
	struct platform_device *pdev;
	struct mutex ois_mutex;
	struct cam_hw_soc_info soc_info;
	struct camera_io_master io_master_info;
	enum cci_i2c_master_t cci_i2c_master;
	enum cci_device_num cci_num;
	struct cam_subdev v4l2_dev_str;
	bool is_i3c_device;
	struct cam_ois_intf_params bridge_intf;
	struct i2c_settings_array i2c_fwinit_data;
	struct i2c_settings_array i2c_init_data;
	struct i2c_settings_array i2c_preprog_data;
	struct i2c_settings_array i2c_precoeff_data;
	struct i2c_settings_array i2c_calib_data;
	struct i2c_settings_array i2c_postcalib_data;
	struct i2c_settings_array i2c_mode_data;
#ifdef CONFIG_MOT_OIS_AF_DRIFT
	struct i2c_settings_array i2c_af_drift_data;
#endif
#ifdef CONFIG_MOT_OIS_AFTER_SALES_SERVICE
	struct i2c_settings_array i2c_gyro_data;
#endif
	struct i2c_settings_array i2c_time_data;
	enum msm_camera_device_type_t ois_device_type;
	enum cam_ois_state cam_ois_state;
	char ois_name[32];
	uint8_t ois_fw_flag;
	uint8_t ois_preprog_flag;
	uint8_t ois_precoeff_flag;
	uint8_t is_ois_calib;
	uint8_t ois_postcalib_flag;
	uint8_t ois_fw_txn_data_sz;
	uint8_t ois_fw_inc_addr;
	uint8_t ois_fw_addr_type;
	uint8_t ois_fw_data_type;
	struct cam_ois_opcode opcode;
#ifdef CONFIG_DONGWOON_OIS_VSYNC
	bool is_ois_vsync_irq_supported;
	int vsync_irq;
	struct mutex vsync_mutex;
	struct completion vsync_completion;
	uint64_t prev_timestamp;
	uint64_t curr_timestamp;
	int packet_count;
	bool is_first_vsync;
	uint8_t *ois_data;
	int ois_data_size;
	bool is_video_mode;
	bool is_need_eis_data;
#endif
#ifdef CONFIG_MOT_OIS_SEM1217S_DRIVER
	struct mutex sem1217s_mutex;
#endif
#ifdef CONFIG_MOT_OIS_EARLY_UPGRADE_FW
	uint8_t ois_early_fw_flag;
#endif
#ifdef CONFIG_MOT_DONGWOON_OIS_AF_DRIFT
	bool af_drift_supported;
#endif
#if defined(CONFIG_MOT_OIS_SEM1217S_DRIVER) || defined(CONFIG_MOT_OIS_DW9784_DRIVER)
	bool af_ois_use_same_ic;
#endif
};

/**
 * @brief : API to register OIS hw to platform framework.
 * @return struct platform_device pointer on on success, or ERR_PTR() on error.
 */
int cam_ois_driver_init(void);

/**
 * @brief : API to remove OIS Hw from platform framework.
 */
void cam_ois_driver_exit(void);
#endif /*_CAM_OIS_DEV_H_ */
