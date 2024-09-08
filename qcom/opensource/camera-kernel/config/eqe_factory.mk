# Settings for compiling kalama camera architecture

# Localized KCONFIG settings
CONFIG_MOT_OIS_DW9784_DRIVER := y
CONFIG_CCI_DEBUG_INTF := y
CONFIG_MOT_OIS_EARLY_UPGRADE_FW := y
# Flags to pass into C preprocessor
ccflags-y += -DCONFIG_MOT_OIS_DW9784_DRIVER=1
ccflags-y += -DCONFIG_CCI_DEBUG_INTF=1
ccflags-y += -DCONFIG_MOT_OIS_EARLY_UPGRADE_FW=1
ccflags-y += -DCONFIG_MOT_DONGWOON_OIS_AF_DRIFT=1