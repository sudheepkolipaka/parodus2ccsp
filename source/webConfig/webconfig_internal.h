/**
 * @file webconfig_internal.h
 *
 * @description This header defines the webconfig apis
 *
 * Copyright (c) 2019  Comcast
 */

#ifndef _WEBCONFIG_INTERNAL_H_
#define _WEBCONFIG_INTERNAL_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <wdmp-c.h>
#include <cimplog.h>

struct token_data {
    size_t size;
    char* data;
};

#if defined(_COSA_BCM_MIPS_)
#define DEVICE_MAC                   "Device.DPoE.Mac_address"
#elif defined(PLATFORM_RASPBERRYPI)
#define DEVICE_MAC                   "Device.Ethernet.Interface.5.MACAddress"
#elif defined(RDKB_EMU)
#define DEVICE_MAC                   "Device.DeviceInfo.X_COMCAST-COM_WAN_MAC"
#else
#define DEVICE_MAC                   "Device.X_CISCO_COM_CableModem.MACAddress"
#endif

#define SERIAL_NUMBER 		     "Device.DeviceInfo.SerialNumber"
#define FIRMWARE_VERSION       	     "Device.DeviceInfo.X_CISCO_COM_FirmwareName"
#define DEVICE_BOOT_TIME             "Device.DeviceInfo.X_RDKCENTRAL-COM_BootTime"

size_t write_callback_fn(void *buffer, size_t size, size_t nmemb, struct token_data *data);
void getAuthToken(char *webpa_auth_token);


#endif /* _WEBCONFIG_INTERNAL_H_ */
