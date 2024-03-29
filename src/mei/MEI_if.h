/*******************************************************************************
 * Copyright (C) 2004-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corporation. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corporation. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef __MEI_INTRFACE_H__
#define __MEI_INTRFACE_H__

typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef char            CHAR;
typedef unsigned long   ULONG;
typedef UINT32          AMT_STATUS;
typedef UINT32          AMT_BOOLEAN;

typedef enum _MEI_STATUS {
	MEI_STATUS_OK                    = 0x0,
	MEI_STATUS_GENERAL_ERROR         = 0x2000,
	MEI_STATUS_LOCATE_DEVICE_ERROR,
	MEI_STATUS_MEMORY_ACCESS_ERROR,
	MEI_STATUS_WRITE_REGISTER_ERROR,
	MEI_STATUS_MEMORY_ALLOCATION_ERROR,
	MEI_STATUS_BUFFER_OVEREFLOW_ERROR,
	MEI_STATUS_NOT_ENOUGH_MEMORY,
	MEI_STATUS_MSG_TRANSMISSION_ERROR,
	MEI_STATUS_VERSION_MISMATCH,
	MEI_STATUS_UNEXPECTED_INTERRUPT_REASON,
	MEI_STATUS_TIMEOUT_ERROR,
	MEI_STATUS_UNEXPECTED_RESPONSE,
	MEI_STATUS_UNKNOWN_MESSAGE,
	MEI_STATUS_CANNOT_FOUND_HOST_CLIENT,
	MEI_STATUS_CANNOT_FOUND_ME_CLIENT,
	MEI_STATUS_CLIENT_ALREADY_CONNECTED,
	MEI_STATUS_NO_FREE_CONNECTION,
	MEI_STATUS_ILLEGAL_PARAMETER,
	MEI_STATUS_FLOW_CONTROL_ERROR,
	MEI_STATUS_NO_MESSAGE,
	MEI_STATUS_BUFFER_TOO_LARGE,
	MEI_STATUS_BUFFER_TOO_SMALL,
	MEI_STATUS_BUFFER_NOT_EMPTY,
	NUM_OF_MEI_STATUSES
} MEI_STATUS;

const GUID MEI_PTHI  = {0x12f80028, 0xb4b7, 0x4b2d, {0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c}};

const GUID FW_UPDATE_GUID = {0x309dcde8, 0xccb1, 0x4062, {0x8f, 0x78, 0x60, 0x1, 0x15, 0xa3, 0x43, 0x27}};

const GUID WD_GUID    = {0x05B79A6F, 0x4628, 0x4D7F, {0x89, 0x9D, 0xA9, 0x15, 0x14, 0xCB, 0x32, 0xAB}};

#pragma pack(1)

typedef struct _MEI_VERSION {
	UINT8 major;
	UINT8 minor;
	UINT8 hotfix;
	UINT16 build;
} MEI_VERSION;

typedef struct _MEI_CLIENT {
	UINT32  MaxMessageLength;
	UINT8 ProtocolVersion;
	UINT8 reserved[3];
} MEI_CLIENT;

typedef union _MEFWCAPS_SKU
{
	UINT32   Data;
	struct {
		UINT32   Reserved    :1; //Legacy
		UINT32   Qst         :1; //QST
		UINT32   Asf         :1; //ASF2
		UINT32   Amt         :1; //AMT Professional
		UINT32   AmtFund     :1; //AMT Fundamental
		UINT32   Tpm         :1; //TPM
		UINT32   Dt          :1; //Danbury Technology
		UINT32   Fps         :1; //Fingerprint Sensor
		UINT32   HomeIT      :1; //Home IT
		UINT32   Mctp        :1; //MCTP
		UINT32   WoX         :1; //Wake on X
		UINT32   PmcPatch    :1; //PMC Patch
		UINT32   Ve          :1; //VE
		UINT32   Tdt         :1; //Theft Deterrent Technology
		UINT32   Corp        :1; //Corporate
		UINT32   Reserved2   :17;
	} Fields;
} MEFWCAPS_SKU;

typedef enum _MEFWCAPS_MANAGEABILITY_SUPP
{
	MEFWCAPS_MANAGEABILITY_SUPP_NONE = 0,
	MEFWCAPS_MANAGEABILITY_SUPP_AMT,
	MEFWCAPS_MANAGEABILITY_SUPP_ASF,
	MEFWCAPS_MANAGEABILITY_SUPP_CP
} MEFWCAPS_MANAGEABILITY_SUPP;


#pragma pack()

#endif // __MEI_INTRFACE_H__
