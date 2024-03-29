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

#ifndef __CONFIG_CONNECTION_H__
#define __CONFIG_CONNECTION_H__

#include <list>
#include <string>
#include "Semaphore.h"
#include "PTHICommand.h"
#include "FWULCommand.h"


#define _CFCON_AMT_DISABLED 0
#define _CFCON_AMT_ENABLED  1
#define _CFCON_AMT_UNKNOWN  2
#define _CFCON_AMT_AT3      3

/*
	This class is used as a wrapper to direct connection to AMT
*/

class ConfigConnection
{
public:
	ConfigConnection(bool verbose = false);
	~ConfigConnection();

	bool Init(bool checkEnabled = true);
	bool IsInitialized();
	void Deinit();

	//used to check if AMT is enabled
	int  IsAMTEnabled(bool useOpenPTHI = false);

	//update host FQDN in AMT is one of LMS functions
	AMT_STATUS SendHostFQDN(char* fqdn);

	enum INIT_STATES {
		INIT_STATE_DISCONNECTED = 0,
		INIT_STATE_CONNECTING,
		INIT_STATE_CONNECTED
	};

private:
	Semaphore _initLock;
	Semaphore _requestLock;
	INIT_STATES _initState;

	PTHICommand _pthiCommand;
	FWULCommand _fwulCommand;
};

#endif

