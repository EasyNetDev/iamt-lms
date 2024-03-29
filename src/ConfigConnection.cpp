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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "ConfigConnection.h"
#include "Lock.h"
#include "ATNetworkTool.h"

ConfigConnection::ConfigConnection(bool verbose) :
_initState(ConfigConnection::INIT_STATE_DISCONNECTED),
_pthiCommand(verbose, 5000),
_fwulCommand(verbose)
{
}

ConfigConnection::~ConfigConnection()
{
}

bool ConfigConnection::IsInitialized()
{
	Lock il(_initLock);
	return ((_initState == INIT_STATE_CONNECTED) ? true : false);
}

int ConfigConnection::IsAMTEnabled(bool useOpenPTHI)
{
	FWU_GET_VERSION_MSG_REPLY verMsg;
	FWU_GET_INFO_MSG_REPLY infoMsg;
	MEI_STATUS meiRet;
	int ret = _CFCON_AMT_UNKNOWN;

	if (useOpenPTHI) {
		CODE_VERSIONS ver;
		AMT_STATUS ast = _pthiCommand.GetCodeVersions(ver);
		if (PTHI_STATUS_EMPTY_RESPONSE == ast) {
			return _CFCON_AMT_DISABLED;
		}
		if (AMT_STATUS_SUCCESS == ast) {
			return _CFCON_AMT_ENABLED;
		}
		return ret;
	}

	if (_fwulCommand.FWULClient.Init()) {
		meiRet = _fwulCommand.GetFWUVersionAndInfo(verMsg, infoMsg);
		_fwulCommand.FWULClient.Deinit();
		if (MEI_STATUS_OK == meiRet) {
			if (infoMsg.MessageType == FWU_GET_INFO_REPLY) {
				return ((MEFWCAPS_MANAGEABILITY_SUPP_AMT
					 == infoMsg.ManageabilityMode)
					    ? _CFCON_AMT_ENABLED
					    : _CFCON_AMT_DISABLED);
			}
			ret = _CFCON_AMT_AT3;
		}
	}

	return ret;
}

bool ConfigConnection::Init(bool checkEnabled)
{
	{
		Lock il(_initLock);
		if (_initState == INIT_STATE_CONNECTING) {
			return false;
		}
		_initState = INIT_STATE_CONNECTING;
	}

	if (!(_pthiCommand.PTHIClient.Init(1))) {
		Deinit();
		return false;
	}

	if (checkEnabled) {
		if (_CFCON_AMT_ENABLED != IsAMTEnabled(true)) {
			Deinit();
			return false;
		}
	}

	{
		Lock il(_initLock);
		if (_initState != INIT_STATE_CONNECTING) {
			_pthiCommand.PTHIClient.Deinit();
			return false;
		}
		_initState = INIT_STATE_CONNECTED;
	}

	return true;
}

void ConfigConnection::Deinit()
{
	Lock il(_initLock);
	if (_initState != INIT_STATE_CONNECTING) {
		_pthiCommand.PTHIClient.Deinit();
	}
	_initState = INIT_STATE_DISCONNECTED;
}

AMT_STATUS ConfigConnection::SendHostFQDN(char* fqdn)
{
	Lock l(_requestLock);

	{
		Lock il(_initLock);
		if (_initState != INIT_STATE_CONNECTED) {
			return PTSDK_STATUS_INTERNAL_ERROR;
		}
	}
	AMT_ANSI_STRING host;
	host.Buffer=fqdn;
	host.Length=strlen(fqdn);
	AMT_STATUS result = _pthiCommand.SetHostFQDN(host);

		if (result == AMT_STATUS_INTERNAL_ERROR) {
			Lock il(_initLock);
			if (!_pthiCommand.PTHIClient.IsInitialized()) {
				_initState = INIT_STATE_DISCONNECTED;
			}
		}
	return result;
}

