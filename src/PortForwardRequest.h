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

#ifndef _PORT_FORWARD_REQUEST_H_
#define _PORT_FORWARD_REQUEST_H_

#include <string>


#ifndef SOCKET
#define SOCKET int
#endif

typedef int (*IsConnectionPermittedCallback)(void * const param, SOCKET s);

/*
	This class manages life cycles of port forward request instances
*/
class PortForwardRequest
{
public:
	enum PORT_FORWARD_REQUEST_STATUS {
		NOT_ACTIVE,
		PENDING_REQUEST,
		LISTENING
	};

	PortForwardRequest(std::string bindedAddress, int port,
			   SOCKET listeningSocket,
			   IsConnectionPermittedCallback cb, bool isLocal) :
		_bindedAddress(bindedAddress),
		_port(port),
		_local(isLocal),
		_listeningSocket(listeningSocket),
		_cb(cb),
		_status(NOT_ACTIVE),
		_channelCount(0) {}

	const std::string GetBindedAddress() const { return _bindedAddress; }
	const unsigned int GetPort() const { return _port; }
	SOCKET GetListeningSocket() const { return _listeningSocket; }

	int IsConnectionPermitted(void *param, SOCKET s)
	{
		if (_cb != NULL) {
			return _cb(param, s);
		} else {
			return -1;
		}
	}

	PORT_FORWARD_REQUEST_STATUS GetStatus() { return _status; }
	bool IsLocal() { return _local; }
	bool SetStatus(PORT_FORWARD_REQUEST_STATUS newStatus) { _status = newStatus; return true; }
	unsigned int GetChannelCount() { return _channelCount; }
	unsigned int IncreaseChannelCount() { return ++_channelCount; }

	unsigned int DecreaseChannelCount()
	{
		if (_channelCount > 0) {
			--_channelCount;
		}
		return _channelCount;
	}


private:
	const std::string _bindedAddress; // machine address on which LME asks for a Port Forwarding
	const unsigned int _port;		  // a port on which LMS should listen for data targeted to LME 
	const bool _local;				  // if the port forwarding is from local or from VPN as well (currently unsupported in Linux)
	const SOCKET _listeningSocket;	  // a listening socket created for the above port 
	const IsConnectionPermittedCallback _cb; // function that should check validity of a remote request (currently unsupported in Linux)
	PORT_FORWARD_REQUEST_STATUS _status;
	unsigned int _channelCount;	
};

#endif
