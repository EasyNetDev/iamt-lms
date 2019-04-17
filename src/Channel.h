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

#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include "PortForwardRequest.h"
#ifndef SOCKET
#define SOCKET int
#endif

/* 
	This Class represents a basic entity used by APF protocol (one between LME and LMS) for port forwarding
	Channel connects a socket on LMS side with a socket on LME side.
*/
class Channel
{
public:
	enum CHANNEL_STATUS {
		NOT_OPENED,
		OPEN,
		WAITING_CLOSE,
		CLOSED
	};

	static const unsigned int LMS_WINDOW_SIZE = 4095;

	Channel(PortForwardRequest *portForwardRequest, SOCKET socket) :
		_recipientChannel(0),
		_senderChannel(0),
		_socket(socket),
		_txWindow(0),
		_rxWindow(LMS_WINDOW_SIZE),
		_status(NOT_OPENED),
		_portForwardRequest(portForwardRequest) {}

	unsigned int GetRecipientChannel() const { return _recipientChannel; }
	unsigned int GetSenderChannel() const { return _senderChannel; }
	bool SetRecipientChannel(unsigned int recipientChannel) { _recipientChannel = recipientChannel; return true; }
	bool SetSenderChannel(unsigned int senderChannel) { _senderChannel = senderChannel; return true; }
	unsigned int GetTxWindow() const { return _txWindow; }
	unsigned int GetRxWindow() const { return _rxWindow; }

	bool AddBytesTxWindow(const int bytesToAdd)
	{
		if ((int)_txWindow + bytesToAdd < 0) {
			_txWindow = 0;
			return true;
		}
		_txWindow += bytesToAdd;
		return true;
	}

	bool AddBytesRxWindow(const int bytesToAdd)
	{
		if ((int)_rxWindow + bytesToAdd < 0) {
			_rxWindow = 0;
			return true;
		}
		_rxWindow = (_rxWindow + bytesToAdd > LMS_WINDOW_SIZE) ?
			(LMS_WINDOW_SIZE) :
			(_rxWindow + bytesToAdd);
		return true;
	}

	SOCKET GetSocket() const { return _socket; }
	CHANNEL_STATUS GetStatus() const { return _status; }
	bool SetStatus(const CHANNEL_STATUS newStatus) { _status = newStatus; return true; }
	PortForwardRequest * GetPortForwardRequest() const { return _portForwardRequest; }


private:
	unsigned int _recipientChannel; // represents an "external" side of LME socket i.e. created and accessible by LMS
	unsigned int _senderChannel;    // represents an "internal"  side of LME socket i.e. created and managed by LME
	const SOCKET _socket;			// an OS socket for which channel serves as a pipe
	unsigned int _txWindow;			// size of LMS-->LME data buffer - see APF protocol
	unsigned int _rxWindow;			// size of LME-->LMS data buffer 
	CHANNEL_STATUS _status;			// status of channel
	PortForwardRequest *_portForwardRequest; // context of the channel
};

#endif
