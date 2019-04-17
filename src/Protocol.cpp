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
#include <cerrno>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>
#include "strings.h"

#define _stprintf_s snprintf
#define strnicmp strncasecmp

#include <fstream>
#include <algorithm>
#include "Protocol.h"
#include "LMS_if.h"
#include "Lock.h"
#include "ATNetworkTool.h"


const LMEProtocolVersionMessage Protocol::MIN_PROT_VERSION(1, 0);
const LMEProtocolVersionMessage Protocol::MAX_PROT_VERSION(1, 0);

Protocol::Protocol() :
#if DEBUGLOG
_lme(true),
#else
_lme(false),
#endif
_rxSocketBuffer(NULL),
_rxSocketBufferSize(0),
_cfg(true)
{
	_serverSignalSocket = INVALID_SOCKET;
	_clientSignalSocket = INVALID_SOCKET;
	_sockets_active = false;
	_handshakingStatus = NOT_INITIATED;
	_pfwdService = NOT_STARTED;
	_AmtProtVersion.MajorVersion = 0;
	_AmtProtVersion.MinorVersion = 0;

	memset(_AMTFQDN, 0, sizeof(_AMTFQDN));
	memset(_HOSTFQDN, 0, sizeof(_AMTFQDN));
	_deinitReq = false;
	_listenFailReported.clear();
}

Protocol::~Protocol()
{
  if(IsInitialized())
  {
      _lme.Disconnect(APF_DISCONNECT_BY_APPLICATION);
	DeinitFull();
	_listenFailReported.clear();
  }  
  DestroySockets();
}

bool Protocol::Init(EventLogCallback cb, void *param)
{

  PRINT("Protocol::Init started\n");
	_eventLog = cb;
	_eventLogParam = param;

	DeinitFull();

	{
		Lock dl(_deinitLock);
		_deinitReq = false;
	}

	if (!_lme.Init(_LmeCallback, this)) {
		return false;
	}

	{
		Lock l(_versionLock);

		if (_handshakingStatus == NOT_INITIATED) {
			_lme.ProtocolVersion(MAX_PROT_VERSION);
			
			_handshakingStatus = INITIATED;
		}
	}

	if (!_cfg.Init(true)) 
	{
	     PRINT("Failed to Init Configuration\n");
	    _lme.Deinit();
	    return false;
	}

	_sendHostFQDN();
	long bufSize = _lme.GetMeiBufferSize() - sizeof(APF_CHANNEL_DATA_MESSAGE);
	if (bufSize > 0) {
		_rxSocketBuffer = new char[bufSize];
		_rxSocketBufferSize = bufSize;
	} else {
		DeinitFull();
		return false;
	}

 PRINT("Protocol::Init finished\n");
	return true;
}

Channel *Protocol::_getSockOpenChannel(SOCKET s)
{
  if(_socketToChannel.find(s) == _socketToChannel.end())
    return NULL;

  return _socketToChannel[s];
}

bool Protocol::IsDeInitialized()
{
	Lock dl(_deinitLock);
	return _deinitReq;
}


bool Protocol::IsInitialized()
{
	if (IsDeInitialized()) {
		return false;
	}

	return _lme.IsInitialized();
}

void Protocol::Deinit()
{
	Lock dl(_deinitLock);
	_deinitReq = true;

	ATNetworkTool::CloseSocket(_serverSignalSocket);
	ATNetworkTool::CloseSocket(_clientSignalSocket);

	{
		Lock l(_channelsLock);

		SocketToChannelMap::iterator it = _socketToChannel.begin();

		for (; it != _socketToChannel.end(); it++) {
			ATNetworkTool::CloseSocket(it->first);
			delete it->second;
		}
		
		_channelToSocket.clear();
		_socketToChannel.clear();
		_channelGenerator.Reset();
	}

	{
		Lock l(_portsLock);
		PortMap::iterator it = _openPorts.begin();

		for (; it != _openPorts.end(); it++) {
			if (it->second.size() > 0) {
				ATNetworkTool::CloseSocket(it->second[0]->GetListeningSocket());

				PortForwardRequestList::iterator it2 = it->second.begin();
				for (; it2 != it->second.end(); it2++) {
					delete *it2;
				}
				it->second.clear();
			}
		}
		_openPorts.clear();
	}

	_lme.Deinit();
	_cfg.Deinit();
	

	{
		Lock vl(_versionLock);
		_handshakingStatus = NOT_INITIATED;
		_pfwdService = NOT_STARTED;
		_AmtProtVersion.MajorVersion = 0;
		_AmtProtVersion.MinorVersion = 0;
	}

}

void Protocol::DeinitFull()
{
	Deinit();

	if (_rxSocketBuffer != NULL) {
		delete []_rxSocketBuffer;
		_rxSocketBuffer = NULL;
		_rxSocketBufferSize = 0;
	}

	_serverSignalSocket = INVALID_SOCKET;
	_clientSignalSocket = INVALID_SOCKET;
	_sockets_active = false;

	memset(_AMTFQDN, 0, sizeof(_AMTFQDN));
	memset(_HOSTFQDN, 0, sizeof(_HOSTFQDN));
}

bool Protocol::_checkListen(std::string address, in_port_t port, int &socket)
{
	bool exists = false;

	PortMap::iterator it = _openPorts.find(port);
	if (it != _openPorts.end()) {
		if (it->second.size() > 0) {
			socket = it->second[0]->GetListeningSocket();
			PortForwardRequestList::iterator it2 = it->second.begin();

			for (; it2 != it->second.end(); it2++) {
				if (((*it2)->GetStatus() != PortForwardRequest::NOT_ACTIVE) &&
				    ((*it2)->GetBindedAddress().compare(address) == 0)) {
					exists = true;
					break;
				}
			}

		}
	} else {
		PortForwardRequestList portForwardRequestList;
		_openPorts[port] = portForwardRequestList;
	}

	return exists;
}

int Protocol::_listenPort(in_port_t port, int &error)
{
	int family = PF_INET;
	struct stat bufFile;

	// Linux IPV6 module creates /proc/net/if_net6 so stat the file
	// to see if IPV6 is enabled in kernel
	if(stat("/proc/net/if_inet6", &bufFile) == 0) {
		family = PF_INET6;
	}

  // Only creating one server socket because Linux supports dual stack
  // IPV6/IPV4 so the IPV6 server socket accepts IPV4 connections
  // via IPv4-mapped addresses
	return ATNetworkTool::CreateServerSocket(
			port,
			error,
			false, true, family);
}

bool Protocol::CreateSockets()
{
	int error;
	_sockets_active = false;

	ATNetworkTool::CloseSocket(_serverSignalSocket);
	_serverSignalSocket = ATNetworkTool::CreateServerSocket((in_port_t)0, error, true);
	if (_serverSignalSocket == INVALID_SOCKET) {
		return false;
	}

	ATNetworkTool::CloseSocket(_clientSignalSocket);
	_clientSignalSocket = ATNetworkTool::ConnectToSocket(_serverSignalSocket, error);
	if (_clientSignalSocket == INVALID_SOCKET) {
		ATNetworkTool::CloseSocket(_serverSignalSocket);
		_serverSignalSocket = INVALID_SOCKET;
		return false;
	}

	struct sockaddr_storage addr;
	socklen_t addrLen = sizeof(addr);
	SOCKET s_new = accept(_serverSignalSocket, (struct sockaddr *)&addr, &addrLen);
	if (s_new == INVALID_SOCKET) {
		ATNetworkTool::CloseSocket(_serverSignalSocket);
		ATNetworkTool::CloseSocket(_clientSignalSocket);
		_serverSignalSocket = INVALID_SOCKET;
		_clientSignalSocket = INVALID_SOCKET;
		return false;
	}

	ATNetworkTool::CloseSocket(_serverSignalSocket);
	_serverSignalSocket = s_new;

	_sockets_active = true;
	return true;
}

void Protocol::DestroySockets()
{
	_sockets_active = false;

	if (_serverSignalSocket != INVALID_SOCKET) {
		ATNetworkTool::CloseSocket(_serverSignalSocket);
		_serverSignalSocket = INVALID_SOCKET;
	}
}

bool Protocol::_acceptConnection(SOCKET s, unsigned int port)
{
	ATAddress addr;
	int error = 0;
	char buf[NI_MAXHOST];

	if (!IsInitialized()) {
		return false;
	}

	SOCKET s_new = ATNetworkTool::Accept(s, addr, error);
	if (s_new == INVALID_SOCKET) {
#if DEBUGLOG
		const char *msg = _getErrMsg(error);
		PRINT("Error accepting new connection (%d): %s\n", error, msg);
#endif
		return false;
	}

	const char *addrStr = addr.inNtoP(buf, NI_MAXHOST);
	if (addrStr == NULL) {
		PRINT("Error: ntop failed for new connection\n");
		ATNetworkTool::CloseSocket(s_new);
		return false;
	}

	PortForwardRequest *portForwardRequest = NULL;

	//_portsLock is already aquired by the calling function: Select().
	PortMap::iterator it = _openPorts.find(port);
	if (it != _openPorts.end()) {
		PortForwardRequestList::iterator it2 = it->second.begin();

		for (; it2 != it->second.end(); it2++) {
			if (((*it2)->GetStatus() == PortForwardRequest::LISTENING) &&
				(1 == (*it2)->IsConnectionPermitted(this, s_new))) {
				portForwardRequest = *it2;
				break;
			}
		}

	}

	if (portForwardRequest == NULL) {
		PRINT("Error: new connection is denied (addr %s)\n", addrStr);
		ATNetworkTool::CloseSocket(s_new);
		return false;
	}

	{
		Channel *c = new Channel(portForwardRequest, s_new);
		c->SetStatus(Channel::NOT_OPENED);

		Lock l(_channelsLock);
		unsigned int newChannelID = _getNewChannel();
		if (newChannelID == ILLEGAL_CHANNEL) 
		{
#if DEBUGLOG
		  PRINT("Cannot generate a new channel");
#endif
		    return false;
		}
		c->SetSenderChannel(newChannelID);
		_socketToChannel[s_new] = c;
		_channelToSocket[newChannelID] = s_new;

		c->GetPortForwardRequest()->IncreaseChannelCount();

		std::string connectedIP;
		if (portForwardRequest->IsLocal()) {
			if (addr.family() == AF_INET)
				connectedIP = "127.0.0.1";
			else
				connectedIP = "::1";
			addrStr = connectedIP.c_str();
		} else
			connectedIP = addrStr;

		_lme.ChannelOpenForwardedRequest((UINT32) newChannelID,
			connectedIP,
			port,
			addrStr,
			addr.inPort());
		PRINT("Send channel open request to LME. Sender %d. addr: %s port: %d \n",
			(int)newChannelID, addrStr, port);
	}

	return true;
}

int Protocol::Select()
{
	fd_set rset;
	int res;
	int fdCount = 0;
	int fdMin = -1;

	FD_ZERO(&rset);

	FD_SET(_serverSignalSocket, &rset);
	if ((int)_serverSignalSocket > fdCount) {
		fdCount = (int)_serverSignalSocket;
	}

	{
		Lock l(_portsLock);
		PortMap::iterator it = _openPorts.begin();

		for (; it != _openPorts.end(); it++) {
			if (it->second.size() > 0) {
				SOCKET serverSocket = it->second[0]->GetListeningSocket();
				FD_SET(serverSocket, &rset);
				if ((int)serverSocket > fdCount) {
					fdCount = (int)serverSocket;
				}
			}
		}
	}

	{
		Lock l(_channelsLock);

		SocketToChannelMap::iterator it = _socketToChannel.begin();

		for (; it != _socketToChannel.end(); it++) {
			if ((it->second->GetStatus() == Channel::OPEN) &&
			    (it->second->GetTxWindow() > 0)) {
				SOCKET socket = it->first;
				FD_SET(socket, &rset);
				if ((int)socket > fdCount) {
					fdCount = (int)socket;
				}
				if ((fdMin == -1) || ((int)socket < fdMin)) {
					fdMin = (int)socket;
				}
			}
		}
	}

	fdCount++;
	res = select(fdCount, &rset, NULL, NULL, NULL);
	if (res == -1) {
#if DEBUGLOG
		int err = errno;


		const char *msg = _getErrMsg(err);
		PRINT("Select error (%d): %s\n", err, msg);
#endif
		return -1;
	}

	if (res == 0) {
		return 0;
	}

	if (!IsInitialized()) {
		return 0;
	}

	if (FD_ISSET(_serverSignalSocket, &rset)) {	// Received a 'signal'
		char c = 0;
		res = recv(_serverSignalSocket, &c, 1, 0);
		FD_CLR(_serverSignalSocket, &rset);
		res--;
	}

	{
		Lock l(_portsLock);
		PortMap::iterator it = _openPorts.begin();

		for (; it != _openPorts.end(); it++) {
			if (it->second.size() > 0) {
				SOCKET serverSocket = it->second[0]->GetListeningSocket();
				if (FD_ISSET(serverSocket, &rset)) {
					// connection request
					PRINT("Connection requested on port %d\n", it->first);
					_acceptConnection(serverSocket, it->first);
					FD_CLR(serverSocket, &rset);
					res--;
				}
			}
		}
	}

	int i;
	for (i = fdMin/*0*/; (res > 0) && (i < fdCount); i++) {
		if (FD_ISSET(i, &rset)) {
			_rxFromSocket(i);
			res--;
		}
	}

	return 1;
}

int Protocol::_rxFromSocket(SOCKET s)
{
	Channel *c = NULL;

	if (!IsInitialized()) {
		return 0;
	}

	{
		Lock l(_channelsLock);

		Channel *cx = _getSockOpenChannel(s);

		if (cx == NULL) {
			// Data received from a socket that is not in the map.
			// Since we only select on our sockets, this means it was
			// in the map, but was removed, probably because we received
			// an End Connection message from the MEI.
			return 0;
		}

		c = new Channel(*cx);
	}

	int res;

	int len = std::min(c->GetTxWindow(), _rxSocketBufferSize);
	res = recv(s, _rxSocketBuffer, len, 0);
	if (res > 0) {
		// send data to LME
		PRINT("Received %d bytes from socket %d. Sending to LME\n", res, (int)s);

		_lme.ChannelData(c->GetRecipientChannel(), res, (unsigned char *)_rxSocketBuffer);
		
		goto out;
	} else if (res == 0) {
		// connection closed
		PRINT("Received 0 bytes from socket %d.\n", (int)s);
		goto out;
	} else {
#if DEBUGLOG
		int err = errno;

		const char *msg = _getErrMsg(err);
		PRINT("Receive error on socket %d (%d): %s\n", (int)s, err, msg);
#endif
		goto out;
	}

out:
	{
		Lock l(_channelsLock);

		Channel *cx = _getSockOpenChannel(s);

		if (cx == NULL) {
			// Data received from a socket that is not in the map.
			// Since we only select on our sockets, this means it was
			// in the map, but was removed, probably because we received
			// an End Connection message from the MEI.
			delete c;
			return 0;
		}
		if (res > 0) {
			cx->AddBytesTxWindow(-res);
		}
		else {
			cx->SetStatus(Channel::WAITING_CLOSE);
			_lme.ChannelClose(c->GetRecipientChannel(), c->GetSenderChannel());
		}
	}
	delete c;

	return 0;
}

void Protocol::SignalSelect()
{
	if (_clientSignalSocket != INVALID_SOCKET)
		_signalSelect();
}

void Protocol::_signalSelect()
{
	int senderr = 0;

	_send(_clientSignalSocket, "s", 1, senderr); //Enforce a new execution of Select()
}

void Protocol::_closePortForwardRequest(PortForwardRequest *p)
{
	PortMap::iterator it = _openPorts.find(p->GetPort());
	if (it == _openPorts.end()) {
		return;
	}

	bool found = false;
	PortForwardRequestList::iterator it2 = it->second.begin();
	for (; it2 != it->second.end(); it2++) {
		if ((*it2) == p) {
			found = true;
			break;
		}
	}

	if (!found) {
		PRINT("Port forwarding request doesn't exist\n");
		return;
	}

	if ((*it2)->GetStatus() == PortForwardRequest::NOT_ACTIVE) {

		SOCKET serverSocket = (*it2)->GetListeningSocket();
		delete (*it2);
		it->second.erase(it2);

		if (it->second.size() == 0) {
			int res = ATNetworkTool::CloseSocket(serverSocket);
			if (res != 0)
			{
				PRINT("Error %d in closing server socket at port %d.\n",errno, p->GetPort());
			}
			_openPorts.erase(it);
		}
	}
}

bool Protocol::_checkProtocolFlow(LMEMessage *message)
{
	switch (message->MessageType) {
	case APF_SERVICE_REQUEST:
	case APF_USERAUTH_REQUEST:
		{
			Lock l(_versionLock);
			if (_handshakingStatus != AGREED) {
				_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
				Deinit();
				return false;
			}
			return true;
		}
		break;

	case APF_GLOBAL_REQUEST:
	case APF_CHANNEL_OPEN:
	case APF_CHANNEL_OPEN_CONFIRMATION:
	case APF_CHANNEL_OPEN_FAILURE:
	case APF_CHANNEL_CLOSE:
	case APF_CHANNEL_DATA:
	case APF_CHANNEL_WINDOW_ADJUST:
		{
			Lock l(_versionLock);
			if ((_handshakingStatus != AGREED) || (_pfwdService != STARTED)) {
				_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
				Deinit();
				return false;
			}
			return true;
		}
		//break;

	case APF_DISCONNECT:
	case APF_PROTOCOLVERSION:
		return true;
		break;

	default:
		{
			_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
			Deinit();
			return false;
		}
		break;
	}

	return false;
}

unsigned int Protocol::_getMinMessageLen(LMEMessage *message)
{
	switch (message->MessageType) {
	case APF_SERVICE_REQUEST:
		return sizeof(LMEServiceRequestMessage);
		break;
	case APF_USERAUTH_REQUEST:
		return sizeof(LMEUserAuthRequestMessage);
		break;
	case APF_GLOBAL_REQUEST:
		return sizeof(LMEGlobalRequestMessage);
		break;
	case APF_CHANNEL_OPEN:
		return sizeof(LMEChannelOpenRequestMessage);
		break;
	case APF_CHANNEL_OPEN_CONFIRMATION:
		return sizeof(LMEChannelOpenReplySuccessMessage);
		break;
	case APF_CHANNEL_OPEN_FAILURE:
		return sizeof(LMEChannelOpenReplyFailureMessage);
		break;
	case APF_CHANNEL_CLOSE:
		return sizeof(LMEChannelCloseMessage);
		break;
	case APF_CHANNEL_DATA:
		return sizeof(LMEChannelDataMessage);
		break;
	case APF_CHANNEL_WINDOW_ADJUST:
		return sizeof(LMEChannelWindowAdjustMessage);
		break;
	case APF_DISCONNECT:
		return sizeof(LMEDisconnectMessage);
		break;
	case APF_PROTOCOLVERSION:
		return sizeof(LMEProtocolVersionMessage);
		break;
	default:
		return 0;
	}

	return 0;
}

bool Protocol::_checkMessageAndProtocol(LMEMessage *message, unsigned int len)
{
	if (len < sizeof(LMEMessage)) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return false;
	}

	if (!_checkProtocolFlow(message)) {
		return false;
	}
	if (len < _getMinMessageLen(message)) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return false;
	}
	return true;
}

void Protocol::_LmeCallback(void *param, void *buffer, unsigned int len, int *status)
{
	Protocol *prot = (Protocol *)param;

	prot->_LmeReceive(buffer, len, status);
}

void Protocol::_LmeReceive(void *buffer, unsigned int len, int *status)
{
	LMEMessage *message = (LMEMessage *)buffer;
	*status = 0;

	if (!_checkMessageAndProtocol(message, len)) {
		return;
	}

	switch (message->MessageType) {
	case APF_DISCONNECT:
		{
			PRINT("LME requested to disconnect with reason code 0x%08x\n",
				((LMEDisconnectMessage *)message)->ReasonCode);
			Deinit();
			return;
		}
		break;

	case APF_SERVICE_REQUEST:
		{
			LMEServiceRequestMessage *sRMsg =
				(LMEServiceRequestMessage *)message;

			if ((sRMsg->ServiceName.compare(APF_SERVICE_AUTH) == 0) ||
				(sRMsg->ServiceName.compare(APF_SERVICE_PFWD) == 0)) {

				_lme.ServiceAccept(sRMsg->ServiceName);
				PRINT("Accepting service: %s\n",
					sRMsg->ServiceName.c_str());
				if (sRMsg->ServiceName.compare(APF_SERVICE_PFWD) == 0) {
					Lock l(_versionLock);
					_pfwdService = STARTED;
				}
			} else {
				PRINT("Requesting to disconnect from LME with reason code 0x%08x\n",
					APF_DISCONNECT_SERVICE_NOT_AVAILABLE);
				_lme.Disconnect(APF_DISCONNECT_SERVICE_NOT_AVAILABLE);
				Deinit();
				return;
			}
		}
		break;

	case APF_USERAUTH_REQUEST:
		{
			PRINT("Sending Userauth success message\n");
			_lme.UserAuthSuccess();
		}
		break;

	case APF_PROTOCOLVERSION:
		_apfProtocolVersion((LMEProtocolVersionMessage *)message);
		break;

	case APF_GLOBAL_REQUEST:
		_apfGlobalRequest((LMEGlobalRequestMessage *)message, len, status);
		break;

	case APF_CHANNEL_OPEN:
		_apfChannelOpen((LMEChannelOpenRequestMessage *)message, status);
		break;

	case APF_CHANNEL_OPEN_CONFIRMATION:
		{
			LMEChannelOpenReplySuccessMessage *chOpenSuccMsg =
				(LMEChannelOpenReplySuccessMessage *)message;

			Lock l(_channelsLock);

			ChannelToSocketMap::iterator it = _channelToSocket.find(chOpenSuccMsg->RecipientChannel);
			if (it != _channelToSocket.end()) {
			        Channel *c = _socketToChannel[it->second];
				c->SetStatus(Channel::OPEN);
				c->SetRecipientChannel(chOpenSuccMsg->SenderChannel);
				PRINT("Established new channel. Recipient: %d. Sender: %d\n", 
				      c->GetRecipientChannel(), c->GetSenderChannel());
				c->AddBytesTxWindow(chOpenSuccMsg->InitialWindow);
			}

			_signalSelect();
		}
		break;

	case APF_CHANNEL_OPEN_FAILURE:
		{
			PortForwardRequest *clPFwdReq =
				_apfChannelOFail((LMEChannelOpenReplyFailureMessage *)message);
			if (clPFwdReq != NULL) {
				Lock l(_portsLock);
				_closePortForwardRequest(clPFwdReq);
			}
		}
		break;

	case APF_CHANNEL_CLOSE:
		{
			PortForwardRequest *clPFwdReq =
				_apfChannelClose((LMEChannelCloseMessage *)message);
			if (clPFwdReq != NULL) {
				Lock l(_portsLock);
				_closePortForwardRequest(clPFwdReq);
			}
		}
		break;

	case APF_CHANNEL_DATA:
		{
			PortForwardRequest *clPFwdReq =
				_apfChannelData((LMEChannelDataMessage *)message, status);
			if (clPFwdReq != NULL) {
				Lock l(_portsLock);
				_closePortForwardRequest(clPFwdReq);
			}
		}
		break;

	case APF_CHANNEL_WINDOW_ADJUST:
		{
			LMEChannelWindowAdjustMessage *channelWindowMessage = (LMEChannelWindowAdjustMessage *)message;

			Lock l(_channelsLock);

			ChannelToSocketMap::iterator it = _channelToSocket.find(channelWindowMessage->RecipientChannel);
			if (it != _channelToSocket.end()) {
			        Channel *c = _socketToChannel[it->second];
				c->AddBytesTxWindow(channelWindowMessage->BytesToAdd);
				_signalSelect();
			}
		}
		break;

	default:
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		break;
	}
}

unsigned int Protocol::_getMinGlobalMsgLen(LMEGlobalRequestMessage *globalMessage)
{
	switch (globalMessage->RequestType) {
	case LMEGlobalRequestMessage::TCP_FORWARD_REQUEST:
		return sizeof(LMETcpForwardRequestMessage);
		break;
	case LMEGlobalRequestMessage::TCP_FORWARD_CANCEL_REQUEST:
		return sizeof(LMETcpForwardCancelRequestMessage);
		break;
	case LMEGlobalRequestMessage::UDP_SEND_TO:
		return sizeof(LMEUdpSendToMessage);
		break;
	default:
		return 0;
	}
	return 0;
}

void Protocol::_apfGlobalRequest(LMEGlobalRequestMessage *globalMessage,
				 unsigned int len, int *status)
{
	PRINT("Global Request type 0x%02x\n", globalMessage->RequestType);

	if (len < _getMinGlobalMsgLen(globalMessage)) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return;
	}

	switch (globalMessage->RequestType) {
	case LMEGlobalRequestMessage::TCP_FORWARD_REQUEST:
		_apfTcpForwardRequest((LMETcpForwardRequestMessage *)globalMessage, status);
		break;

	case LMEGlobalRequestMessage::TCP_FORWARD_CANCEL_REQUEST:
		_apfTcpForwardCancel((LMETcpForwardCancelRequestMessage *)globalMessage);
		break;

	case LMEGlobalRequestMessage::UDP_SEND_TO:
		_aptSendUdp((LMEUdpSendToMessage *)globalMessage, status);
		break;

	default:
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		break;
	}
}

void Protocol::_apfTcpForwardRequest(LMETcpForwardRequestMessage *tcpFwdReqMsg, int *status)
{
	bool failure = false;

	if ((tcpFwdReqMsg->Address.compare("0.0.0.0") == 0) || // attempt to use VPN
	    (tcpFwdReqMsg->Address.compare("::") == 0))        // currently not supported in Linux
	
	{		// Send failure reply to LME
			TCHAR message[1024];
			static bool loggedEvent = false;
			_stprintf_s(message, 1024,TEXT("Host VPN not supported. Denying request from Intel AMT."));
			if (!loggedEvent)
			{
			  _eventLog(_eventLogParam, message, EVENTLOG_ERROR_TYPE);
			  loggedEvent = true;
			}
			PRINT(message);
			_lme.TcpForwardReplyFailure();
			return;
	}

	IsConnectionPermittedCallback cb = _isLocalCallback;
	

	{
		Lock l(_portsLock);
		SOCKET serverSocket = INVALID_SOCKET;
		listenPortSet::iterator lpi;

		if (_checkListen(tcpFwdReqMsg->Address, tcpFwdReqMsg->Port, serverSocket)) {
			*status = 1;
			// Log in Event Log
			TCHAR message[1024];
			_stprintf_s(message, 1024,
				TEXT("LMS Service already accepted a request at %s:%d\n"),
				tcpFwdReqMsg->Address.c_str(),
				tcpFwdReqMsg->Port);
			_eventLog(_eventLogParam, message, EVENTLOG_ERROR_TYPE);
			PRINT(message);
			// Send failure reply to LME
			_lme.TcpForwardReplyFailure();
			return;
		}

		lpi = _listenFailReported.find(tcpFwdReqMsg->Port);

		if (serverSocket == INVALID_SOCKET) {
			int error;
			serverSocket = _listenPort(tcpFwdReqMsg->Port, error);
			if (serverSocket == INVALID_SOCKET) {
				*status = 1;
				// Log in Event Log
				TCHAR message[1024];
				_stprintf_s(message, 1024,
					TEXT("LMS Service cannot listen at port %d.\n"),
					tcpFwdReqMsg->Port);
				if (lpi == _listenFailReported.end()) {
					_eventLog(_eventLogParam, message, EVENTLOG_ERROR_TYPE);
					_listenFailReported.insert(tcpFwdReqMsg->Port);
				}
				PRINT(message);
				// Send failure reply to LME
				_lme.TcpForwardReplyFailure();
				failure = true;
			}
		}

		if (failure != true) {
			PRINT("Listening at port %d at %s interface.\n",
				tcpFwdReqMsg->Port,
				((cb == _isLocalCallback) ? "local" : "remote"));

			PortForwardRequest *portForwardRequest =
				new PortForwardRequest(tcpFwdReqMsg->Address,
					tcpFwdReqMsg->Port,
					serverSocket, cb, (cb == _isLocalCallback));

			_openPorts[tcpFwdReqMsg->Port].push_back(portForwardRequest);

			// Send success reply to LME
			_lme.TcpForwardReplySuccess(tcpFwdReqMsg->Port);

			portForwardRequest->SetStatus(
				(cb == _isLocalCallback) ?
				PortForwardRequest::LISTENING :
				PortForwardRequest::PENDING_REQUEST);
			if (lpi != _listenFailReported.end()) {
				_listenFailReported.erase(lpi);
			}

			_signalSelect();
		}
	}

	if (failure == true) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return;
	}

	if (cb == _isLocalCallback) { //only for local connection
		if (_listenFailReported.empty()) { // leave if for future needs
			_updateIPFQDN(tcpFwdReqMsg->Address.c_str());
		}
	}
}

void Protocol::_apfTcpForwardCancel(LMETcpForwardCancelRequestMessage *tcpFwdCnclMsg)
{
	bool found = false;
	Lock l(_portsLock);

	PortMap::iterator it = _openPorts.find(tcpFwdCnclMsg->Port);
	if (it == _openPorts.end()) {
		PRINT("Previous request on address %s and port %d doesn't exist.\n",
			tcpFwdCnclMsg->Address.c_str(), tcpFwdCnclMsg->Port);
		_lme.TcpForwardCancelReplyFailure();
		return;
	}

	PortForwardRequestList::iterator it2 = it->second.begin();
	for (; it2 != it->second.end(); it2++) {
		if (((*it2)->GetBindedAddress().compare(tcpFwdCnclMsg->Address) == 0) &&
			((*it2)->GetStatus() != PortForwardRequest::NOT_ACTIVE)) {
				found = true;
				break;
		}
	}

	if (found) {
		(*it2)->SetStatus(PortForwardRequest::NOT_ACTIVE);
			if ((*it2)->GetChannelCount() == 0) {
			_closePortForwardRequest(*it2);
		}
		_lme.TcpForwardCancelReplySuccess();
	} else {
		PRINT("Previous request on address %s and port %d doesn't exist.\n",
			tcpFwdCnclMsg->Address.c_str(), tcpFwdCnclMsg->Port);
		_lme.TcpForwardCancelReplyFailure();
	}
}

void Protocol::_aptSendUdp(LMEUdpSendToMessage *udpSendToMessage, int *status)
{
	int error = 0;

	SOCKET s = ATNetworkTool::Connect(udpSendToMessage->Address.c_str(),
					  udpSendToMessage->Port, error,
					  PF_UNSPEC, SOCK_DGRAM);
	if (s == INVALID_SOCKET) {
		*status = 1;
		PRINT("Unable to send UDP data.\n");
		return;
	}

	int count = _send(s, (char *)udpSendToMessage->Data, udpSendToMessage->DataLength, error);
	if (count >= 0)
	{
		PRINT("Sent UDP data: %d bytes of %d.\n", count, udpSendToMessage->DataLength);
	}
	else
	{
			PRINT("Unable to send UDP data.\n");
	}

	ATNetworkTool::CloseSocket(s);
}

void Protocol::_apfProtocolVersion(LMEProtocolVersionMessage *verMsg)
{
	Lock l(_versionLock);

	switch (_handshakingStatus) {
	case AGREED:
	case NOT_INITIATED:
		_lme.ProtocolVersion(MAX_PROT_VERSION);
	case INITIATED:
		if (*verMsg < MIN_PROT_VERSION) {
			PRINT("Version %d.%d is not supported.\n",
				verMsg->MajorVersion, verMsg->MinorVersion);
			_lme.Disconnect(APF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
			Deinit();
			return;
		}
		if (*verMsg > MAX_PROT_VERSION) {
			_AmtProtVersion = MAX_PROT_VERSION;
		} else {
			_AmtProtVersion = (*verMsg);
		}
		_handshakingStatus = AGREED;
		break;

	default:
		_lme.Disconnect(APF_DISCONNECT_BY_APPLICATION);
		Deinit();
		break;
	}
}

unsigned int  Protocol::_getNewChannel()
{
	return _channelGenerator.GenerateChannel();
}

void Protocol::_removeFromMaps(Channel *c)
{
	SOCKET s = c->GetSocket();
	_channelToSocket.erase(c->GetSenderChannel());
	_socketToChannel.erase(s);
}
void Protocol::_UNSConnection()
{
	PRINT("UNS event\n");
}
int Protocol::_sendHostFQDN()
{
	char localName[FQDN_MAX_SIZE] = "\0";
	gethostname(localName, sizeof(localName));
	hostent *s=gethostbyname(localName);
	if ((s != NULL) && (strcmp(s->h_name, _HOSTFQDN) != 0))
	{
		_cfg.SendHostFQDN(s->h_name);
		memcpy(_HOSTFQDN, s->h_name, sizeof(_HOSTFQDN));
		return 0;
	}
	return -1;
}
void Protocol::_apfChannelOpen(LMEChannelOpenRequestMessage *chOpenMsg, int *status)
{
	int error = 0;

	PRINT("Got channel request from Intel AMT. "
		" Recipient channel %d for address %s, port %d.\n",
		chOpenMsg->SenderChannel,
		chOpenMsg->Address.c_str(), chOpenMsg->Port);
	if(chOpenMsg->Port==0)
	{
			_UNSConnection();
			_sendHostFQDN();
			return;
	}
	SOCKET s = ATNetworkTool::Connect(chOpenMsg->Address.c_str(),
					  chOpenMsg->Port, error, PF_UNSPEC);
	if (s == INVALID_SOCKET) {
		*status = 1;
		PRINT("Unable to open direct channel to address %s.\n",
			chOpenMsg->Address.c_str());
		return;
	}

	ATNetworkTool::SetNonBlocking(s);

	Channel *c = new Channel(NULL, s);
	c->AddBytesTxWindow(chOpenMsg->InitialWindow);
	c->SetRecipientChannel(chOpenMsg->SenderChannel);

	c->SetStatus(Channel::OPEN);

	{
		Lock l(_channelsLock);
		unsigned int newChannelID = _getNewChannel();
		PRINT("new channel id: %d\n",newChannelID);
		if (newChannelID == ILLEGAL_CHANNEL)
		{
		    *status = 1;
		    PRINT("Unable to allocate a new channel.\n");
		    return;
		}
		c->SetSenderChannel(newChannelID);
		_socketToChannel[s] = c;
		_channelToSocket[newChannelID] = s;
	        _lme.ChannelOpenReplySuccess(c->GetRecipientChannel(), c->GetSenderChannel());
	}

	_signalSelect();
}

PortForwardRequest *Protocol::_closeMChannel(Channel *c)
{
	PortForwardRequest *clPFwdReq = NULL;

	ATNetworkTool::CloseSocket(c->GetSocket());
	PortForwardRequest *p = c->GetPortForwardRequest();
	if ((p != NULL) && (p->DecreaseChannelCount() == 0)) {
		clPFwdReq = p;
	}
	delete c;

	return clPFwdReq;
}

PortForwardRequest *Protocol::_apfChannelOFail(LMEChannelOpenReplyFailureMessage *chFailMsg)
{
	PortForwardRequest *clPFwdReq = NULL;

	Lock l(_channelsLock);

	ChannelToSocketMap::iterator it = _channelToSocket.find(chFailMsg->RecipientChannel);
	if (it != _channelToSocket.end()) 
	{
		SOCKET s = it->second;
		Channel* c = _socketToChannel[s];

		_removeFromMaps(c);
		_channelGenerator.FreeChannel(c->GetSenderChannel());
		clPFwdReq = _closeMChannel(c);
		
		
		PRINT("Channel open request was refused. Reason code: 0x%02x reason.\n",
			chFailMsg->ReasonCode);
	}

	return clPFwdReq;
}

PortForwardRequest *Protocol::_apfChannelClose(LMEChannelCloseMessage *chClMsg)
{
	PortForwardRequest *clPFwdReq = NULL;

	Lock l(_channelsLock);
	PRINT("_apfChannelClose: RecipientChannel=%d\n",chClMsg->RecipientChannel);


	ChannelToSocketMap::iterator it = _channelToSocket.find(chClMsg->RecipientChannel);
	if (it != _channelToSocket .end()) 
	{
	        SOCKET s = it->second;
		Channel *c = _socketToChannel[s];
		switch(c->GetStatus()) {
		case Channel::OPEN:
			c->SetStatus(Channel::CLOSED);
			
			_lme.ChannelClose(c->GetRecipientChannel(), c->GetSenderChannel());
			PRINT("Channel %d was closed by Intel AMT.\n", c->GetSenderChannel());
			break;

		case Channel::WAITING_CLOSE:
			PRINT("Received reply by Intel AMT on closing channel %d.\n", c->GetSenderChannel());
			break;

		case Channel::CLOSED:
		case Channel::NOT_OPENED:
			break;
		}

		_removeFromMaps(c);
		clPFwdReq = _closeMChannel(c);

	}

	_channelGenerator.FreeChannel(chClMsg->RecipientChannel);
	
	return clPFwdReq;
}

PortForwardRequest *Protocol::_apfChannelData(LMEChannelDataMessage *chDMsg, int *status)
{
	PortForwardRequest *clPFwdReq = NULL;

	do {
		Lock l(_channelsLock);

	        ChannelToSocketMap::iterator it = _channelToSocket.find(chDMsg->RecipientChannel);
		if (it == _channelToSocket.end()) 
			break;
	       
		
		Channel* channel = _socketToChannel[it->second];
		
		if ((channel->GetStatus() != Channel::OPEN) &&
		    (channel->GetStatus() != Channel::WAITING_CLOSE)) {
			break;
		}

		if (channel->GetRxWindow() < chDMsg->DataLength) {
			break;
		}

		int senderr = 0;
		int count = _send(channel->GetSocket(), (char *)chDMsg->Data,
				chDMsg->DataLength, senderr);
		PRINT("Sent %d bytes of %d from Intel AMT to channel %d with socket %d.\n",
			count, chDMsg->DataLength, chDMsg->RecipientChannel,
			channel->GetSocket());

		if ((count == -1) && (senderr == EPIPE)) {
			*status = 1;
			_removeFromMaps(channel);
			//_channelGenerator.FreeChannel(channel->GetSenderChannel());
			clPFwdReq = _closeMChannel(channel);
			
			PRINT("Channel send data request was refused. Broken pipe.\n");
			break;
		}
		_lme.ChannelWindowAdjust(channel->GetRecipientChannel(), chDMsg->DataLength);
	} while (0);

	return clPFwdReq;
}

int Protocol::_isLocalCallback(void *const param, SOCKET s)
{
	int error = 0;
	int family = AF_INET;
	struct stat bufFile;

	PRINT("local check started\n");
	// Linux IPV6 module creates /proc/net/if_net6 so stat the file
	// to see if IPV6 is enabled in kernel
	if(stat("/proc/net/if_inet6", &bufFile) == 0) {
		family = AF_UNSPEC;
	}

	int ret = ((1 == ATNetworkTool::IsSockPeerLocal(s, error, family)) ? 1 : -1);
	PRINT("local check finished\n");
	return ret;
}

int Protocol::_updateIPFQDN(const char *fqdn)
{
	if (strcmp(fqdn, _AMTFQDN) != 0) {
		char localName[FQDN_MAX_SIZE] = "\0";
		int res = gethostname(localName, sizeof(localName));
		hostent *s=gethostbyname(localName);
		// If AMT FQDN is equal to local FQDN then we don't do anything
		if ((s == NULL) || (res == -1) || (strcasecmp(fqdn, s->h_name) != 0)) {
			if (_handleFQDNChange(fqdn) < 0) {
				ERROR("Error: failed to update FQDN info\n");
				return -1;
			}
		} else {
			if (_handleFQDNChange("") < 0) {
				ERROR("Error: failed to update FQDN info\n");
				return -1;
			}
		}
	}

	memcpy(_AMTFQDN, fqdn, sizeof(_AMTFQDN));

	PRINT("Got FQDN: %s\n", _AMTFQDN);

	return 0;
}


const char *Protocol::_getErrMsg(DWORD err)
{
	static char buffer[1024];

	return strerror_r(err, buffer, sizeof(buffer) - 1);
}


int Protocol::_handleFQDNChange(const char *fqdn)
{
	const char *hostFile = "hosts";
	const char *tmpFile = "hosts-lms.tmp";
	bool hasFqdn4 = false;
	bool hasFqdn6 = false;
	bool hasOldFqdn=false;
#define LMS_MAX_FILENAME_LEN 1024
	char inFileName[LMS_MAX_FILENAME_LEN] = "";
	char oldFqdn[FQDN_MAX_SIZE + 1];
	char outFileName[LMS_MAX_FILENAME_LEN] = "";
	char host[FQDN_MAX_SIZE + 1];
#define LMS_MAX_LINE_LEN 1023
	char line[LMS_MAX_LINE_LEN + 1];
#define LMS_LINE_SIG_FIRST_WORDS(a) "# LMS GENERATED " a " "
#define LMS_LINE_SIG_LAST_WORD "LINE"
#define LMS_LINE_SIG_LAST_WORD_LEN 4
#define LMS_LINE_SIG(a) LMS_LINE_SIG_FIRST_WORDS(a) LMS_LINE_SIG_LAST_WORD
#define lmsstr(s) lmsname(s)
#define lmsname(s) #s
#define LMS_LINE_FORMAT_IPV4 "127.0.0.1       %s %s " LMS_LINE_SIG("IPv4")
#define LMS_LINE_FORMAT_IPV6 "::1             %s %s " LMS_LINE_SIG("IPv6")
#define LMS_LINE_SCAN_FORMAT_IPV4 "127.0.0.1 %" lmsstr(FQDN_MAX_SIZE) "s %" lmsstr(FQDN_MAX_SIZE) "s " LMS_LINE_SIG_FIRST_WORDS("IPv4") "%" lmsstr(LMS_LINE_SIG_LAST_WORD_LEN) "c"
#define LMS_LINE_SCAN_FORMAT_IPV6 "::1       %" lmsstr(FQDN_MAX_SIZE) "s %" lmsstr(FQDN_MAX_SIZE) "s " LMS_LINE_SIG_FIRST_WORDS("IPv6") "%" lmsstr(LMS_LINE_SIG_LAST_WORD_LEN) "c"
	char tmpsige[LMS_LINE_SIG_LAST_WORD_LEN];

	const char *dir = "/etc/";
	struct stat bufFile;
	bool has_ipv6 = false;

     	// Linux IPV6 module creates /proc/net/if_net6 so stat the file
     	// to see if IPV6 is enabled in kernel
     	if(stat("/proc/net/if_inet6", &bufFile) == 0) {
        	has_ipv6 = true;
     	}

	strncat(inFileName, dir, LMS_MAX_FILENAME_LEN - 1);
	strncat(outFileName, dir, LMS_MAX_FILENAME_LEN - 1);
	strncat(inFileName, hostFile, LMS_MAX_FILENAME_LEN - 1);
	strncat(outFileName, tmpFile, LMS_MAX_FILENAME_LEN - 1);

	FILE *ifp = fopen(inFileName, "r");
	if (NULL == ifp) {
		_eventLog(_eventLogParam, TEXT("Error: Can't open hosts file"), EVENTLOG_ERROR_TYPE);
		return -1;
	}

	FILE *ofp = fopen(outFileName, "w");
	if (NULL == ofp) {
		_eventLog(_eventLogParam, TEXT("Error: Can't create temporary hosts file"), EVENTLOG_ERROR_TYPE);
		fclose(ifp);
		return -1;
	}

	// First create a copy of the hosts file, without lines that were
	// previously added by the LMS.
	// Go over each line and copy it to the tmp file.
	while (fgets(line, sizeof(line), ifp)) {
		// don't copy the line if it was generated by the LMS
		memset(oldFqdn, 0, sizeof(oldFqdn));
		memset(tmpsige, 0, sizeof(tmpsige));
		if (0 == (
		    (3 == sscanf(line, LMS_LINE_SCAN_FORMAT_IPV4, oldFqdn, host, tmpsige))
		    ? strncmp(tmpsige, LMS_LINE_SIG_LAST_WORD, LMS_LINE_SIG_LAST_WORD_LEN)
		    : (-2))
		) {
			hasOldFqdn=true;
			if (0 == strncmp((char *)fqdn, oldFqdn, FQDN_MAX_SIZE)) {
				// copy the old LMS line too, since it's up to date
				fprintf(ofp, "%s", line);
				hasFqdn4 = true;
			}
			continue;
		}

		if (0 == (
		    (3 == sscanf(line, LMS_LINE_SCAN_FORMAT_IPV6, oldFqdn, host, tmpsige))
		    ? strncmp(tmpsige, LMS_LINE_SIG_LAST_WORD, LMS_LINE_SIG_LAST_WORD_LEN)
		    : (-2))
		) {
			if (0 == strncmp((char *)fqdn, oldFqdn, FQDN_MAX_SIZE)) {
				// copy the old LMS line too, since it's up to date
				if(has_ipv6){
					fprintf(ofp, "%s", line);
				}
				hasFqdn6 = true;
			}
			continue;
		}

		fprintf(ofp, "%s", line);

		while ((LMS_MAX_LINE_LEN == strnlen(line, LMS_MAX_LINE_LEN))
		    && ('\n' != line[LMS_MAX_LINE_LEN - 1])
		    && (fgets(line, sizeof(line), ifp))) {
			fprintf(ofp, "%s", line);
		}
	}

     if ((hasFqdn4 && (hasFqdn6 == has_ipv6)) || (!hasOldFqdn && fqdn[0]==0)) {		
		fclose(ofp);
		fclose(ifp);
		unlink(outFileName);
		return 0;
	}

	// If the original hosts file does not end with a new line character,
	// add a new line at the end of the new file before adding our line.
	fseek(ifp, -1, SEEK_END);
	char lastChar = fgetc(ifp);
	if ('\n' != lastChar) {
		fprintf(ofp, "\n");
	}

	memset(host, 0, FQDN_MAX_SIZE + 1);
	strncpy(host, fqdn, FQDN_MAX_SIZE);
	char *lmsdot = strchr(host, '.');
	if (NULL != lmsdot) {
		lmsdot[0] = '\0';
	}

	if ((fqdn != NULL) && (fqdn[0] != 0)) {
		// Add the specified FQDN to the end of the tmp file
		if(!hasFqdn4)
			fprintf(ofp, LMS_LINE_FORMAT_IPV4 "\n", fqdn, host);
		if(!hasFqdn6 && has_ipv6)
			fprintf(ofp, LMS_LINE_FORMAT_IPV6 "\n", fqdn, host);
	}

	fclose(ofp);
	fclose(ifp);

	if (0 != std::rename(outFileName, inFileName)) {
		std::string tmp2FileName = std::string(inFileName) + ".~tmp";
		std::ifstream mfile(inFileName, std::ios_base::in);
		if (!mfile.is_open()) {
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [1]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		std::ofstream wfile(tmp2FileName.c_str(), std::ios_base::out | std::ios_base::trunc);
		if (!wfile.is_open()) {
			mfile.close();
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [2]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		wfile << mfile.rdbuf();
		if (wfile.bad()) {
			mfile.close();
			wfile.close();
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [3]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		mfile.close();
		wfile.close();
		std::ifstream sfile(outFileName, std::ios_base::in);
		if (!sfile.is_open()) {
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [4]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		std::ofstream dfile(inFileName, std::ios_base::out | std::ios_base::trunc);
		if (!dfile.is_open()) {
			sfile.close();
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [5]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		dfile << sfile.rdbuf();
		if (dfile.bad()) {
			sfile.close();
			dfile.close();
			unlink(inFileName);
			if (0 != std::rename(outFileName, inFileName)) {
				std::rename(tmp2FileName.c_str(), inFileName);
				_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [6]"), EVENTLOG_ERROR_TYPE);
				return -1;
			}
		}
		sfile.close();
		dfile.close();
	}

	_eventLog(_eventLogParam, TEXT("hosts file updated"), EVENTLOG_INFORMATION_TYPE);

	return 0;
}

ssize_t Protocol::_send(int s, const void *buf, size_t len, int &senderr)
{
	ssize_t result;

	if (-1 == (result = send(s, buf, len, MSG_NOSIGNAL))) {
		senderr = errno;
	}

	return result;
}
