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

#include "ATNetworkTool.h"
#include <sstream>
#include <algorithm>
#include <cerrno>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>

bool ATNetworkTool::GetHostNameDomain(const char *name, std::string &domain)
{
	const char *domp = strchr(name, '.');
	if (domp) {
		domp++;
		if (*domp) {
#ifdef LMS_NET_DEBUG
			printf("D:  %s\n", domp);
#endif
			domain = domp;
			return true;
		}
	}
	return false;
}

bool ATNetworkTool::GetHentDomain(struct hostent *hent, std::string &domain)
{
	if (NULL == hent) {
		return false;
	}
	if (NULL == hent->h_name) {
		return false;
	}

#ifdef LMS_NET_DEBUG
	printf("N:  %s\n", hent->h_name);
#endif
	if (ATNetworkTool::GetHostNameDomain(hent->h_name, domain)) {
		return true;
	}

	if (NULL != hent->h_aliases) {
		for (char **ssx = hent->h_aliases; ssx && *ssx; ssx++) {
#ifdef LMS_NET_DEBUG
			printf("A:  %s\n", *ssx);
#endif
			if (ATNetworkTool::GetHostNameDomain(*ssx, domain)) {
				return true;
			}
		}
	}
	return false;
}

bool ATNetworkTool::GetIPDomain(const ATAddress &ip, std::string &domain, int &error)
{
	char hbuf[NI_MAXHOST];

	if (0 != (error = getnameinfo(ip.addr(), ip.size(),
				      hbuf, sizeof(hbuf),
				      NULL, 0,
				      NI_NAMEREQD))) {
		return false;
	}

	return ATNetworkTool::GetHostNameDomain(hbuf, domain);
}

int ATNetworkTool::GetLocalIPs(ATAddressList &addresses, int &error, int family, bool withloopback)
{
	struct ifaddrs *ifap;

	if (0 != getifaddrs(&ifap)) {
		error = errno;
		return -1;
	}

	addresses.clear();
	for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {

		if (NULL == ifa->ifa_addr) {
			continue;
		}
		if ((ifa->ifa_flags & IFF_UP) == 0) {
			continue;
		}
		if ((!withloopback) &&
		    (((ifa->ifa_flags & IFF_LOOPBACK) != 0) ||
		    ((ifa->ifa_flags & (IFF_BROADCAST | IFF_POINTOPOINT)) == 0))) {
			continue;
		}

		if (AF_UNSPEC != family) {
			if (ATNetworkTool::AF_XINETX == family) {
				if (!ATAddress::saIsInet(ifa->ifa_addr)) {
					continue;
				}
			} else {
				if (ifa->ifa_addr->sa_family != family) {
					continue;
				}
			}
		}

		addresses.insert(ifa->ifa_addr);

	}


	freeifaddrs(ifap);
	return 0;
}

int ATNetworkTool::GetLocalNetDomains(ATDomainMap &domains, int &error, int family)
{
	int ret;
	ATAddressList addresses;

	if (0 != (ret = ATNetworkTool::GetLocalIPs(addresses, error, family))) {
		return ret;
	}

	domains.clear();
	ATAddressList::iterator aend = addresses.end();
	for (ATAddressList::iterator ait = addresses.begin();
	    ait != aend;
	    ait++)
	{
		std::string domain;
		if (ATNetworkTool::GetIPDomain(*ait, domain, error)) {
			domains[*ait] = domain;
		}
	}
	return 0;
}

int ATNetworkTool::GetSockDomain(int sock, std::string &domain, int &error)
{
	struct sockaddr_storage ss;
	socklen_t salen = sizeof(ss);
	struct sockaddr *sa;

	sa = (struct sockaddr *)&ss;

	if (getsockname(sock, sa, &salen) != 0) {
		error = errno;
		return -1;
	}

	if (ATNetworkTool::GetIPDomain(sa, domain, error)) {
		return 1;
	}
	return 0;
}

int ATNetworkTool::GetSockPeerIP(int sock, ATAddressList & peerAddresses, int &error)
{
	struct sockaddr_storage ss;
	socklen_t salen = sizeof(ss);
	struct sockaddr *sa;

	memset(&ss,0,salen);
	sa = (sockaddr *)&ss;

	if (getpeername(sock, sa, &salen) != 0) {
		error = errno;
		return -1;
	}

	struct in6_addr addr = ((struct sockaddr_in6*)sa)->sin6_addr;

	if(sa->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr)) //if(IN6_IS_ADDR_V4COMPAT(&addr))
	{
		struct in_addr demapped_addr;
		memcpy(&demapped_addr.s_addr, &addr.__in6_u.__u6_addr8[12], 4);

		struct sockaddr_in sa_in;
		sa_in.sin_family = AF_INET;
		sa_in.sin_addr = demapped_addr;
		sa_in.sin_port = 0;
		memset(sa_in.sin_zero,'\0',sizeof(sa_in.sin_zero));

		peerAddresses.insert(ATAddress((sockaddr*)&sa_in));

		return 0;
	}

	peerAddresses.insert(ATAddress(sa));

	return 0;
}

int ATNetworkTool::IsSockPeerLocal(int sock, int &error, int family)
{
	ATAddressList localAddresses;
	ATAddressList peerAddresses;

	if(0 != GetSockPeerIP(sock,peerAddresses,error))
	{
		return -1;
	}

	if (0 != ATNetworkTool::GetLocalIPs(localAddresses, error,
						family, true)) {
		return -1;
	}


	if(std::includes(localAddresses.begin(), localAddresses.end(),peerAddresses.begin(), peerAddresses.end()))
	{
		return 1;
	}

	return 0;
}

int ATNetworkTool::CloseSocket(int s)
{
	shutdown(s, SHUT_RDWR);
	return close(s);
}

int ATNetworkTool::CreateSocket(const struct addrinfo *addr, int &error, bool needBindLoc)
{
	return ATNetworkTool::CreateSocket(addr->ai_addr, addr->ai_addrlen,
					   error, needBindLoc,
					    addr->ai_family, addr->ai_socktype,
					    addr->ai_protocol);
}

int ATNetworkTool::CreateSocket(const struct sockaddr *addr, socklen_t addrlen,
				int &error, bool needBindLoc,
				int family, int socktype, int protocol)
{
  int s = socket(family, socktype, protocol);
	if (s < 0) {
		error = errno;
		return -1;
	}

	if (socktype != SOCK_DGRAM) {
		linger l;
		l.l_onoff = 0;
		l.l_linger = 0;
		if (setsockopt(s, SOL_SOCKET, SO_LINGER,
			       (char *)&l, sizeof(l)) == -1) {
			error = errno;
			close(s);
			return -1;
		}
		int on=1;
		if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR, &on,sizeof(on)) == -1)
		{
			error = errno;
			close(s);
			return -1;
		}
	}
	if (needBindLoc) // we don't want ever accept connections from network
	{                // this is like condition accept in windows and connected to WinHTTP issue
	    const char *device = "lo";
		struct ifreq ifr;
		strcpy(ifr.ifr_name, device);
		if(setsockopt(s,SOL_SOCKET,SO_BINDTODEVICE, &ifr,sizeof(ifr)) == -1)
		{
			error = errno;
			close(s);
			return -1;
		}
		printf("successfully binded local\n");
	  
	}
	if (bind(s, addr, addrlen) == -1) {
		error = errno;
		close(s);
		return -1;
	}
	return s;
}

int ATNetworkTool::ConnectSocket(struct addrinfo *addr,
				 int &error, bool loopback)
{
	return ATNetworkTool::ConnectSocket(addr->ai_addr, addr->ai_addrlen,
					    error, loopback,
					    addr->ai_family, addr->ai_socktype,
					    addr->ai_protocol);
}

int ATNetworkTool::ConnectSocket(const struct sockaddr *addr, socklen_t addrlen,
				 int &error, bool loopback,
				 int family, int socktype, int protocol)
{
	struct addrinfo hints, *paddr, *paddrp;
	int oks = -1;

	memset(&hints, 0, sizeof(hints));
	if (ATNetworkTool::AF_XINETX == family) {
		hints.ai_family = PF_UNSPEC;
	} else {
		hints.ai_family = family;
	}
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
#ifdef AI_NUMERICSERV
	hints.ai_flags   |= AI_NUMERICSERV;
#endif
	if (!loopback) {
		hints.ai_flags |= AI_PASSIVE;
	}
	if ((error = getaddrinfo(NULL, "0", &hints, &paddrp)) != 0) {
		return -1;
	}
	for (paddr = paddrp; paddr; paddr = paddr->ai_next) {
		if (ATNetworkTool::AF_XINETX == family) {
			if (!ATAddress::saIsInet(paddr->ai_addr)) {
				continue;
			}
		}

		int s = ATNetworkTool::CreateSocket(paddr, error);
		if (s < 0) {
			continue;
		}

		if (connect(s, addr, addrlen) != 0) {
			error = errno;
			ATNetworkTool::CloseSocket(s);
			continue;
		}

		oks = s;
		break;
	}
	freeaddrinfo(paddrp);
	return oks;
}

int ATNetworkTool::CreateServerSocket(in_port_t port,
					int &error,
					bool loopback, bool nonblocking,
					int family, int socktype, int protocol,
					int backlog)
{
	std::stringstream ssport;

	ssport << port;
	return ATNetworkTool::CreateServerSocket(ssport.str().c_str(),
						 error,
						 loopback, nonblocking,
						 family, socktype, protocol,
						 backlog);
}

int ATNetworkTool::CreateServerSocket(const char *port,
					int &error,
					bool loopback, bool nonblocking,
					int family, int socktype, int protocol,
					int backlog)
{
	ATSocketList sockets;
	int s = -1;

	int num = ATNetworkTool::CreateServerSockets(sockets, port,
						     error,
						     loopback, nonblocking,
						     family, socktype, protocol,
						     backlog, true);
	if ((num > 0) && (sockets.size() > 0)) {
		s = sockets[0];
	}
	sockets.clear();
	return s;
}


int ATNetworkTool::CreateServerSockets(ATSocketList &sockets, in_port_t port,
					int &error,
					bool loopback, bool nonblocking,
					int family, int socktype, int protocol,
					int backlog, bool one)
{
	std::stringstream ssport;

	ssport << port;
	return ATNetworkTool::CreateServerSockets(sockets, ssport.str().c_str(),
						  error,
						  loopback, nonblocking,
						  family, socktype, protocol,
						  backlog, one);
}

int ATNetworkTool::CreateServerSockets(ATSocketList &sockets, const char *port,
					int &error,
					bool loopback, bool nonblocking,
					int family, int socktype, int protocol,
					int backlog, bool one)
{
	struct addrinfo hints, *paddr, *paddrp;
	int num = 0;

	memset(&hints, 0, sizeof(hints));
	if (ATNetworkTool::AF_XINETX == family) {
		hints.ai_family = PF_UNSPEC;
	} else {
		hints.ai_family = family;
	}
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
#ifdef AI_NUMERICSERV
	hints.ai_flags   |= AI_NUMERICSERV;
#endif
	if (!loopback) {
		hints.ai_flags |= AI_PASSIVE;
	}
	if ((error = getaddrinfo(NULL, port, &hints, &paddrp)) != 0) {
		return -1;
	}
	for (paddr = paddrp; paddr; paddr = paddr->ai_next) {
		if (ATNetworkTool::AF_XINETX == family) {
			if (!ATAddress::saIsInet(paddr->ai_addr)) {
				continue;
			}
		}

		int s = ATNetworkTool::CreateServerSocket(paddr, error,
							  nonblocking,
							  backlog);
		if (s < 0) {
			continue;
		}
		sockets.push_back(s);
		num++;
		if (one) {
			break;
		}
	}
	freeaddrinfo(paddrp);
	return num;
}

int ATNetworkTool::CreateServerSocket(const struct addrinfo *addr, int &error,
					bool nonblocking, int backlog)
{
    int s = ATNetworkTool::CreateSocket(addr, error, true);
	if (s < 0) {
		return -1;
	}

	if (nonblocking) {
		ATNetworkTool::SetNonBlocking(s);
	}

	if (listen(s, backlog) == -1) {
		error = errno;
		ATNetworkTool::CloseSocket(s);
		return -1;
	}

	return s;
}

int ATNetworkTool::SetNonBlocking(int s, bool block)
{
	if (block) {
		return fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
	} else {
		return fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
	}
}

int ATNetworkTool::ConnectToSocket(int sock, int &error, bool loopback,
				    int socktype, int protocol)
{
	struct sockaddr_storage ss;
	socklen_t addrLen = sizeof(ss);
	struct sockaddr *sa = (struct sockaddr *)&ss;

	if (getsockname(sock, sa, &addrLen) != 0) {
		error = errno;
		return -1;
	}
	int s = ATNetworkTool::ConnectSocket(sa, addrLen,
					     error, loopback,
					     sa->sa_family,
					     socktype, protocol);
	if (s < 0) {
		return -1;
	}
	return s;
}

int ATNetworkTool::Connect(const char *host, in_port_t port,
				int &error,
				int family, int socktype, int protocol)
{
	std::stringstream ssport;

	ssport << port;

	return ATNetworkTool::Connect(host, ssport.str().c_str(), error,
					family, socktype, protocol);
}

int ATNetworkTool::Connect(const char *host, const char *port,
				int &error,
				int family, int socktype, int protocol)
{
	struct addrinfo hints, *paddr, *paddrp;
	int oks = -1;

	if (socktype != SOCK_DGRAM) {
		socktype = SOCK_STREAM;
	}

	memset(&hints, 0, sizeof(hints));
	if (ATNetworkTool::AF_XINETX == family) {
		hints.ai_family = PF_UNSPEC;
	} else {
		hints.ai_family = family;
	}
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	hints.ai_flags    = AI_NUMERICHOST;
#ifdef AI_NUMERICSERV
	hints.ai_flags   |= AI_NUMERICSERV;
#endif
	if ((error = getaddrinfo(host, port, &hints, &paddrp)) != 0) {
		memset(&hints, 0, sizeof(hints));
		if (ATNetworkTool::AF_XINETX == family) {
			hints.ai_family = PF_UNSPEC;
		} else {
			hints.ai_family = family;
		}
		hints.ai_socktype = socktype;
		hints.ai_protocol = protocol;
#ifdef AI_NUMERICSERV
		hints.ai_flags   |= AI_NUMERICSERV;
#endif
		if ((error = getaddrinfo(host, port, &hints, &paddrp)) != 0) {
			return -1;
		}
	}
	for (paddr = paddrp; paddr; paddr = paddr->ai_next) {
		if (ATNetworkTool::AF_XINETX == family) {
			if (!ATAddress::saIsInet(paddr->ai_addr)) {
				continue;
			}
		}

		int s = ATNetworkTool::ConnectSocket(paddr, error);
		if (s < 0) {
			continue;
		}
		oks = s;
		break;
	}
	freeaddrinfo(paddrp);
	return oks;
}

int ATNetworkTool::ConnectLoopback(in_port_t port,
				int &error,
				int family, int socktype, int protocol)
{
	std::stringstream ssport;

	ssport << port;

	return ATNetworkTool::ConnectLoopback(ssport.str().c_str(), error,
					family, socktype, protocol);
}

int ATNetworkTool::ConnectLoopback(const char *port,
				int &error,
				int family, int socktype, int protocol)
{
	struct addrinfo hints, *paddr, *paddrp;
	int oks = -1;

	if (socktype != SOCK_DGRAM) {
		socktype = SOCK_STREAM;
	}

	memset(&hints, 0, sizeof(hints));
	if (ATNetworkTool::AF_XINETX == family) {
		hints.ai_family = PF_UNSPEC;
	} else {
		hints.ai_family = family;
	}
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
#ifdef AI_NUMERICSERV
	hints.ai_flags   |= AI_NUMERICSERV;
#endif
	if ((error = getaddrinfo(NULL, port, &hints, &paddrp)) != 0) {
		return -1;
	}
	for (paddr = paddrp; paddr; paddr = paddr->ai_next) {
		if (ATNetworkTool::AF_XINETX == family) {
			if (!ATAddress::saIsInet(paddr->ai_addr)) {
				continue;
			}
		}

		int s = ATNetworkTool::ConnectSocket(paddr, error, true);
		if (s < 0) {
			continue;
		}
		oks = s;
		break;
	}
	freeaddrinfo(paddrp);
	return oks;
}

unsigned int ATNetworkTool::GetLocalPort(int sock)
{
	struct sockaddr_storage ss;
	socklen_t addrLen = sizeof(ss);
	struct sockaddr *sa = (struct sockaddr *)&ss;

	if (getsockname(sock, sa, &addrLen) != 0) {
		return 0;
	}
	switch (sa->sa_family) {
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		break;
	case AF_INET:
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
		break;
	}
	return 0;
}

int ATNetworkTool::Accept(int s, ATAddress &address,
			  int &error, bool nonblocking)
{
	struct sockaddr_storage saddr;
	socklen_t addrLen = sizeof(saddr);
	struct sockaddr *addr = (struct sockaddr *)&saddr;

	int s_new = accept(s, addr, &addrLen);
	if (s_new == -1) {
		error = errno;
		return -1;
	}
	ATAddress atAddress(addr);
	address = atAddress;

	ATNetworkTool::SetNonBlocking(s_new, nonblocking);

	return s_new;
}

