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
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <aio.h>
#include <linux/mei.h>
#include "MEILinux.h"

const char MEILinux::MEI_VERSION_SYSFS_FILE[] = "/sys/module/mei/version";

/***************************** public functions *****************************/

MEILinux::MEILinux(const GUID guid, bool verbose) :
MEI(guid, verbose),
_fd(-1),
_haveMeiVersion(false)
{
}

MEILinux::~MEILinux()
{
	if (_fd != -1) {
		close(_fd);
	}
}

bool MEILinux::GetMeiVersionFromUname(MEI_VERSION &ver)
{
 
  utsname buf;
  if (uname(&buf) == -1) {
    return false;
  }
  sscanf(buf.release, "%hhd.%hhd.%hhd",&ver.major, &ver.minor, &ver.hotfix);
  ver.build = 1111;
   
  return true;
}
bool MEILinux::GetMeiVersionFromSysFs(MEI_VERSION &ver)
{

  FILE *verFile;
  bool ret;

  unsigned int major, minor, hotfix, build;

  verFile = fopen(MEILinux::MEI_VERSION_SYSFS_FILE, "r");

  if (verFile == NULL) {
      ret = false;
      goto Cleanup;
  }

  if (fscanf(verFile,"%u.%u.%u.%u", &major, &minor, &hotfix, &build) != 4) {
      ret = false;
      goto Cleanup;
  }

  ver.major = (UINT8)major;
  ver.minor = (UINT8)minor;
  ver.hotfix = (UINT8)hotfix;
  ver.build  = (UINT16)build;


  ret = true;

Cleanup:

  if (verFile != NULL && fclose(verFile) != 0)
    ret = false;

  return ret;
}

bool MEILinux::GetMeiVersion(MEI_VERSION &version) const
{
	if (_haveMeiVersion) {
		memcpy(&version, &_meiVersion, sizeof(MEI_VERSION));
		return true;
	}
	return false;
}

bool MEILinux::Init(unsigned char reqProtocolVersion)
{
	int result;
	struct mei_client *mei_client;
	bool return_result = true;
	struct mei_connect_client_data data;

	_haveMeiVersion = false;
	if (_initialized) {
		Deinit();
	}

	_fd = open("/dev/mei", O_RDWR);

	if (_fd == -1 ) {
		if (_verbose) {
			fprintf(stderr, "Error: Cannot establish a handle to the MEI driver\n");
		}
		return false;
	}
	_initialized = true;

        _haveMeiVersion = GetMeiVersionFromSysFs(_meiVersion)  ||
			 GetMeiVersionFromUname(_meiVersion);

	if (!_haveMeiVersion) {
	  if (_verbose) {
	    fprintf(stderr, "error in GetMeiVersion()");
	  }

	  return_result = false;
	  Deinit();
	  goto mei_free;
	}
	
	if (_verbose) {
		fprintf(stdout, "Connected to MEI driver, version: %d.%d.%d.%d\n",
			_meiVersion.major, _meiVersion.minor, _meiVersion.hotfix, _meiVersion.build);
		fprintf(stdout, "Size of guid = %lu\n", (unsigned long)sizeof(_guid));
	}

	memset(&data, 0, sizeof(data));

	memcpy(&data.in_client_uuid, &_guid, sizeof(_guid));
	result = ioctl(_fd, IOCTL_MEI_CONNECT_CLIENT, &data);
	if (result) {
		if (_verbose) {
			fprintf(stderr, "error in IOCTL_MEI_CONNECT_CLIENT receive message. err=%d\n", result);
		}
		return_result = false;
		Deinit();
		goto mei_free;
	}
	mei_client = &data.out_client_properties;
	if (_verbose) {
		fprintf(stdout, "max_message_length %d \n", (mei_client->max_msg_length));
		fprintf(stdout, "protocol_version %d \n", (mei_client->protocol_version));
	}

	if ((reqProtocolVersion > 0) && (mei_client->protocol_version != reqProtocolVersion)) {
		if (_verbose) {
			fprintf(stderr, "Error: MEI protocol version not supported\n");
		}
		return_result = false;
		Deinit();
		goto mei_free;
	}

	_protocolVersion = mei_client->protocol_version;
	_bufSize = mei_client->max_msg_length;

mei_free:

	return return_result;
}

void MEILinux::Deinit()
{
	if (_fd != -1) {
		close(_fd);
		_fd = -1;
	}

	_bufSize = 0;
	_protocolVersion = 0;
	_initialized = false;
}

int MEILinux::ReceiveMessage(unsigned char *buffer, int len, unsigned long timeout)
{
	int rv = 0;
	int error = 0;

	if (_verbose) {
		fprintf(stdout, "call read length = %d\n", len);
	}
	rv = read(_fd, (void*)buffer, len);
	if (rv < 0) {
		error = errno;
		if (_verbose) {
			fprintf(stderr, "read failed with status %d %d\n", rv, error);
		}
		Deinit();
	} else {
		if (_verbose) {
			fprintf(stderr, "read succeeded with result %d\n", rv);
		}
	}
	return rv;
}

int MEILinux::SendMessage(const unsigned char *buffer, int len, unsigned long timeout)
{
	int rv;

	if (_verbose)
		fprintf(stdout, "call write length = %d\n", len);

	rv = write(_fd, buffer, len);
	if (rv < 0) {
		if (_verbose)
			fprintf(stderr,"write failed with status %d %d\n", rv, errno);

		Deinit();
	}

	return rv;
}

