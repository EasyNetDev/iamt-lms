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
#include "iatshareddata.h"
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <csignal>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include "types.h"
#include "Protocol.h"
#include "version.h"
#include "ATVersion.h"
#include "glue.h"

#ifdef DAEMON
#include "daemonize.h"
#endif //DAEMON

#define LOCK_PATH IATSTATERUNDIR
/* Change this to whatever your daemon is called */
#define DAEMON_PID_FILE "//lms.pid"

#define QUICK_CONNECT_COUNT 30
#define SLEEP_TIMEOUT 30
#define QUICK_SLEEP_TIMEOUT 5
#define DEBUGLOG 1


bool isRunning(int running = -1)
{
	static int _running = 0;
	if (running >= 0)
	{
		_running = running;
	}
	if (_running == 1)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void log(void *param, LPCTSTR message, WORD eventType)
{
#ifdef DEBUGLOG
	syslog((int)eventType, "%s", message);
#endif
}

//This needs to be global for termination action
Protocol prot;
int lock_pid_file_fd = -1;
glue plugin;

void exitcleanup()
{
	prot.Deinit();
	prot.DestroySockets();
	syslog(EVENTLOG_INFORMATION_TYPE, "Service stopped\n");
	closelog();
	if (-1 != lock_pid_file_fd) {
		close(lock_pid_file_fd);
		lock_pid_file_fd = -1;
		unlink(LOCK_PATH DAEMON_PID_FILE);
	}

	plugin.deinit();
}

//Action termination
void terminationHandler(int signum, siginfo_t *sinfo, void *dummy)
{
	PRINT("LMS Service received - Signal:%d   Err:(%d) Code:(%d)\n", signum, sinfo->si_errno, sinfo->si_code);
	if (isRunning()) {
		syslog(EVENTLOG_WARNING_TYPE, "Received termination signal (%d)\n", signum);

		isRunning(0);
		prot.SignalSelect();
		exit(EXIT_SUCCESS);
	}
}

void setTerminationHandler()
{
	int sigSet = 0;
	// Termination signal handler.
	struct sigaction terminateAction;
	// Set up the structure to specify the termination action.
	terminateAction.sa_sigaction = terminationHandler;
	sigemptyset(&terminateAction.sa_mask);
	terminateAction.sa_flags = SA_SIGINFO;
	sigSet &= sigaction(SIGTERM, &terminateAction, NULL);
	sigSet &= sigaction(SIGQUIT, &terminateAction, NULL);
	sigSet &= sigaction(SIGINT,  &terminateAction, NULL);
	sigSet &= sigaction(SIGHUP,  &terminateAction, NULL);
	sigSet &= sigaction(SIGPIPE, &terminateAction, NULL);
	sigSet &= sigaction(SIGALRM, &terminateAction, NULL);
	sigSet &= sigaction(SIGUSR1, &terminateAction, NULL);
	sigSet &= sigaction(SIGUSR2, &terminateAction, NULL);

	if (sigSet != 0) {
		syslog(EVENTLOG_WARNING_TYPE, "Failed to register terminate signal handler\n");
	}
}

/**
 * 	lock_pid_file - creates a pid file and writes current process pid into it
 *
 *  lockfile - name of a file to be created
 *
 *  return: 0 on success, -1 on fatal error, -2 on error
 **/
int lock_pid_file(const char *lockfile)
{
	int lfp = -1;
	size_t towrite = 0;
	ssize_t written = 0;
	int haserror = 0;
	char pid_buf[32];
	int error;

	/* Create the lock file as the current user */
	if (lockfile && lockfile[0]) {
		lfp = open(lockfile, O_RDWR | O_CREAT, 0644);
		if (lfp < 0) {
			syslog(LOG_ERR,
			       "unable to create lock file %s, code=%d (%s)",
			       lockfile, errno, strerror(errno));
			return -1;
		}
		if (-1 == flock(lfp, LOCK_EX | LOCK_NB)) {
			error = errno;
			if (EWOULDBLOCK == errno) {
				syslog(LOG_ERR, "The LMS service is already running!");
				close(lfp);
			} else {
				syslog(LOG_ERR,
				       "unable to lock file %s, code=%d (%s)",
				       lockfile, error, strerror(error));
				close(lfp);
				unlink(lockfile);
				return -2;
			}
			return -1;
		}
		if (-1 == ftruncate(lfp, 0)) {
			syslog(LOG_ERR,
			       "unable to truncate lock file %s, code=%d (%s)",
			       lockfile, errno, strerror(errno));
			close(lfp);
			unlink(lockfile);
			return -2;
		}
		snprintf(pid_buf, sizeof(pid_buf), "%u", getpid());
		towrite = strnlen(pid_buf, 31);
		written = write(lfp, pid_buf, towrite);
		error = errno;
		if (-1 == written) {
			haserror = 1;
		} else if (towrite != (size_t)written) {
			haserror = 1;
		} else if (-1 == fsync(lfp)) {
			error = errno;
			haserror = 1;
		}
		if (1 == haserror) {
			syslog(LOG_ERR,
			       "unable to write pid into lock file %s, code=%d (%s)",
			       lockfile, error, strerror(error));
			close(lfp);
			unlink(lockfile);
			return -2;
		}
		lock_pid_file_fd = lfp;
	}
	return 0;
}


int main(int argc, char **argv)
{
	bool alreadyFailed = false;
	bool firstLoop = true;
	bool init = false;
	int connectCount = 0;
	int lockresult = -1;

	if (ATVersion::ShowVersionIfArg(argc, const_cast<const char **>(argv), VER_PRODUCTVERSION_STR)) {
		return 0;
	}

	umask(022);

	openlog("LMS", LOG_CONS, LOG_DAEMON);

#ifdef DAEMON
	daemonize();
#else
	setTerminationHandler();
#endif

	lockresult = lock_pid_file(LOCK_PATH DAEMON_PID_FILE);
	if (-2 == lockresult) {
		lockresult = lock_pid_file(LOCK_PATH DAEMON_PID_FILE);
	}
	if (0 != lockresult) {
		exit(EXIT_FAILURE);
	}

	isRunning(1);
	syslog(EVENTLOG_INFORMATION_TYPE, "Service started\n");

	atexit(exitcleanup);

	plugin.init();

	while (isRunning()) {
		if (!prot.IsInitialized()) {
			if (init) {
#ifdef DEBUGLOG
				log(NULL, "LMS Service lost connection to Intel AMT via MEI driver", EVENTLOG_ERROR_TYPE);
#endif
				init = false;
			}

			if (!prot.Init(log, NULL)) {
				if (firstLoop) {
					syslog(EVENTLOG_ERROR_TYPE, "Cannot connect to Intel AMT via MEI driver");
					firstLoop = false;
				}
				// Failed to connect to the MEI driver.
				// Sleep for a second and try again.
				connectCount++;
				if (connectCount >= QUICK_CONNECT_COUNT) {
					sleep(SLEEP_TIMEOUT);
				} else {
					sleep(QUICK_SLEEP_TIMEOUT);
				}
				continue;
			}
			init = true;
			firstLoop = false;
			connectCount = 0;
#ifdef DEBUGLOG
			log(NULL, "Connected to Intel AMT via MEI driver\n", EVENTLOG_INFORMATION_TYPE);
#endif
		}

		if (!prot.SocketsCreated()) {
			if (!prot.CreateSockets()) {
				if (!alreadyFailed) {
#ifdef DEBUGLOG
					log(NULL, "LMS Service has a problem in acquiring network resources.", EVENTLOG_ERROR_TYPE);
#endif
					alreadyFailed = true;
				}
				continue;
			} else {
				alreadyFailed = false;
			}
		}
		// Select on active sockets (IANA ports and open connections).
		prot.Select();
	}

	return 0;
}
