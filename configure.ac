AC_PREREQ(2.59)
AC_INIT([lms], [8.0.1], [www.intel.com])
AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([1.9 foreign])
AM_MAINTAINER_MODE
AC_LANG([C++])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_mutex_lock], [],
		[AC_MSG_ERROR([Thread support not present or cannot find libpthread])])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_TIME
AC_HEADER_DIRENT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h sys/file.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h], [],
		[AC_MSG_ERROR([required header file missing])])
AC_CHECK_HEADERS([aio.h dirent.h dlfcn.h ifaddrs.h net/if.h pwd.h semaphore.h sys/stat.h sys/types.h], [],
		[AC_MSG_ERROR([required header file missing])])
AC_CHECK_HEADERS([cerrno climits csignal cstdio cstdlib cstring], [],
		[AC_MSG_ERROR([required header file missing])])
AC_CHECK_HEADERS([algorithm fstream iostream list map memory set sstream string vector], [],
		[AC_MSG_ERROR([required header file missing])])
AC_CHECK_HEADERS([pthread.h], [],
		[AC_MSG_ERROR([pthread headers not found])])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_CHECK_TYPE(ssize_t, int)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRERROR_R
AC_FUNC_FORK
AC_FUNC_STRNLEN
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([alarm atexit ftruncate gethostname gettimeofday inet_ntoa memset select socket strchr strdup strerror strstr], [],
		[AC_MSG_ERROR([required syscall missing])])

AC_CHECK_FUNCS(inet_ntop, [],
    AC_CHECK_LIB(nsl, inet_ntop, [],
    AC_CHECK_LIB(socket, inet_ntop, [],
    AC_CHECK_LIB(resolv, inet_ntop, [], [AC_MSG_ERROR([missing inet_ntop syscall])]))))
AC_CHECK_FUNC(getaddrinfo, [],
    AC_CHECK_LIB(nsl, getaddrinfo, [],
    AC_CHECK_LIB(socket, getaddrinfo, [],
    AC_CHECK_LIB(resolv, getaddrinfo))))

AC_SEARCH_LIBS(getaddrinfo, inet6)
AC_REPLACE_FUNCS(getaddrinfo getnameinfo)

CPPFLAGS="$CPPFLAGS -D_LINUX"

dnl ***************************
dnl *** Set debugging flags ***
dnl ***************************

AH_TEMPLATE([DEBUGLOG], [enable logging debug infos])
AC_ARG_ENABLE([debug], 
	      [  --enable-debug    Turn on debugging],,
	      [enable_debug=no])
if test "x$enable_debug" = "xyes"; then
	AC_DEFINE([DEBUGLOG])
	CXXFLAGS="-g $CXXFLAGS"
fi
AM_CONDITIONAL([DEBUG], [test x$enable_debug = xyes])

#set daemon 
AH_TEMPLATE(DAEMON, [run as daemon])
AC_ARG_ENABLE([daemon],
	      [  --enable-daemon=[no/yes] turn on non daemon mode [default=yes]],,
	      [enable_daemon=yes])
if test "x$enable_daemon" = "xyes"; then
	AC_DEFINE(DAEMON)
fi
AM_CONDITIONAL([DAEMON], [test x$enable_daemon = xyes])


dnl *************************************
dnl *** Warnings to show if using GCC ***
dnl *************************************

AC_ARG_ENABLE([more-warnings],
		[  --disable-more-warnings  Inhibit compiler warnings],
		[set_more_warnings=no])
if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	CXXFLAGS="$CXXFLAGS -Wall"
fi

AH_TEMPLATE(_REMOTE_SUPPORT, [LMS remote support])
AC_ARG_ENABLE([remote],
	      [  --enable-remote=[no/yes] enable support for LMS remote access [default=no]],,
	      [enable_remote=yes])
if test "x$enable_remote" = "xyes"; then
	AC_DEFINE(_REMOTE_SUPPORT)
fi

AC_CHECK_LIB(dl, dlsym, [], [AC_MSG_ERROR([missing dl library])])

IATSTATERUNDIR=/var/run
AC_SUBST(IATSTATERUNDIR)

AC_ARG_ENABLE([distcheck],
	      [  --enable-distcheck=[no/yes] turn on distcheck mode [default=no]],,
	      [enable_distcheck=no])
AM_CONDITIONAL([DISTCHECK], [test x$enable_distcheck = xyes])
DISTCHECK_CONFIGURE_FLAGS=--enable-distcheck
AC_SUBST(DISTCHECK_CONFIGURE_FLAGS)

use_rcd_initd=no
if test -f /etc/rc.d/init.d/functions; then
	# RedHat dont like LSB :( 
	use_rcd_initd=yes
fi
AM_CONDITIONAL([USE_RCDINITD], [test x$use_rcd_initd = xyes])


AC_CONFIG_FILES([Makefile
		src/Makefile
		scripts/lms
		src/plugin.h
		src/iatshareddata.h])
AC_OUTPUT
