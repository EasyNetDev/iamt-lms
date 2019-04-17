SUBDIRS=src

if DISTCHECK
initddir=$(prefix)/etc/init.d
else
if USE_RCDINITD
initddir=/etc/rc.d/init.d
else
initddir=/etc/init.d
endif
endif
initd_SCRIPTS=scripts/lms

