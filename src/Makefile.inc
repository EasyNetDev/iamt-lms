
SYNCLIB_SRCS=$(SYNCLIB_SRCDIR)/EventLinux.cpp \
$(SYNCLIB_SRCDIR)/SemaphoreLinux.cpp \
$(SYNCLIB_SRCDIR)/RWLock.cpp \
$(SYNCLIB_SRCDIR)/ThreadLinux.cpp

SYNCLIB_HDRS=$(SYNCLIB_HDRDIR)/Semaphore.h \
$(SYNCLIB_HDRDIR)/Event.h \
$(SYNCLIB_HDRDIR)/RWLock.h \
$(SYNCLIB_HDRDIR)/Lock.h \
$(SYNCLIB_HDRDIR)/Thread.h \
$(SYNCLIB_HDRDIR)/SPtr.h

MEI_HDRS=$(MEI_DIR)/mei.h \
$(MEI_DIR)/MEI_if.h \
$(MEI_DIR)/MEILinux.h \
$(MEI_DIR)/StatusCodeDefinitions.h \
$(MEI_DIR)/MNGCommand.h \
$(MEI_DIR)/FWULCommand.h \
$(MEI_DIR)/PTHICommand.h

MEI_SRCS=$(MEI_DIR)/MEILinux.cpp \
$(MEI_DIR)/MNGCommand.cpp \
$(MEI_DIR)/FWULCommand.cpp \
$(MEI_DIR)/PTHICommand.cpp

TOOLS_HDRS=$(TOOLS_DIR)/ATVersion.h \
$(TOOLS_DIR)/ATNetworkTool.h \
$(TOOLS_DIR)/daemonize.h

TOOLS_SRCS=$(TOOLS_DIR)/ATVersion.cpp \
$(TOOLS_DIR)/ATNetworkTool.cpp \
$(TOOLS_DIR)/daemonize.cpp

MAIN_HDRS=types.h \
Channel.h \
PortForwardRequest.h \
LMS_if.h \
LMS_if_constants.h \
LMEConnection.h \
ConfigConnection.h \
Protocol.h \
glue.h \
version.h \
build.h \
ChannelGenerator.h

MAIN_SRCS=main.cpp \
LMEConnection.cpp \
ConfigConnection.cpp \
Protocol.cpp \
glue.cpp \
ChannelGenerator.cpp

SRCS=$(MAIN_SRCS) \
$(TOOLS_SRCS) \
$(MEI_SRCS) \
$(SYNCLIB_SRCS)

HDRS=$(MAIN_HDRS) \
$(TOOLS_HDRS) \
$(MEI_HDRS) \
$(SYNCLIB_HDRS)

