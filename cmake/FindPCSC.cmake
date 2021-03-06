# This CMake script looks for (native) PC/SC functionality
#
# Operating Systems Tested:
# - Mac OS X 10.6 (with Xcode)
# - Fedora 13 (x86)
# - Windows 7 (x86, With Microsoft SDK)
#
# This should work for both 32 bit and 64 bit systems.
#
# Author: F. Kooman <fkooman@tuxed.net>
# Version: 20101017
#

FIND_PACKAGE (PkgConfig)
IF(PKG_CONFIG_FOUND)
   PKG_CHECK_MODULES(PCSC QUIET libpcsclite)
ENDIF(PKG_CONFIG_FOUND)

IF(PCSC_INCLUDE_DIRS AND PCSC_LIBRARIES)
   SET(PCSC_FOUND TRUE)
ELSE(PCSC_INCLUDE_DIRS AND PCSC_LIBRARIES)
   FIND_PATH(PCSC_INCLUDE_DIRS NAMES WinSCard.h PCSC/winscard.h) 
   FIND_LIBRARY(PCSC_LIBRARIES NAMES pcsclite PCSC WinSCard)
ENDIF(PCSC_INCLUDE_DIRS AND PCSC_LIBRARIES)

IF(PCSC_INCLUDE_DIRS AND PCSC_LIBRARIES)
   SET(PCSC_FOUND TRUE)
ENDIF(PCSC_INCLUDE_DIRS AND PCSC_LIBRARIES)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCSC DEFAULT_MSG
  PCSC_LIBRARIES
  PCSC_INCLUDE_DIRS
)

MARK_AS_ADVANCED(PCSC_INCLUDE_DIRS PCSC_LIBRARIES)
