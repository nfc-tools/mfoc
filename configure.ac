#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([mfoc], [0.08], [mifare@nethemba.com])
AM_INIT_AUTOMAKE(@PACKAGE_NAME@, @PACKAGE_VERSION@)


AC_CONFIG_SRCDIR([src/mfoc.c])
AC_CONFIG_HEADERS([config.h])

# Checks for NFC libraries.

NFC_DIR="/usr/local/"
AC_ARG_WITH(libnfc,[  --with-libnfc=DIR     	location of the libnfc],
	[if test "$withval" != no; then
		if test "$withval" != yes; then
			NFC_DIR=$withval
		fi
	 fi])
CFLAGS="$CFLAGS -L$NFC_DIR/lib/ -I$NFC_DIR/include/libnfc/"

# Checks for programs.
AC_PROG_CC
# Checks for header files.

echo $NFC_DIR

AC_CHECK_HEADERS([stdio.h stdlib.h string.h $NFC_DIR/include/libnfc/libnfc.h $NFC_DIR/include/libnfc/defines.h unistd.h],[], [ echo "Error! You need to have libnfc >= 1.2.1."; exit -1; ])

# Checks for libraries
#AC_CHECK_LIB(nfc,nfc_configure, [], [ echo "Error! You need to have liblibnfc >= 1.2.1."; exit -1; ])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

#PKG_CHECK_MODULES(LIBNFC, libnfc, [WITH_LIBNFC="1"], [WITH_LIBNFC="0"])
#if test "$WITH_LIBNFC" = "0"; then 
#	AC_MSG_ERROR([libnfc is mandatory.])
#fi

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
