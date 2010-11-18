AC_INIT([mfoc], [0.10], [mifare@nethemba.com])

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_SRCDIR([src/mfoc.c])

AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for pkg-config modules.
LIBNFC_REQUIRED_VERSION=1.4.0
PKG_CHECK_MODULES([LIBNFC], [libnfc >= $LIBNFC_REQUIRED_VERSION], [], [AC_MSG_ERROR([libnfc >= $LIBNFC_REQUIRED_VERSION is mandatory.])])

PKG_CONFIG_REQUIRES="libnfc"
AC_SUBST([PKG_CONFIG_REQUIRES])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
