AC_INIT([mfoc],[0.10.7],[mifare@nethemba.com])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_SRCDIR([src/mfoc.c])

AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip subdir-objects])
CFLAGS="$CFLAGS -O3"
AX_CFLAGS_WARN_ALL

AC_PROG_CC

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for pkg-config modules.
LIBNFC_REQUIRED_VERSION=1.7.0
PKG_CHECK_MODULES([libnfc], [libnfc >= $LIBNFC_REQUIRED_VERSION], [], [AC_MSG_ERROR([libnfc >= $LIBNFC_REQUIRED_VERSION is mandatory.])])

PKG_CHECK_MODULES([liblzma], [liblzma], LIBS="$LIBS -llzma", [AC_MSG_ERROR([liblzma is mandatory.])])
ACX_PTHREAD(LIBS="$LIBS $PTHREAD_CFLAGS", [AC_MSG_ERROR([pthread is mandatory.])])
AC_CHECK_LIB(m, log, LIBS="$LIBS -lm", [AC_MSG_ERROR([math is mandatory.])])

PKG_CONFIG_REQUIRES="libnfc"
AC_SUBST([PKG_CONFIG_REQUIRES])

AC_C_INLINE

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset])

# C99
CFLAGS="$CFLAGS -std=c99"

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
