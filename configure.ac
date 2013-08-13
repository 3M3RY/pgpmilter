#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pgpmilter], [0.2], [emery@hyperboria.ca])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Werror])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AM_PATH_GPGME

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostname memset strdup strerror strncasecmp strrchr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
