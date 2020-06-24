//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities
//-----------------------------------------------------------------------------

#include "util.h"
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <sysinfoapi.h>
#endif

#define MAX_BIN_BREAK_LENGTH   (3072+384+1)

#ifndef _WIN32
#include <unistd.h>
#endif

// determine number of logical CPU cores (use for multithreaded functions)

extern int num_CPUs(void) {
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#else
    return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

