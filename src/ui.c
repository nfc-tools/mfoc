//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// UI utilities
//-----------------------------------------------------------------------------

#include <stdbool.h>
#ifndef EXTERNAL_PRINTANDLOG
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <readline/readline.h>
#include <pthread.h>
#endif

#include "ui.h"

double CursorScaleFactor = 1;
int PlotGridX = 0, PlotGridY = 0, PlotGridXdefault = 64, PlotGridYdefault = 64, CursorCPos = 0, CursorDPos = 0;
bool flushAfterWrite = false; //buzzy
int GridOffset = 0;
bool GridLocked = false;
bool showDemod = true;

#ifndef EXTERNAL_PRINTANDLOG
static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

void PrintAndLog(char *fmt, ...) {
    va_list argptr, argptr2;

    // lock this section to avoid interlacing prints from different threads
    pthread_mutex_lock(&print_lock);

    va_start(argptr, fmt);
    va_copy(argptr2, argptr);
    vprintf(fmt, argptr);
    printf("          "); // cleaning prompt
    va_end(argptr);
    printf("\n");

    va_end(argptr2);

    if (flushAfterWrite) //buzzy
    {
        fflush(NULL);
    }
    //release lock
    pthread_mutex_unlock(&print_lock);
}
#endif

void SetFlushAfterWrite(bool flush_after_write) {
    flushAfterWrite = flush_after_write;
}

