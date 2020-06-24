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
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

#include "ui.h"

bool lastnewl = true;

static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

void PrintAndLog(bool newl, char *fmt, ...) {
    va_list argptr, argptr2;
    pthread_mutex_init(&print_lock, NULL);
    // lock this section to avoid interlacing prints from different threads
    pthread_mutex_lock(&print_lock);
    
    if (newl) {
        printf("\n");
    } else {
        if (lastnewl)
            printf("\n");
        
        printf("\r");
    }
    va_start(argptr, fmt);
    va_copy(argptr2, argptr);
    vprintf(fmt, argptr);
    printf("          "); // cleaning prompt
    va_end(argptr);
        
    va_end(argptr2);

    fflush(NULL);
    lastnewl = newl;

    //release lock
    pthread_mutex_unlock(&print_lock);
}


