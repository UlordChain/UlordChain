// Copyright (c) 2016-2018 The Ulord Core Foundation
//  Windows
#ifdef _WIN32

#include <windows.h>

double get_wall_time() {
    LARGE_INTEGER time, freq;
    if (!QueryPerformanceFrequency(&freq)) {
        //  Handle error
        return 0;
    }
    if (!QueryPerformanceCounter(&time)) {
        //  Handle error
        return 0;
    }
    return (double)time.QuadPart / freq.QuadPart;
}

double get_cpu_time() {
    FILETIME a, b, c, d;
    if (GetProcessTimes(GetCurrentProcess(),&a,&b,&c,&d) != 0) {
        //  Returns total user time.
        //  Can be tweaked to include kernel times as well.
        return
            (double)(d.dwLowDateTime |
            ((unsigned long long)d.dwHighDateTime << 32)) * 0.000001;
    } else {
        //  Handle error
        return 0;
    }
}

//  Posix/Linux
#else

#include <time.h>
#include <sys/time.h>

double get_wall_time() {
    struct timeval time;
    if (gettimeofday(&time,NULL)) {
        //  Handle error
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * 0.000001;
}

double get_cpu_time() {
    return (double)clock() / CLOCKS_PER_SEC;
}

#endif
