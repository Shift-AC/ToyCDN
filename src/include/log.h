#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include "lock.h"

// set them use gcc -D option.
//#define PROGNAME ""
//#define VERSION ""

extern int verbose;
extern FILE *logFile;
extern lock_t logLock;
extern sigset_t logMask, logOldMask;
void setVerbose(int level);

void initLog();
double getTimestamp();
void printInitLog();

// sigprocmask() is a virtual syscall on x64, so using it here will not cause
// performance issues.
#define doLog(prefix, ...)                                          \
    {                                                               \
        sigprocmask(SIG_SETMASK, &logMask, &logOldMask);            \
        lock(&logLock);                                             \
        fprintf(logFile, "%s(%14.6lf): ", prefix,  getTimestamp()); \
        fprintf(logFile, __VA_ARGS__);                              \
        fprintf(logFile, "\n");                                     \
        fflush(logFile);                                            \
        release(&logLock);                                          \
        sigprocmask(SIG_SETMASK, &logOldMask, &logMask);            \
    }

#define logVerboseL(level, ...)                                         \
    do                                                                  \
    {                                                                   \
        if (verbose >= level)                                           \
        {                                                               \
            doLog("[ Verbose ]", __VA_ARGS__);                          \
        }                                                               \
    } while (0)

#define logVerbose(...) logVerboseL(1, __VA_ARGS__)

#define logMessage(...)                                             \
    do                                                              \
    {                                                               \
        doLog("[ Message ]", __VA_ARGS__);                          \
    } while (0)

#define logWarning(...)                                             \
    do                                                              \
    {                                                               \
        doLog("[ Warning ]", __VA_ARGS__);                          \
    } while (0)

#define logError(...)                                               \
    do                                                              \
    {                                                               \
        doLog("[  Error  ]", __VA_ARGS__);                          \
    } while (0)

#define logFatal(...)                                               \
    do                                                              \
    {                                                               \
        doLog("[  FATAL  ]", __VA_ARGS__);                          \
        exit(1);                                                    \
    } while (0)


static inline char *strerrorV(int num, char *buf)
{
    sprintf(buf, "%d ", num);
    strerror_r(num, buf + strlen(buf), 128);
    return buf;
}

static inline unsigned int alarmWithLog(unsigned int seconds)
{
    logVerboseL(3, "Alarm %d", seconds);
    return alarm(seconds);
}

extern char *usage;
static inline void printUsageAndExit(char **argv)
{
    fprintf(stderr, "Usage: %s [options]\n%s\n", argv[0], usage);
    exit(0);
}

static inline void printVersionAndExit(char *name)
{
    fprintf(stderr, "%s %s\n", name, VERSION);
    exit(0);
}

static inline void failExit(const char *name)
{
    char errbuf[256];
    logFatal("%s() failed(%s).", name, strerrorV(errno, errbuf));
}

static inline int forceClose(int fd)
{
    int ret = close(fd);
    if (ret < 0)
    {
        failExit("close");
    }
    return ret;
}
#endif