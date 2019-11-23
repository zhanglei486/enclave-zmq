#ifndef TIME_H_
#define TIME_H_

# include <sys/time.h>
# include <sys/resource.h>

static int usertime = 0;

# define TM_START        0
# define TM_STOP         1

static double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct rusage rus;
    struct timeval now;
    static struct timeval tmstart;

    if (usertime)
        //getrusage(RUSAGE_SELF, &rus), now = rus.ru_utime;
        ;
    else
        gettimeofday(&now, NULL);

    if (stop == TM_START)
        tmstart = now;
    else
        ret = ((now.tv_sec + now.tv_usec * 1e-6)
               - (tmstart.tv_sec + tmstart.tv_usec * 1e-6));

    return ret;
}

static inline double Time_F(int s)
{
	double ret = app_tminterval(s, usertime);
	return ret;
}

#endif
