#ifndef ZMQ_CURVE_UTIL_H_
#define ZMQ_CURVE_UTIL_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


static void readFromFile(const char *fname, unsigned char *buf, int *len)
{
	struct stat fst;

	stat(fname, &fst);
	*len = fst.st_size;
	if(buf==NULL){
		return;
	}
	FILE *fp =fopen(fname, "rb");
	if(fp==NULL) return;
	fread(buf, *len, 1, fp);
	fclose(fp);
}

#endif
