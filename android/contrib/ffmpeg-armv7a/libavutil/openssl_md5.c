#include "openssl_md5.h"
#include "openssl/md5.h"
#include "log.h"
#include "time.h"
#include "md5.h"
#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

int ff_openssl_file_md5(const char* file, unsigned char** result) {

	if (file == NULL) {
		av_log(NULL, AV_LOG_ERROR, "input parameters are wrong\n");

		return -1;
	}

	FILE *fd = fopen(file, "r");
	MD5_CTX c;
	if (fd == NULL) {
		av_log(NULL, AV_LOG_ERROR, "open failed\n");

		return -1;
	}

	int len;
	unsigned char *pData = (unsigned char*) malloc(1024 * 16);
	if (!pData) {
		fclose(fd);

		av_log(NULL, AV_LOG_ERROR, "malloc failed\n");

		return -1;
	}

	MD5_Init(&c);

	while (0 != (len = fread(pData, 1, 1024 * 16, fd))) {
		MD5_Update(&c, pData, len);
	}

	MD5_Final(result, &c);

	fclose(fd);
	free(pData);

	return 0;
}
