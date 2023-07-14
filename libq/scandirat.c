/*
 * Copyright 2005-2021 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2010 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2014 Mike Frysinger  - <vapier@gentoo.org>
 * Copyright 2018-     Fabian Groffen  - <grobian@gentoo.org>
 */

#include "main.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <xalloc.h>

#include "scandirat.h"

#if !defined(HAVE_SCANDIRAT)

int
scandirat(int dir_fd, const char *dir, struct dirent ***dirlist,
	int (*filter)(const struct dirent *),
	int (*compar)(const struct dirent **, const struct dirent **))
{
	int fd;
	DIR *dirp;
	struct dirent *de, **ret;
	size_t retlen = 0;
	size_t retsize = 0;
#define INCRSZ 64

	/* Cannot use O_PATH as we want to use fdopendir() */
	fd = openat(dir_fd, dir, O_RDONLY|O_CLOEXEC);
	if (fd == -1)
		return -1;
	dirp = fdopendir(fd);
	if (!dirp) {
		close(fd);
		return -1;
	}

	ret = NULL;
	while ((de = readdir(dirp))) {
		size_t sdesz;
		size_t sdenamelen;

		if (filter(de) == 0)
			continue;

		if (retlen == retsize) {
			retsize += INCRSZ;
			ret = xrealloc(ret, sizeof(*ret) * retsize);
		}
		sdesz = (void *)de->d_name - (void *)de;
		sdenamelen = strlen(de->d_name) + 1;
		ret[retlen] = xmalloc(sdesz + sdenamelen);
		memcpy(ret[retlen], de, sdesz);
		strncpy(ret[retlen]->d_name, de->d_name, sdenamelen);
		retlen++;
	}
	*dirlist = ret;

	if (compar != NULL)
		qsort(ret, retlen, sizeof(*ret), (void *)compar);

	/* closes underlying fd */
	closedir(dirp);

	return (int)retlen;
}

#endif

void
scandir_free(struct dirent **de, int cnt)
{
	if (cnt <= 0)
		return;

	while (cnt--)
		free(de[cnt]);
	free(de);
}

int
filter_hidden(const struct dirent *de)
{
	if (de->d_name[0] == '.')
		return 0;
	return 1;
}

int
filter_self_parent(const struct dirent *de)
{
	if (de->d_name[0] == '.' &&
		(de->d_name[1] == '\0' ||
		 (de->d_name[1] == '.' &&
		  de->d_name[2] == '\0')))
		return 0;

	return 1;
}
