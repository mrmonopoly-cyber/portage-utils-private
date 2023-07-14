/*
 * Copyright 2005-2020 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2008 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2015 Mike Frysinger  - <vapier@gentoo.org>
 * Copyright 2018-     Fabian Groffen  - <grobian@gentoo.org>
 */

#include "main.h"
#include "atom.h"

#include <xalloc.h>
#include <stdlib.h>
#include <stdio.h>

const char *argv0;
FILE *warnout;

static inline void boom(depend_atom *a, char *s)
{
	/* python code:
	 *  CATEGORY = cpv[0]
	 *  PN = cpv[1]
	 *  PV = cpv[2]
	 *  PR_int = cpv[3]
	 *  P = PN + "-" + PV
	 *  PVR = PV + "-" + cpv[3]
	 *  print(a+" -> "+CATEGORY+" / ["+P+"] "+PN+" - "+PVR+" ["+PV+"] ["+PR_int+"]")
	 * this most notably doesn't test PVR in compliance with PMS */
	printf("%s -> %s / [%s] %s - %s%s [%s] [r%i]\n",
			s,
			(a->CATEGORY ? a->CATEGORY : "null"),
			a->P,
			a->PN,
			a->PVR, (a->PVR != NULL && a->PR_int == 0) ? "-r0" : "",
			a->PV,
			a->PR_int);
}

int main(int argc, char *argv[])
{
	int i;
	depend_atom *a;

	argv0 = argv[0];
	warnout = stderr;

	/* printf("input -> CATEGORY / [P] PN - PVR [PV] [PR_int]\n"); */
	for (i = 1; i < argc; ++i) {
		a = atom_explode(argv[i]);
		boom(a,argv[i]);
		atom_implode(a);
	}
	if (argc == 1) {
		size_t buflen;
		char *buf, *p;

		buf = NULL;
		while (getline(&buf, &buflen, stdin) != -1) {
			if ((p = strchr(buf, '\n')) != NULL)
				*p = '\0';
			a = atom_explode(buf);
			boom(a, buf);
			atom_implode(a);
		}
	}

	return EXIT_SUCCESS;
}
