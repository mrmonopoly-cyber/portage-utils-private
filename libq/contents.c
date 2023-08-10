/*
 * Copyright 2005-2020 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2008 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2014 Mike Frysinger  - <vapier@gentoo.org>
 * Copyright 2018-     Fabian Groffen  - <grobian@gentoo.org>
 */

#include "main.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "contents.h"

//private

int parser(contents_entry *e,char *line,char *end_line)
{
  e->_data=line;

  if (!strncmp(e->_data, "obj ", 4))
		e->type = CONTENTS_OBJ;
	else if (!strncmp(e->_data, "dir ", 4))
		e->type = CONTENTS_DIR;
	else if (!strncmp(e->_data, "sym ", 4))
		e->type = CONTENTS_SYM;
	else
		return -1;

	e->name = e->_data + 4;

  if(e->type == CONTENTS_DIR){
    return 0;
  }

	/* obj /bin/bash 62ed51c8b23866777552643ec57614b0 1120707577 */
	/* sym /bin/sh -> bash 1120707577 */

  //timestamp
  for (;*end_line!=' ';--end_line) {}

  if(end_line == e->name){
    return -9;
  }
  e->mtime_str=end_line+1;
	e->mtime = strtol(e->mtime_str, NULL, 10);
	if (e->mtime == LONG_MAX) {
    e->mtime = 0;
    e->mtime_str = NULL;
  }
  *end_line='\0';

  //hash
  if(e->type == CONTENTS_OBJ){
    for (;*end_line!=' ';--end_line) {} 
    if(end_line == e->name){
        return -9;
    }
    e->digest=end_line+1;
    *end_line='\0';
  }
  
  //name is already set
  return 0;
}

//public 
/*
 * Parse a line of CONTENTS file and provide access to the individual fields
 */
contents_entry *
contents_parse_line(char *line)
{
	static contents_entry e;
	char *p;

	if (line == NULL || *line == '\0' || *line == '\n')
		return NULL;

	/* chop trailing newline */
	p = &line[strlen(line) - 1];
	if (*p == '\n')
		*p = '\0';

	memset(&e, 0x00, sizeof(e));

  if(parser(&e,line,p-1)){
    return NULL;
  }
  return &e;
}
/*
 * Parse a line of CONTENTS file and provide access to the individual fields
 * updating an exsiting contents_entry if possible, otherwise creating a new one
 * It's possible to give the length of the line, if you don't know pass -1 e the function
 * will compute itself 
 */

int update_entry_contents_parse_line(contents_entry *entry,char *line,int line_len)
{
  char *p;
  if(line_len <= 0){
    line_len = strlen(line);
  }
	if (line == NULL || *line == '\0' || *line == '\n')
		return -1;
  
  if(entry==NULL){
    memset(entry,0x00,sizeof(*entry));
  }

	/* chop trailing newline */
	p = &line[line_len - 1];
	if (*p == '\n')
		*p = '\0';
  return parser(entry,line,p-1);
}
