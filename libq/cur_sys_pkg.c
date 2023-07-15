#include "config.h"

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "hash.h"
#include "cur_sys_pkg.h"

#define HASH_SIZE 32

//private
void in_order_visit(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    in_order_visit(root->minor);
    printf("[%ld,%s]\n",root->key,root->hash_buffer);
    in_order_visit(root->greater);
  }
}


static void add_node(cur_pkg_tree_node **root,char *hash,size_t key)
{
  if(*root==NULL)
  {
    *root=calloc(1,sizeof(**root));
    (*root)->key=key;
    (*root)->hash_buffer=hash;
    (*root)->greater=NULL;
    (*root)->minor=NULL;
    return;
  }

  if(key>(*root)->key) add_node(&(*root)->greater,hash,key);
  if(key<(*root)->key) add_node(&(*root)->minor,hash,key);
  return;
}

size_t hash_from_string(unsigned char *str)
{
  size_t hash = 5381;
  int c;
  
  while ((c = *str++))
  {
      hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }
  return hash;
}


static int is_dir(char *path)
{
  DIR *dir=opendir(path);

  if(dir!=NULL)
  {
    closedir(dir);
    return 1;
  }

  return 0;
}

static void read_file_add_data(cur_pkg_tree_node **root)
{
  FILE *CONTENTS=fopen("./CONTENTS","r");
  int byte_read = 0;
  char *line_buffer=NULL;
  char *line_buffer_end=NULL;
  char *line_buffer_start_path=NULL;
  char *hash_buffer=NULL;
  char *hash_buffer_cursor=NULL;
  char *hash_to_node = NULL;
  size_t line_buffer_size=0;
  size_t key=0;
  
  hash_buffer=calloc(HASH_SIZE+1,sizeof(*hash_buffer));
  hash_buffer[HASH_SIZE]='\0';
  hash_buffer_cursor=hash_buffer+(HASH_SIZE -1);
  while( (byte_read=getline(&line_buffer,&line_buffer_size,CONTENTS)) != -1 )
  {
    if(line_buffer[0]=='o' && line_buffer[1]=='b' && line_buffer[2]=='j')
    {
    	line_buffer_end=line_buffer+(byte_read-1);
	while( !(60 < *line_buffer_end) && !(71> *line_buffer_end) )
	{
		*line_buffer_end='\0';
		--line_buffer_end;
	}
	--line_buffer_end;

	//timestamp
	while(*line_buffer_end != ' ')
	{
		*line_buffer_end='\0';
		--line_buffer_end;
	}
	--line_buffer_end;

	//hash
	while(*line_buffer_end != ' ')
	{
		*hash_buffer_cursor=*line_buffer_end;
		--hash_buffer_cursor;
		--line_buffer_end;
	}
	hash_to_node=strdup(hash_buffer);
	
	//path
	*line_buffer_end='\0';
	line_buffer_start_path=line_buffer+4;
	key=hash_from_string((unsigned char *)line_buffer_start_path);
	*line_buffer_end=' ';

	//tree
	add_node(root,hash_to_node,key);
    }
    hash_buffer_cursor=hash_buffer+(HASH_SIZE -1);
    line_buffer_start_path=NULL;
    line_buffer_end=NULL;
  }

  fclose(CONTENTS);
  free(line_buffer);
  free(hash_buffer);
  hash_buffer=NULL;
  line_buffer=NULL;
  line_buffer_end=NULL;
  line_buffer_start_path=NULL;
}

static int find_in_tree(cur_pkg_tree_node *root,size_t key,char *hash)
{
  if(root != NULL)
  {
    if(key==root->key) return !strcmp(hash,root->hash_buffer);
    if(key>root->key) return find_in_tree(root->greater,key,hash);
    if(key<root->key) return find_in_tree(root->minor,key,hash);
  }
  return 0;
}


//publid
int create_cur_pkg_tree(const char *path, cur_pkg_tree_node **root)
{
  (void)chdir(path);

  DIR *dir = NULL;
  struct dirent * dirent_struct = NULL;

  dir=opendir(".");

  while((dirent_struct=readdir(dir)) != NULL)
  {
    char *name_file=dirent_struct->d_name;
    if(is_dir(name_file) && name_file[0] != '.'){
      create_cur_pkg_tree(name_file,root);
    }else if(!strcmp(name_file,"CONTENTS")){
      read_file_add_data(root);
    }
  }
  
  closedir(dir);
  return 0;
}

int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash)
{
  size_t key= hash_from_string((unsigned char *)file_path_complete);
  return find_in_tree(root,key,hash);
}


void destroy_cur_pkg_tree(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    destroy_cur_pkg_tree(root->greater);
    destroy_cur_pkg_tree(root->minor);
    free(root);
  }
}
