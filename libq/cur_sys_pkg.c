#include "config.h"

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cur_sys_pkg.h"

#define HASH_SIZE 32

//private

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

static size_t roof_sqrt(size_t num)
{
  size_t result=0;

  while (num) {
    ++result;
    num=(num>>1);
  }

  return result;
}

static size_t gen_hash_from_string(char *string)
{
  size_t result=0;
  size_t string_len = strlen(string);
  size_t root_sqrt_len = roof_sqrt(string_len);
  size_t hash_buffer_size=(1<<root_sqrt_len);
  char *hash_buffer=NULL;
  hash_buffer=calloc(hash_buffer_size+1,sizeof(*hash_buffer));
  result = strtol(hash_buffer,NULL,16);
  return result;
}

static int is_dir(char *path)
{
  DIR *dir=opendir(path);

  if(dir!=NULL) return 1;

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
  size_t line_buffer_size=0;
  size_t key=0;
  
  hash_buffer=calloc(HASH_SIZE+1,sizeof(*hash_buffer));
  hash_buffer+=HASH_SIZE;
  
  while( (byte_read=getline(&line_buffer,&line_buffer_size,CONTENTS)) != -1 )
  {
    if(line_buffer[0]=='o' && line_buffer[1]=='b' && line_buffer[2]=='j')
    {
      line_buffer_end=line_buffer + byte_read;
      
      //go to the last character of the string
      while(*line_buffer_end==' ' || *line_buffer_end=='\n')
      {
        *line_buffer_end='\0';
        --line_buffer_end;
      }
      
      //skip and remove timestamp
      for(;*line_buffer_end!=' ';--line_buffer_end)
      {
        *line_buffer_end='\0';
      }
      line_buffer_start_path=line_buffer+4;
      
      //read/save hash
      while(*line_buffer_end != ' ')
      {
        *hash_buffer=*line_buffer_end;
        --hash_buffer;
        --line_buffer_end;
      }
      ++hash_buffer;
      
      //create hash key from complete path of file
      key=gen_hash_from_string(line_buffer_start_path);

      //add element to the tree
      add_node(root,hash_buffer,key);
    }
  }
  fclose(CONTENTS);
  free(line_buffer);
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
int create_cur_pkg_tree(cont char *path, cur_pkg_tree_node **root)
{
  (void)chdir(path);

  DIR *dir = NULL;
  struct dirent * dirent_struct = NULL;

  dir=opendir(".");

  while((dirent_struct=readdir(dir)) != NULL)
  {
    char *name_file=dirent_struct->d_name;
    if(is_dir(name_file)){
      create_cur_pkg_tree(name_file,root);
    }else if(!strcmp(name_file,"CONTENTS")){
      read_file_add_data(root);
      break;
    }
  }
  
  return 0;
}

int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash)
{
  size_t key= gen_hash_from_string(file_path_complete);
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
