#include <openssl/sha.h>
#include <assert.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "cur_sys_pkg.h"

#define HASH_SIZE 32



//private
void in_order_visit(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    in_order_visit(root->minor);
    printf("[%ld,%s,%s]\n",root->key,root->start_buffer,root->start_buffer + root->offset_to_hash);
    in_order_visit(root->greater);
  }
}


static void add_node(cur_pkg_tree_node **root,char *data,size_t key,size_t offset)
{
  if(*root==NULL)
  {
    *root=calloc(1,sizeof(**root));
    (*root)->key=key;
    (*root)->start_buffer=data;
    (*root)->offset_to_hash=offset;
    (*root)->greater=NULL;
    (*root)->minor=NULL;
    return;
  }
  if(key>=(*root)->key) add_node(&(*root)->greater,data,key,offset);
  if(key<(*root)->key) add_node(&(*root)->minor,data,key,offset);
  return;
}

size_t hash_from_string(char *str,size_t len)
{
  char result[512];
  size_t res=0;
  SHA512(str,len,result);
  for (size_t i = 0; i < len; i++) {
    res+=(size_t)result[i];
  }
  return res;
}


static int is_dir(char *string)
{
  struct stat path;
  stat(string, &path);
  return !S_ISREG(path.st_mode);
}

static void read_file_add_data(cur_pkg_tree_node **root)
{
  FILE *CONTENTS=fopen("./CONTENTS","r");
  int byte_read = 0;
  char *line_buffer=NULL;
  char *line_buffer_end=NULL;
  char *line_buffer_start_path=NULL;
  char *data_buffer=NULL;
  char *hash_to_node = NULL;
  size_t line_buffer_size=0;
  size_t key=0;
  
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

    //path + hash
    *line_buffer_end='\0';
    line_buffer_start_path=line_buffer+4;
    data_buffer=strdup(line_buffer_start_path);
    size_t size_data_string= strlen(data_buffer);
    data_buffer[(size_data_string )- HASH_SIZE -1] = '\0';

    key=hash_from_string(data_buffer,size_data_string - HASH_SIZE -1);

    //tree
    add_node(root,data_buffer,key,size_data_string - HASH_SIZE +1);

    }
    line_buffer_start_path=NULL;
    line_buffer_end=NULL;
  }

  fclose(CONTENTS);
  free(line_buffer);
  free(data_buffer);
  data_buffer=NULL;
  line_buffer=NULL;
  line_buffer_end=NULL;
  line_buffer_start_path=NULL;
}

static int find_in_tree(cur_pkg_tree_node *root,size_t key,char *hash,char *path)
{
  if(root != NULL)
  {
    if(key==root->key && !strcmp(path,root->start_buffer)) 
      return !strcmp(hash,root->start_buffer + root->offset_to_hash);

    if(key>=root->key) 
      return find_in_tree(root->greater,key,hash,path);

    if(key<root->key) 
      return find_in_tree(root->minor,key,hash,path);
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

int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash,size_t len)
{
  size_t key= hash_from_string(file_path_complete,len);
  return find_in_tree(root,key,hash,file_path_complete);
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
