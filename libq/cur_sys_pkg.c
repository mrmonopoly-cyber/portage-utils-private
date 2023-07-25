#include "config.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <assert.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hash.h"
#include "xchdir.h"
#include "cur_sys_pkg.h"

#define HASH_SIZE 32



//private
void in_order_visit(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    in_order_visit(root->minor);
    printf("[%s,%s,%s]\n",root->key,root->start_buffer,root->start_buffer + root->offset_to_hash);
    in_order_visit(root->greater);
  }
}

int compare_hash_num(char *hash1,char*hash2)
{
  int temp1,temp2;
  for(int i=0;i<HASH_SIZE;++i)
  {
    temp1=hash1[i];
    temp2=hash2[i];
    if(temp1 < temp2)
    {
      return 1;
    }else if (temp1 > temp2) {
      return 0;
    }
  }
  return -1;
}

static void add_node(cur_pkg_tree_node **root,char *data,char *key,size_t offset,char *package_name)
{
  if(*root==NULL)
  {
    *root=calloc(1,sizeof(**root));
    (*root)->key=key;
    (*root)->start_buffer=data;
    (*root)->offset_to_hash=offset;
    (*root)->package_name=package_name;
    (*root)->greater=NULL;
    (*root)->minor=NULL;
    return;
  }

  int is_greater=compare_hash_num((*root)->key,key);
  assert(is_greater != -1);
  if(is_greater) add_node(&(*root)->greater,data,key,offset,package_name);
  if(!is_greater) add_node(&(*root)->minor,data,key,offset,package_name);

  return;
}

static char *hash_from_file(char *file_path_complete)
{
  FILE *file_to_hash;
  char buf[512];
  unsigned char hex_hash[HASH_SIZE+1];
  hex_hash[HASH_SIZE]='\0';
  MD5_CTX ctx;
  
  char *out = NULL;
  out=calloc(HASH_SIZE+1, sizeof(*out));

  file_to_hash = fopen(file_path_complete,"r");
  MD5_Init(&ctx);

  size_t byte_read=0;
  while ( ( byte_read = fread(buf,1,512,file_to_hash) ) > 0) {
    MD5_Update(&ctx,buf,byte_read);
  }
  MD5_Final(hex_hash,&ctx);

  hash_hex(out,hex_hash,(HASH_SIZE>>1));
  out[HASH_SIZE]='\0';

  fclose(file_to_hash);

  return out;
}

char *hash_from_string(char *str,size_t len)
{
  unsigned char hex_buf[len];
  char *hash_final=calloc(HASH_SIZE+1,sizeof(*hash_final));
  hash_final[32]='\0';
  hex_buf[len-1]='\0';
  MD5_CTX ctx;
  
  MD5_Init(&ctx);
  MD5_Update(&ctx,str,len);
  MD5_Final(hex_buf,&ctx);
  hash_hex(hash_final,hex_buf,(HASH_SIZE>>1));
  
  return hash_final;
}


static int is_dir(char *string)
{
  struct stat path;
  stat(string, &path);
  return !S_ISREG(path.st_mode);
}

static void read_file_add_data(cur_pkg_tree_node **root)
{
  FILE *CATEGORY=fopen("./CATEGORY","r");
  FILE *CONTENTS=fopen("./CONTENTS","r");
  int byte_read = 0;
  char *package_name;
  char *line_buffer=NULL;
  char *line_buffer_end=NULL;
  char *line_buffer_start_path=NULL;
  char *data_buffer=NULL;
  size_t line_buffer_size=0;
  size_t package_name_size=0;
  char *key=NULL;
  
  byte_read = getline(&package_name,&package_name_size,CATEGORY);
  package_name[byte_read-1]='\0';

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
      *line_buffer_end = '\0';
      line_buffer_start_path=line_buffer+4;
      data_buffer=strdup(line_buffer_start_path);
      size_t size_data_string= strlen(data_buffer);
      data_buffer[(size_data_string -1)- HASH_SIZE] = '\0';

      key=hash_from_string(data_buffer,(size_data_string -1) - HASH_SIZE);

      //tree
      add_node(root,data_buffer,key,size_data_string - HASH_SIZE,package_name);

      }
      key=NULL;
      data_buffer=NULL;
      line_buffer_start_path=NULL;
      line_buffer_end=NULL;
  }

  fclose(CONTENTS);
  fclose(CATEGORY);
  free(line_buffer);
  data_buffer=NULL;
  line_buffer=NULL;
  line_buffer_end=NULL;
  line_buffer_start_path=NULL;
}

static int find_in_tree(cur_pkg_tree_node *root,char * key,char *hash,const char *category)
{
  if(root != NULL)
  { 
    int is_greater=compare_hash_num(root->key,hash);
    
    if(is_greater)
      return find_in_tree(root->greater,key,hash,category);
    if(!is_greater)
      return find_in_tree(root->minor,key,hash,category);

    if(is_greater == -1 && !strcmp(category,root->package_name))
      return !strcmp(hash,root->start_buffer + root->offset_to_hash);
  }
  return 0;
}


//publid
int create_cur_pkg_tree(const char *path, cur_pkg_tree_node **root)
{ 
  xchdir(path);

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
  xchdir("..");
  return 0;
}

int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash,const char *category)
{
  char *key;
  int to_free = 0;
  int res=0;
  if(hash == NULL)
  {
    hash = hash_from_file(file_path_complete);
    to_free=1;
  }
  key= hash_from_string(file_path_complete,strlen(file_path_complete));
  res = find_in_tree(root,key,hash,category);

  if(to_free)
  {
    free(hash);
    hash=NULL;
  }

  return res;
}

void destroy_cur_pkg_tree(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    destroy_cur_pkg_tree(root->greater);
    destroy_cur_pkg_tree(root->minor);
    free(root->start_buffer);
    free(root);
  }
}
