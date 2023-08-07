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
#include <xalloc.h>

#include "atom.h"
#include "hash.h"
#include "xchdir.h"
#include "cur_sys_pkg.h"


#define HASH_SIZE 32
#define SIZE_STR_VAR_DB_PKG 12

//private

//data
typedef struct cur_pkg_tree_node {
  char *key;
  char *hash_buffer;
  char *package_name;
  unsigned int safe_to_free_package_name;
  struct cur_pkg_tree_node *greater;
  struct cur_pkg_tree_node *minor;
}cur_pkg_tree_node;


//functions
static unsigned int conv_char_int(char dig)
{
  if((int) dig > 57) 
  {
    return (int)dig - 87;
  }
  return (int )dig - 48;
}

static int compare_hash_num(char *hash1,char*hash2)
{
  int temp1,temp2;
  for(int i=0;i<HASH_SIZE;++i)
  {
    temp1=conv_char_int(hash1[i]);
    temp2=conv_char_int(hash2[i]);
    if(temp2 > temp1)
    {
      return 1;
    }else if (temp2 < temp1) {
      return -1;
    }
  }
  return 0;
}

static char *get_fullname_package(depend_atom *datom)
{
  int cat_len,name_len=0;
  char *package_name =NULL;

  assert(datom!=NULL);
  assert(datom->CATEGORY!=NULL);
  assert(datom->PN!=NULL);

  cat_len=strlen(datom->CATEGORY);
  name_len=strlen(datom->PN);
  package_name=calloc((cat_len +1+ name_len +1), sizeof(*package_name));
  package_name[cat_len + 1 +name_len]='\0';

  strcat(package_name,datom->CATEGORY);
  strcat(package_name,"/");
  strcat(package_name,datom->PN);

  return package_name;
}
static void add_node(cur_pkg_tree_node **root,char *data,char *key,
                     char *package_name,unsigned int safe_to_free)
{
  if(*root==NULL)
  {
    *root=xmalloc(sizeof(**root));
    (*root)->key=key;
    (*root)->hash_buffer=data;
    (*root)->package_name=package_name;
    (*root)->safe_to_free_package_name=safe_to_free;
    (*root)->greater=NULL;
    (*root)->minor=NULL;
    return;
  }

  int is_greater=compare_hash_num((*root)->key,key);
  
  switch (is_greater) {
    case 0:
          printf("there are two packages wich update the same file %s %s, the hash of the file is %s\n"
                 ,package_name,(*root)->package_name,data);
      return ;
    case 1:
      return add_node(&(*root)->greater,data,key,package_name,safe_to_free);
    case -1:
      return add_node(&(*root)->minor,data,key,package_name,safe_to_free);
  }
}

static char *hash_from_file(char *file_path_complete)
{
  FILE *file_to_hash;
  char buf[512];
  unsigned char hex_hash[HASH_SIZE+1];
  hex_hash[HASH_SIZE]='\0';
  MD5_CTX ctx;
  
  char *out = NULL;
  out=xmalloc(HASH_SIZE+1* sizeof(*out));
  out[HASH_SIZE]='\0';

  file_to_hash = fopen(file_path_complete,"r");
  if(file_to_hash == NULL)
  {
    fprintf(stderr, "%s not found\n",file_path_complete);
    out=xmalloc(3* sizeof(*out));
    out[0]='-';
    out[1]='1';
    out[2]='\0';

    fclose(file_to_hash);

    return out;
  }
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
  unsigned char hex_buf[HASH_SIZE+1];
  char *hash_final=xmalloc(HASH_SIZE+1*sizeof(*hash_final));
  hash_final[HASH_SIZE]='\0';
  hex_buf[HASH_SIZE]='\0';
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

static void read_file_add_data(cur_pkg_tree_node **root,char *package_name)
{
  FILE *CONTENTS=fopen("./CONTENTS","r");
  int byte_read = 0;
  unsigned int safe_to_free = 1;
  char *line_buffer=NULL;
  char *line_buffer_end=NULL;
  char *line_buffer_start_path=NULL;
  char *hash_buffer=NULL;
  char *key=NULL;
  size_t line_buffer_size=0;
  

  //read file CONTENTS
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

      //hash
      *line_buffer_end = '\0';
      line_buffer_end-=HASH_SIZE;
      hash_buffer=strdup(line_buffer_end);
      hash_buffer[HASH_SIZE] = '\0';
  
      //path
      --line_buffer_end;
      *line_buffer_end='\0';
      line_buffer_start_path=line_buffer+4;
      key=hash_from_string(line_buffer_start_path,line_buffer_end - line_buffer_start_path);

      //tree
      add_node(root,hash_buffer,key,package_name,safe_to_free);
      safe_to_free=0;
    }
      key=NULL;
      hash_buffer=NULL;
      line_buffer_start_path=NULL;
      line_buffer_end=NULL;
  }

  fclose(CONTENTS);
  free(line_buffer);
  hash_buffer=NULL;
  line_buffer=NULL;
  line_buffer_end=NULL;
  line_buffer_start_path=NULL;
}

static int find_in_tree(cur_pkg_tree_node *root,char * key,char *hash,const char *category)
{
  if(!strcmp(hash,"-1")) return 1;

  if(root != NULL)
  { 
    int is_greater=compare_hash_num(root->key,key);
  
    if(is_greater == 0 && !strcmp(category,root->package_name))
      return !strcmp(hash,root->hash_buffer);

    switch (is_greater) {
      case 1:
        return find_in_tree(root->greater,key,hash,category);
        break;
      case -1:
        return find_in_tree(root->minor,key,hash,category);
        break;
      default:
    }
  }
  return 0;
}

//public
int create_cur_pkg_tree(const char *path, cur_pkg_tree_node **root, depend_atom *atom)
{ 
  char *package_name;
  char *name_file;
  DIR *dir = NULL;
  struct dirent * dirent_struct = NULL;
  int find_it =0;

  xchdir(path);
  dir=opendir(".");

  while(!find_it && (dirent_struct=readdir(dir)) != NULL)
  {
    name_file=dirent_struct->d_name;
    if(is_dir(name_file) && name_file[0] != '.' && 
      (!strcmp(name_file,atom->CATEGORY) || strstr(name_file,atom->PN))){ 
        //this case will possibly load also a wrong package 
        //example car and car-lib but it should not be a problem 
        create_cur_pkg_tree(name_file,root,atom);
    }else if(!strcmp(name_file,"CONTENTS")){
      package_name=get_fullname_package(atom);
      read_file_add_data(root,package_name);
      find_it=1;
    }
  }

  closedir(dir);
  xchdir("..");
  return 0;
}

int is_default(cur_pkg_tree_node *root,char *file_path_complete,const char *category)
{
  char *key;
  int res=0;
  char *hash =NULL;

  hash = hash_from_file(file_path_complete);
  key= hash_from_string(file_path_complete,strlen(file_path_complete));
  res = find_in_tree(root,key,hash,category);

  free(hash);
  free(key);
  key=NULL;
  hash=NULL;

  return res;
}

void destroy_cur_pkg_tree(cur_pkg_tree_node *root)
{
  
  if(root!=NULL)
  {
    destroy_cur_pkg_tree(root->greater);
    destroy_cur_pkg_tree(root->minor);

    free(root->hash_buffer);
    root->hash_buffer=NULL;

    free(root->key);
    root->key=NULL;
    
    if(root->safe_to_free_package_name){
      free(root->package_name);
    }
    root->package_name=NULL;

    free(root);
    root=NULL;
  }
}

void in_order_visit(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    if(root->minor!=NULL) in_order_visit(root->minor);
    printf("[%s,%s,%s,%s]\n",root->key,root->hash_buffer,
           root->hash_buffer,root->package_name);
    if(root->greater!=NULL) in_order_visit(root->greater);
  }
}
