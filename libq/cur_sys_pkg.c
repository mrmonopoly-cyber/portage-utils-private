#include "config.h"

#include <openssl/evp.h>
#include <assert.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <xalloc.h>

#include "xchdir.h"
#include "contents.h"
#include "atom.h"
#include "hash.h"
#include "hash_md5_sha1.h"
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
  
  if(!is_greater){
    printf("there are two packages wich update the same file %s %s, the hash of the file is %s\n"
            ,package_name,(*root)->package_name,data);
  }

  switch (is_greater) {
    case 1:
      return add_node(&(*root)->greater,data,key,package_name,safe_to_free);
    case -1:
      return add_node(&(*root)->minor,data,key,package_name,safe_to_free);
  }
}

static char *hash_from_file(char *file_path_complete)
{
  char *out = NULL;
  out=hash_file(file_path_complete,HASH_MD5);
  return strdup(out);
}

char *hash_from_string(char *str,size_t len)
{
  unsigned char hex_buf[HASH_SIZE+1];
  char *hash_final=xmalloc(HASH_SIZE+1*sizeof(*hash_final));
  hash_final[HASH_SIZE]='\0';
  hex_buf[HASH_SIZE]='\0';
  unsigned int HASH_MD5_len = (HASH_SIZE>>1);
  
  EVP_MD_CTX* md5Context = EVP_MD_CTX_new();
  EVP_MD_CTX_init(md5Context);
  EVP_DigestInit_ex(md5Context, EVP_md5(), NULL);
  EVP_DigestUpdate(md5Context, str,len); 
  EVP_DigestFinal_ex(md5Context, hex_buf, &HASH_MD5_len);
  EVP_MD_CTX_free(md5Context);
  hash_hex(hash_final,hex_buf,HASH_MD5_len);

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
  int safe_to_free = 1;
  char *line_buffer=NULL;
  size_t line_buffer_size=0;
  contents_entry *line_cont=NULL;

  //read file CONTENTS
  while( (byte_read=getline(&line_buffer,&line_buffer_size,CONTENTS)) != -1 )
  {
    if(line_buffer[0]=='o' && line_buffer[1]=='b' && line_buffer[2]=='j')
    {
      char *key=NULL;
      line_cont=contents_parse_line_general(line_buffer,byte_read);
      assert(line_cont!=NULL);
      key=hash_from_string(line_cont->name,(size_t) ((line_cont->digest-1)- line_cont->name));
      add_node(root,strdup(line_cont->digest),key,package_name,safe_to_free);
      safe_to_free=0;
      key=NULL;
    }
  }

  fclose(CONTENTS);
  free(line_buffer);
}

static int find_in_tree(cur_pkg_tree_node *root,char * key,char *hash,const char *category)
{
  if(!strcmp(hash,"-1")) return 1;

  if(root != NULL)
  { 
    int is_greater=compare_hash_num(root->key,key);
  
    switch (is_greater) {
      case 0:
        return !strcmp(hash,root->hash_buffer) && !strcmp(category,root->package_name);
        break;
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
    printf("[%s,%s,%s]\n",root->key,root->hash_buffer,root->package_name);
    if(root->greater!=NULL) in_order_visit(root->greater);
  }
}
