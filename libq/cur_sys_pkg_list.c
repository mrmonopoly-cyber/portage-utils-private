#include "config.h"

#include "cur_sys_pkg_list.h"

#include <string.h>
#include <xalloc.h>

//private

pkg_list_buffer *create_buffer(char *package_name,int size)
{
  pkg_list_buffer *buffer=NULL;
  buffer=malloc(sizeof(*buffer));
  buffer->list_size=PKG_LIST_BUFFER_SIZE;
  buffer->list=xmalloc(size* sizeof(*buffer->list));
  buffer->next_free=1;
  buffer->list[0] = package_name;
  buffer->next=NULL;
  return buffer; 
}

//public
void add_package_to_buffer(pkg_list_buffer **buffer,char *package_name,unsigned int next_size)
{
  unsigned int next_free=0;
  if(*buffer==NULL)
  {
    *buffer=create_buffer(package_name,next_size);
    return ;
  }
  next_free=(*buffer)->next_free;
  if(next_free == ((*buffer)->list_size -1))
  {
    return add_package_to_buffer(&(*buffer)->next,package_name,next_size*2);
  }

  (*buffer)->list[next_free]=package_name;
  ++(*buffer)->next_free;
  return ;
}

int find_package_in_list(pkg_list_buffer *buffer,char *package_name)
{
  unsigned int i= 0;
  char **buff_list = NULL;
  if(buffer!=NULL)
  {
    buff_list = buffer->list;
    for (;i<buffer->next_free;++i) {
      if(!strcmp(package_name,buff_list[i])){
        return 1;
      }
    }
    if(buffer->next!=NULL){
      return find_package_in_list(buffer->next,package_name);
    }
  }
  return 0;
}

void destroy_pkg_list_buffer(pkg_list_buffer *root)
{
  if(root!=NULL)
  {
    for (unsigned int i =0;i<root->next_free;++i) {
      free(root->list[i]);
      root->list[i]=NULL;
    }
    destroy_pkg_list_buffer(root->next);
    root->next=NULL;
    free(root);
  }
}
