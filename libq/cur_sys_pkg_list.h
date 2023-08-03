#ifndef CUR_SYS_PKG_LIST
#define CUR_SYS_PKG_LIST

#define PKG_LIST_BUFFER_SIZE 8

typedef struct pkg_list_buffer{
  char ** list;
  unsigned int list_size;
  unsigned int next_free;
  struct pkg_list_buffer *next;
}pkg_list_buffer;


void add_package_to_buffer(pkg_list_buffer **buffer,char *package_name,unsigned int next_size);

int find_package_in_list(pkg_list_buffer *buffer,char *package_name);

void destroy_pkg_list_buffer(pkg_list_buffer *root);

#endif // !CUR_SYS_PKG_LIST
