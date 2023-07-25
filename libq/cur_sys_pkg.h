#ifndef CUR_SYS_PKG
#define CUR_SYS_PKG

#include <stdio.h>

typedef struct cur_pkg_tree_node {
  size_t key;
  size_t offset_to_hash;
  char *start_buffer;
  struct cur_pkg_tree_node *greater;
  struct cur_pkg_tree_node *minor;
}cur_pkg_tree_node;


void in_order_visit(cur_pkg_tree_node *root);
int create_cur_pkg_tree(const char *path, cur_pkg_tree_node **root);
int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash);
int is_default(cur_pkg_tree_node *root,char *file_path_complete);
void destroy_cur_pkg_tree(cur_pkg_tree_node *root);

#endif // !CUR_SYS_PKG
