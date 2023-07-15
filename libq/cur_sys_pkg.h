#ifndef CUR_SYS_PKG
#define CUR_SYS_PKG

#include <stdio.h>

typedef struct cur_pkg_tree_node {
  size_t key;
  char *hash_buffer;
  struct cur_pkg_tree_node *greater;
  struct cur_pkg_tree_node *minor;
}cur_pkg_tree_node;


void in_order_visit(cur_pkg_tree_node *root);
int create_cur_pkg_tree(char *path, cur_pkg_tree_node **root);
int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash);
void destroy_cur_pkg_tree(cur_pkg_tree_node *root);

void in_order_visit(cur_pkg_tree_node *root)
{
  if(root!=NULL)
  {
    in_order_visit(root->minor);
    printf("[%ld,%s]\n",root->key,root->hash_buffer);
    in_order_visit(root->greater);
  }
}

#endif // !CUR_SYS_PKG
