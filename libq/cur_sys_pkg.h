#ifndef CUR_SYS_PKG
#define CUR_SYS_PKG

typedef struct cur_pkg_tree_node {
  size_t key;
  char *hash_buffer;
  struct cur_pkg_tree_node *greater;
  struct cur_pkg_tree_node *minor;
}cur_pkg_tree_node;


int create_cur_pkg_tree(char *path, cur_pkg_tree_node **root);
int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash);
void destroy_cur_pkg_tree(cur_pkg_tree_node *root);

#endif // !CUR_SYS_PKG
