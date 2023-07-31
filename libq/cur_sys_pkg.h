#ifndef CUR_SYS_PKG
#define CUR_SYS_PKG

#include <stdio.h>

//BST node with an entry for key(based on hash of filename) hash found in /var/db/pkg/.../CONTENTS, package fullname of the package
typedef struct cur_pkg_tree_node {
  char *key;
  char *hash_buffer;
  char *package_name;
  struct cur_pkg_tree_node *greater;
  struct cur_pkg_tree_node *minor;
}cur_pkg_tree_node;


void in_order_visit(cur_pkg_tree_node *root);
//create the tree searching from the path with in
int create_cur_pkg_tree(const char *path, cur_pkg_tree_node **root);
//return 1 if a file with that hash and that category is in the three, else 0
int is_in_tree(cur_pkg_tree_node *root,char *file_path_complete,char *hash,const char *category);
//return 1 if the file B of the package C is has the same hash of the one in /var/db/pkg/.../CONTENTS
#define is_default(A,B,C) is_in_tree(A,B,NULL,C)
//dealloc the tree
void destroy_cur_pkg_tree(cur_pkg_tree_node *root);

#endif // !CUR_SYS_PKG
