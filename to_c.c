#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  int fd;
  unsigned char buffer[4096];
  ssize_t s, i;
  size_t total_size;
  int col;
  
  if (argc != 3) {
    fprintf (stderr, "Usage: to_c <file> <arrayname>\n");
    return 1;
  }

  fd = open (argv[1], O_RDONLY);
  if (fd == -1) {
    perror ("Can't read file");
    return 1;
  }
  
  total_size = 0;
  printf ("static const char %s[] = {\n", argv[2]);
  col = 0;
  while ((s = read (fd, buffer, sizeof (buffer))) > 0) {
    total_size += s;
    for (i = 0; i < s; i++) {
      if (col == 0)
	printf ("    \"");
      printf ("\\x%02x", buffer[i]);
      col++;
      if (col == 20) {
	printf ("\"\n");
	col = 0;
      }
    }
  }
  if (col != 0)
    printf ("\"\n");

  printf ("};\n");

  printf ("#define %s_size %zd\n", argv[2], total_size);

  return 0;
}

