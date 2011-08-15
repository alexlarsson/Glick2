#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

int
send_message (int target_socket,
	      char *message,
	      size_t message_size,
	      int fd_to_send)
 {
   struct msghdr socket_message;
   struct iovec io_vector[1];
   struct cmsghdr *control_message = NULL;
   char ancillary_buffer[CMSG_SPACE(sizeof (int))];

   io_vector[0].iov_base = message;
   io_vector[0].iov_len = message_size;

   /* initialize socket message */
   memset (&socket_message, 0, sizeof (struct msghdr));
   socket_message.msg_iov = io_vector;
   socket_message.msg_iovlen = 1;

   memset (ancillary_buffer, 0, sizeof (ancillary_buffer));
   socket_message.msg_control = ancillary_buffer;
   socket_message.msg_controllen = sizeof (ancillary_buffer);

   /* initialize a single ancillary data element for fd passing */
   control_message = CMSG_FIRSTHDR(&socket_message);
   control_message->cmsg_level = SOL_SOCKET;
   control_message->cmsg_type = SCM_RIGHTS;
   control_message->cmsg_len = CMSG_LEN(sizeof(int));
   *((int *) CMSG_DATA(control_message)) = fd_to_send;

   return sendmsg (target_socket, &socket_message, 0);
 }

int
main (void)
{
  struct sockaddr_un address = {0};
 int socket_fd, nbytes;
 char buffer[256];

 socket_fd = socket (PF_UNIX, SOCK_SEQPACKET, 0);
 if (socket_fd < 0)
   {
     perror("socket()");
     return 1;
   }

 address.sun_family = AF_UNIX;
 snprintf(address.sun_path, sizeof (address.sun_path), "/tmp/test/socket");

 if (connect (socket_fd, 
	      (struct sockaddr *) &address, 
	      sizeof(struct sockaddr_un)) != 0)
   {
     perror ("connect()");
     return 1;
   }

 nbytes = snprintf (buffer, 256, "ping");
 send_message (socket_fd, buffer, nbytes, 1);
 
 nbytes = read (socket_fd, buffer, 256);
 buffer[nbytes] = 0;

 printf("MESSAGE FROM SERVER: %s\n", buffer);

 close (socket_fd);

 return 0;
}
