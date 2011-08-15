import socket
s = socket.socket(socket.AF_UNIX)
path = "/tmp/test/socket"
s.bind (path)
s.listen(5)
a = s.accept ()
print a
