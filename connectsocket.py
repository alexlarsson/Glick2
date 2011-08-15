import socket
s = socket.socket(socket.AF_UNIX, 5)
path = "/tmp/test/socket"
s.connect (path)
