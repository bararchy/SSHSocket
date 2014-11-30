SSHSocket
=========

A Ruby impelementaiotn of the SSH Server Side Protocol using ffi 

Usage:

```ruby
require 'sshsocket'

sock = SSHSocket::Socket.new(rsakey: '/path/to/ssh_host_rsa_key', 
			   		 dsakey: '/path/to/ssh_host_dsa_key',
			   		 password: 'test',
			   		 user: 'test',
			   		 port: '5555',
			   		 listen_address: '0.0.0.0',
			   		 banner: 'my_SSH',
			   		 timeout: "300")
sock.listen
sock.close
```
 Licensed under: The MIT License (MIT)

Thanks: 
* @ik5 (idokan@gmail.com).
