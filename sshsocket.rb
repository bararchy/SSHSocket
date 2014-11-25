require 'rubygems'
require 'ffi'


module SSHSocket
  	extend FFI::Library
	ffi_lib_flags :now, :global
	ffi_lib 'libssh'
	attach_function :ssh_init, [], :int
	attach_function :ssh_bind_new, [], :pointer
	attach_function :ssh_new, [], :pointer
	attach_function :ssh_bind_options_set, [:pointer, :varargs], :int
	attach_function :ssh_bind_listen, [:pointer], :int
	attach_function :ssh_bind_accept, [:pointer, :pointer], :string
	attach_function :ssh_get_error, [:pointer], :string
	attach_function :ssh_handle_key_exchange, [:pointer], :string
	attach_function :ssh_message_get, [:pointer], :string
	attach_function :ssh_message_type, [:string], :string
end

module Options
	SSH_BIND_OPTIONS_BINDADDR = 0
	SSH_BIND_OPTIONS_BINDPORT = 1
	SSH_BIND_OPTIONS_BINDPORT_STR = 2
	SSH_BIND_OPTIONS_HOSTKEY = 3
	SSH_BIND_OPTIONS_DSAKEY = 4
	SSH_BIND_OPTIONS_RSAKEY = 5
	SSH_BIND_OPTIONS_BANNER = 6
	SSH_BIND_OPTIONS_LOG_VERBOSITY = 7
	SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = 8
	SSH_BIND_OPTIONS_ECDSAKEY = 9
end


def check_error(result, pointer)
	if result.class != String && result != nil && result < 0
		puts "Error #{result.to_i}: #{SSHSocket.ssh_get_error(pointer)}"
		exit 1
	elsif result.class == String && result == ""
		puts "Error #{result.to_i}: #{SSHSocket.ssh_get_error(pointer)}"
		exit 1
	else
		puts "No Error: #{result}"
	end
end


begin
	sshbind = SSHSocket.ssh_bind_new
	# Configure the session
	result = SSHSocket.ssh_bind_options_set(sshbind, :int, Options::SSH_BIND_OPTIONS_BINDADDR, :string, "0.0.0.0")
	check_error(result, sshbind)
	result = SSHSocket.ssh_bind_options_set(sshbind, :int, Options::SSH_BIND_OPTIONS_BINDPORT_STR, :string, "5555")
	check_error(result, sshbind)
	result = SSHSocket.ssh_bind_options_set(sshbind, :int, Options::SSH_BIND_OPTIONS_RSAKEY, :string, "/home/unshadow/Desktop/keys_for_ssh/ssh_host_rsa_key")
	check_error(result, sshbind)
	result = SSHSocket.ssh_bind_options_set(sshbind, :int, Options::SSH_BIND_OPTIONS_DSAKEY, :string, "/home/unshadow/Desktop/keys_for_ssh/ssh_host_dsa_key")
	check_error(result, sshbind)
	sshsession = SSHSocket.ssh_new
	result = SSHSocket.ssh_bind_listen(sshbind)
	check_error(result, sshbind)
	result = SSHSocket.ssh_bind_accept(sshbind, sshsession)
	puts "should return 'SSH_OK': #{result}"
	result = SSHSocket.ssh_handle_key_exchange(sshsession)
	check_error(result, sshsession)
	msg = SSHSocket.ssh_message_get(sshsession)
	puts msg
	type = SSHSocket.ssh_message_type(msg)
	puts type
rescue Exception => e
	puts "Error #{e.message}"
	puts "Error #{e.backtrace}"	
end