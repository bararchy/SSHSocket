require 'rubygems'
require 'ffi'
require 'thread'
require 'socket'
require 'hex_string'
# Defs
threads = []
max_threads = 5
pass = "testing"
user = "unshadow"

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
	attach_function :ssh_bind_accept_fd, [:pointer, :pointer, :int], :string
	attach_function :ssh_message_subtype, [:string], :string
	attach_function	:ssh_message_auth_user, [:string], :string
	attach_function	:ssh_message_auth_password, [:string], :string
	attach_function :ssh_message_free, [:string], :string
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
	unless result.nil? || result.kind_of?(String) || result <= 0
		if pointer.nil?
			puts "Error #{result.to_i}"
			exit 1
		else
			puts "Error #{result.to_i}: #{SSHSocket.ssh_get_error(pointer)}"
			exit 1
		end
	end
	if result.kind_of?(String) && result.empty?
		puts "Error #{result.to_i}: #{SSHSocket.ssh_get_error(pointer)}"
		exit 1
	else
		puts "No Error: #{result}"
	end
end 

def initialize_ssh
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
	return sshbind, sshsession
end

sshbind,sshsession = initialize_ssh
SSHSocket.ssh_bind_accept(sshbind, sshsession)
result = SSHSocket.ssh_handle_key_exchange(sshsession)
msg = SSHSocket.ssh_message_get(sshsession)
type = SSHSocket.ssh_message_type(msg)
puts msg.to_hex_string.to_byte_string
#puts type.unpack('U'*type.length).collect {|x| x.to_s 16}.join
exit 0
case type
	when /SSH_REQUEST_AUTH/
		subtype = SSHSocket.ssh_message_subtype(msg)
		puts subtype
		case subtype
			when /SSH_AUTH_METHOD_PASSWORD/
				user_ssh = SSHSocket.ssh_message_auth_user(msg)
				pass_ssh = SSHSocket.ssh_message_auth_password(msg)
				puts user_ssh, pass_ssh
		end	
	else
		SSHSocket.ssh_message_free(msg)
end
