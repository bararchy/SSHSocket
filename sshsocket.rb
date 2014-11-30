require 'rubygems'
require 'ffi'
require 'thread'
require 'socket'
require 'hex_string'
# Defs
threads = []
max_threads = 5
pass = "test"
user = "test"

module SSHSocket
  	extend FFI::Library
	ffi_lib_flags :now, :global
	ffi_lib 'libssh'
	class SSH_bind_struct < FFI::Struct
	end
	class SSH_new_session < FFI::Struct
	end
	class SSH_message < FFI::Struct
	end
	class SSH_channel < FFI::Struct
	end
	attach_function :ssh_init, [], :int
	attach_function :ssh_bind_new, [], SSH_bind_struct
	attach_function :ssh_bind_free, [SSH_bind_struct], :int
	attach_function :ssh_new, [], SSH_new_session
	attach_function :ssh_bind_options_set, [SSH_bind_struct, :varargs], :int
	attach_function :ssh_bind_listen, [SSH_bind_struct], :int
	attach_function :ssh_disconnect, [SSH_new_session], :int
	attach_function :ssh_bind_accept, [SSH_bind_struct, SSH_new_session], :string
	attach_function :ssh_get_error, [SSH_new_session], :string
	attach_function :ssh_handle_key_exchange, [SSH_new_session], :string
	attach_function :ssh_message_get, [SSH_new_session], SSH_message
	attach_function :ssh_message_type, [SSH_message], :int
	attach_function :ssh_bind_accept_fd, [:pointer, :pointer, :int], :string
	attach_function :ssh_message_subtype, [SSH_message], :int
	attach_function	:ssh_message_auth_user, [:string], :string
	attach_function	:ssh_message_auth_password, [:string], :string
	attach_function :ssh_message_free, [SSH_message], :int
	attach_function :ssh_message_auth_set_methods, [SSH_message, :int], :int
	attach_function :ssh_message_reply_default, [SSH_message], :int
	attach_function :ssh_message_auth_user, [SSH_message], :string
	attach_function :ssh_message_auth_password, [SSH_message], :string
	attach_function :ssh_message_auth_reply_success, [SSH_message, :int], :int
	attach_function :ssh_message_channel_request_open_reply_accept, [SSH_message], SSH_channel
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

module Messages_General
	SSH_REQUEST_AUTH = 1
 	SSH_REQUEST_CHANNEL_OPEN = 2
	SSH_REQUEST_CHANNEL = 3
	SSH_REQUEST_SERVICE = 4
	SSH_REQUEST_GLOBAL = 5
end
module Messages_Auth
	SSH_AUTH_METHOD_UNKNOWN = 0
	SSH_AUTH_METHOD_NONE = 0x0001
	SSH_AUTH_METHOD_PASSWORD = 0x0002
	SSH_AUTH_METHOD_PUBLICKEY = 0x0004
	SSH_AUTH_METHOD_HOSTBASED = 0x0008
	SSH_AUTH_METHOD_INTERACTIVE = 0x0010
	SSH_AUTH_METHOD_GSSAPI_MIC = 0x0020
end
def check_error(result, pointer)
	unless result.nil? || result.kind_of?(String) || result <= 0
		if pointer.nil?
			puts "Error #{result.to_i}"
		else
			puts "Error #{result.to_i}: #{SSHSocket.ssh_get_error(pointer)}"
		end
	end
	if result.kind_of?(String) && result.empty?
		puts "Error #{result.to_i}: #{SSHSocket.ssh_get_error(pointer)}"
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
SSHSocket.ssh_handle_key_exchange(sshsession)

# Authentication loop

while true
	msg = SSHSocket.ssh_message_get(sshsession)
	puts "messge is: #{msg}"
	unless msg 
		break
	end
	type = SSHSocket.ssh_message_type(msg)
	unless type > -1
		SSHSocket.ssh_message_free(msg)
		break
	end
	puts "type is: #{type}"
	case type
		when Messages_General::SSH_REQUEST_AUTH
			subtype = SSHSocket.ssh_message_subtype(msg)
			puts "subtype is: #{subtype}"
			case subtype
				when Messages_Auth::SSH_AUTH_METHOD_PASSWORD
					user_ssh = SSHSocket.ssh_message_auth_user(msg)
					pass_ssh = SSHSocket.ssh_message_auth_password(msg)
					puts "Got user: #{user_ssh} and pass: #{pass_ssh}"
					if user_ssh == user && pass_ssh == pass
						puts "Password Auth OK"
						SSHSocket.ssh_message_auth_reply_success(msg,0)
						SSHSocket.ssh_message_free(msg)
						break
					else
						puts SSHSocket.ssh_get_error(sshsession)
						SSHSocket.ssh_disconnect(sshsession)
						break
					end
				when Messages_Auth::SSH_AUTH_METHOD_NONE
					puts "User #{SSHSocket.ssh_message_auth_user(msg)} wants to auth with unknown auth #{SSHSocket.ssh_message_subtype(msg)}\n",
					SSHSocket.ssh_message_auth_set_methods(msg, Messages_Auth::SSH_AUTH_METHOD_PASSWORD)# | Messages_Auth::SSH_AUTH_METHOD_INTERACTIVE)
					SSHSocket.ssh_message_reply_default(msg)
			end	
		else
			SSHSocket.ssh_message_auth_set_methods(msg, Messages_Auth::SSH_AUTH_METHOD_PASSWORD)# | Messages_Auth::SSH_AUTH_METHOD_INTERACTIVE)
			SSHSocket.ssh_message_reply_default(msg)
	end
end


# Channel Loop
while true
	msg = SSHSocket.ssh_message_get(sshsession)
	puts "messge is: #{msg}"
	unless msg 
		break
	end
	type = SSHSocket.ssh_message_type(msg)
	unless type > -1
		SSHSocket.ssh_message_free(msg)
		break
	end
	subtype = SSHSocket.ssh_message_subtype(msg)
	if type == Messages_General::SSH_REQUEST_CHANNEL_OPEN && subtype == 1
		chan = SSHSocket.ssh_message_channel_request_open_reply_accept(msg)
		puts "We got a request to open a channel #{chan}"
		break
	else
		SSHSocket.ssh_message_reply_default(msg)
		SSHSocket.ssh_message_free(msg)
	end
end

# Shell loop.to_ruby

 /* wait for a shell */
do {
message = ssh_message_get(session);
if(message != NULL) {
if(ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
shell = 1;
ssh_message_channel_request_reply_success(message);
ssh_message_free(message);
break;
} else if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
ssh_message_channel_request_reply_success(message);
ssh_message_free(message);
continue;
}
}
ssh_message_reply_default(message);
ssh_message_free(message);
} else {
break;
}


SSHSocket.ssh_bind_free(sshbind)
