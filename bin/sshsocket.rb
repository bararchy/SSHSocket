#!/usr/bin/env ruby
require 'rubygems'
require 'bundler'
Bundler.require(:default)

# Defs
module SSHSocket_Module
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
	attach_function :ssh_options_set, [SSH_bind_struct, :varargs], :int
	attach_function :ssh_bind_listen, [SSH_bind_struct], :int
	attach_function :ssh_disconnect, [SSH_new_session], :int
	attach_function :ssh_bind_accept, [SSH_bind_struct, SSH_new_session], :int
	attach_function :ssh_get_error, [SSH_new_session], :string
	attach_function :ssh_handle_key_exchange, [SSH_new_session], :int
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
	attach_function :ssh_message_channel_request_reply_success, [SSH_message], :int
end

module General_Options
	SSH_OPTIONS_HOST = 0
	SSH_OPTIONS_PORT = 1
	SSH_OPTIONS_PORT_STR = 2
	SSH_OPTIONS_FD = 3
	SSH_OPTIONS_USER = 4
	SSH_OPTIONS_SSH_DIR = 5
	SSH_OPTIONS_IDENTITY = 6
	SSH_OPTIONS_ADD_IDENTITY = 7
	SSH_OPTIONS_KNOWNHOSTS = 8
	SSH_OPTIONS_TIMEOUT = 9
	SSH_OPTIONS_TIMEOUT_USEC = 10
	SSH_OPTIONS_SSH1 = 11
	SSH_OPTIONS_SSH2 = 12
	SSH_OPTIONS_LOG_VERBOSITY = 13
	SSH_OPTIONS_LOG_VERBOSITY_STR = 14
	SSH_OPTIONS_CIPHERS_C_S = 15
	SSH_OPTIONS_CIPHERS_S_C = 16
	SSH_OPTIONS_COMPRESSION_C_S = 17
	SSH_OPTIONS_COMPRESSION_S_C = 18
	SSH_OPTIONS_PROXYCOMMAND = 19
	SSH_OPTIONS_BINDADDR = 20
	SSH_OPTIONS_STRICTHOSTKEYCHECK = 21
	SSH_OPTIONS_COMPRESSION = 22
	SSH_OPTIONS_COMPRESSION_LEVEL = 23
	SSH_OPTIONS_KEY_EXCHANGE = 24
	SSH_OPTIONS_HOSTKEYS = 25
	SSH_OPTIONS_GSSAPI_SERVER_IDENTITY = 26
	SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY = 27
	SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS = 28
	SSH_OPTIONS_HMAC_C_S = 29
	SSH_OPTIONS_HMAC_S_C = 30
end

module Bind_Options
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

class SSHSocket
	
	def initialize(options={})

		@user_name		||= options[:user]			 rescue nil
		@password       ||=	options[:password]		 rescue nil
		@rsakey         ||= options[:rsakey]         rescue nil
		@dsakey         ||= options[:dsakey]         rescue nil
		@port           ||= options[:port]           rescue nil
		@listen_address ||= options[:listen_address] rescue nil
		@timeout        ||= options[:timeout]        rescue nil
		@banner         ||= options[:banner]         rescue nil

		# Some senity cheks
		raise ArgumentError.new('Configuration Error: rsa key is given but dsa key is missing !') if @rsakey && ! @dsakey
		raise ArgumentError.new('Configuration Error: no port given to liten on') if ! @port	
		raise ArgumentError.new('Configuration Error: Missing user or password') if ! @user_name || ! @password
		
		@sshbind = SSHSocket_Module.ssh_bind_new # initialize the ssh session instance
		# Configure the session intance
		SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, Bind_Options::SSH_BIND_OPTIONS_BINDADDR, :string, @listen_address) if @listen_address
		SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, Bind_Options::SSH_BIND_OPTIONS_BINDPORT_STR, :string, @port) if @port
		SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, Bind_Options::SSH_BIND_OPTIONS_RSAKEY, :string, @rsakey) if @rsakey
		SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, Bind_Options::SSH_BIND_OPTIONS_DSAKEY, :string, @dsakey) if @dsakey
		SSHSocket_Module.ssh_options_set(@sshbind, :int, General_Options::SSH_OPTIONS_TIMEOUT, :string, @timeout) if @timeout
		SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, Bind_Options::SSH_BIND_OPTIONS_BANNER, :string, @banner) if @banner
	end

	def listen

		@sshsession = SSHSocket_Module.ssh_new
		SSHSocket_Module.ssh_bind_listen(@sshbind)
		accept = SSHSocket_Module.ssh_bind_accept(@sshbind, @sshsession)
		unless accept >= 0
			puts 'Error in version exchange phase'
			SSHSocket_Module.ssh_bind_free(@sshbind)
			exit 1
		end
		exchange = SSHSocket_Module.ssh_handle_key_exchange(@sshsession)
		unless exchange >= 0
			puts 'Error in key exchange phase'
			SSHSocket_Module.ssh_bind_free(@sshbind)
			exit 1	
		end
		auth_loop
		chan_loop
		shell_loop
	end
	
	def close	
		SSHSocket_Module.ssh_bind_free(@sshbind)
		SSHSocket_Module.ssh_disconnect(@sshsession)
	end


	private
	def auth_loop
		# Authentication loop
		try = 0
		while true
			msg = SSHSocket_Module.ssh_message_get(@sshsession)
			next unless msg
			type = SSHSocket_Module.ssh_message_type(msg)
			next unless type > -1
			case type
				when Messages_General::SSH_REQUEST_AUTH
					subtype = SSHSocket_Module.ssh_message_subtype(msg)
					puts "subtype is: #{subtype}"
					case subtype
						when Messages_Auth::SSH_AUTH_METHOD_PASSWORD
							user_ssh = SSHSocket_Module.ssh_message_auth_user(msg)
							pass_ssh = SSHSocket_Module.ssh_message_auth_password(msg)
							puts "Got user: #{user_ssh} and pass: #{pass_ssh}"
							if user_ssh == @user_name && pass_ssh == @password
								puts "Password Auth OK"
								SSHSocket_Module.ssh_message_auth_reply_success(msg,0)
								SSHSocket_Module.ssh_message_free(msg)
								break
							else
								puts "Wrong username or password"
								SSHSocket_Module.ssh_message_reply_default(msg)
								try = try + 1
								break if try > 2
								next
							end
						when Messages_Auth::SSH_AUTH_METHOD_NONE
							puts "User #{SSHSocket_Module.ssh_message_auth_user(msg)} wants to auth with unknown auth #{SSHSocket_Module.ssh_message_subtype(msg)}\n"
							SSHSocket_Module.ssh_message_auth_set_methods(msg, Messages_Auth::SSH_AUTH_METHOD_PASSWORD)
							SSHSocket_Module.ssh_message_reply_default(msg)
					end	
				else
					SSHSocket_Module.ssh_message_auth_set_methods(msg, Messages_Auth::SSH_AUTH_METHOD_PASSWORD)
					SSHSocket_Module.ssh_message_reply_default(msg)
			end
		end
	end

	def chan_loop
		# Channel Loop
		while true
			msg = SSHSocket_Module.ssh_message_get(@sshsession)
			puts "messge is: #{msg}"
			next unless msg 
			type = SSHSocket_Module.ssh_message_type(msg)
			next unless type > -1
			subtype = SSHSocket_Module.ssh_message_subtype(msg)
			if type == Messages_General::SSH_REQUEST_CHANNEL_OPEN && subtype == 1
				chan = SSHSocket_Module.ssh_message_channel_request_open_reply_accept(msg)
				puts "We got a request to open a channel #{chan}"
				break
			else
				SSHSocket_Module.ssh_message_reply_default(msg)
				SSHSocket_Module.ssh_message_free(msg)
			end
		end
	end

	def shell_loop
		while true
			msg = SSHSocket_Module.ssh_message_get(@sshsession)
			next unless msg
			type = SSHSocket_Module.ssh_message_type(msg)
			next unless type > -1
			subtype = SSHSocket_Module.ssh_message_subtype(msg)
			if type == Messages_General::SSH_REQUEST_CHANNEL && subtype == 3
				SSHSocket_Module.ssh_message_channel_request_reply_success(msg)
				SSHSocket_Module.ssh_message_free(msg)
				puts "We got a request to open a shell"
				break
			else
				SSHSocket_Module.ssh_message_reply_default(msg)
				SSHSocket_Module.ssh_message_free(msg)
			end
		end
	end
end
