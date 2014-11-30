require 'ffi'
require_relative 'sshsocket/api'

module SSHSocket
    class Socket

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
            raise ArgumentError.new('Configuration Error: rsa file is missing') unless @rsakey
            raise ArgumentError.new('Configuration Error: dsa file is missing') unless @dsakey
            raise ArgumentError.new('Configuration Error: no port given to liten on') if ! @port	
            raise ArgumentError.new('Configuration Error: Missing credentials') if ! @user_name || ! @password

            @sshbind = API.ssh_bind_new # initialize the ssh session instance
            # Configure the session intance
            API::SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, API::Bind_Options::SSH_BIND_OPTIONS_BINDADDR, :string, @listen_address) if @listen_address
            API::SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, API::Bind_Options::SSH_BIND_OPTIONS_BINDPORT_STR, :string, @port) if @port
            API::SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, API::Bind_Options::SSH_BIND_OPTIONS_RSAKEY, :string, @rsakey) if @rsakey
            API::SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, API::Bind_Options::SSH_BIND_OPTIONS_DSAKEY, :string, @dsakey) if @dsakey
            API::SSHSocket_Module.ssh_options_set(@sshbind, :int, API::General_Options::SSH_OPTIONS_TIMEOUT, :string, @timeout) if @timeout
            API::SSHSocket_Module.ssh_bind_options_set(@sshbind, :int, API::Bind_Options::SSH_BIND_OPTIONS_BANNER, :string, @banner) if @banner
        end

        def listen

            @sshsession = API.ssh_new
            API.ssh_bind_listen(@sshbind)
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
end
