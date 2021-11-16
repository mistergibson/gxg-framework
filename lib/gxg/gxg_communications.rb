# ### GxG Communications Layer
# Note: MatrixClient --> 64K max message size (gross), less than 1K overhead --> so, 63K max payload size (64512 bytes).
module GxG
    BRIDGES = {}
    BRIDGES_AVAILABLE = {}
    module Communications
        BRIDGE_THREAD_SAFETY = ::Mutex.new
        def self.bridge(the_uuid)
            if ::GxG::valid_uuid?(the_uuid)
                BRIDGE_THREAD_SAFETY.synchronize { ::GxG::BRIDGES[(the_uuid)] }
            else
                nil
            end
        end
        #
        def self.open_bridge(process=nil, the_url=nil, options=nil)
            new_bridge = ::GxG::Communications::Bridge.new(process, the_url, options)
            BRIDGE_THREAD_SAFETY.synchronize { ::GxG::BRIDGES[(new_bridge.uuid)] = new_bridge }
            new_bridge.uuid
        end
        #
        def self.close_bridge(the_uuid=nil)
            if ::GxG::valid_uuid?(the_uuid)
                the_bridge = BRIDGE_THREAD_SAFETY.synchronize { ::GxG::BRIDGES.delete(the_uuid) }
                if the_bridge
                    the_bridge.close
                    timeout = ::Chronic::parse("30 seconds from now").to_f
                    while the_bridge.open? do
                        sleep 1.0
                        if Time.now.to_f >= timeout
                            break
                        end
                    end
                end
                true
            else
                false
            end
        end
        # ### Adapters
        class BridgeAdapter
            # WARNING: Only instantiate subclasses
            def self.protocol()
                :unspecified
            end
            #
            def self.abilities()
                []
            end
            #
            def self.limits()
                {}
            end
            #
            def self.templates()
                {}
            end
            #
            def initialize(the_process=nil, the_url=nil, options=nil)
                if the_url.is_a?(::String)
                    the_url = ::URI::parse(the_url)
                end
                unless the_url.is_a?(::URI::Generic)
                    raise ArgumentError, "You MUST provide a valid URL as a String or URI."
                end
                unless the_process
                    raise ArgumentError, "You MUST provide a Service or Application object to interact with."
                end
                @process = the_process
                @url = the_url
                @options = (options || {})
                unless @options.is_a?(::Hash)
                    raise ArgumentError, "You must provide options as a Hash."
                end
                @active = false
                @connector = nil
                @thread_safety = ::Mutex.new
                #
                @uuid = ::GxG::uuid_generate.to_sym
                self
            end
            #
            def uuid()
                @uuid
            end
            #
            def my_id()
                nil
            end
            #
            def open?()
                if @connector
                    if @connector.closed?
                        @active = false
                    else
                        @active = true
                    end
                end
                @active
            end
            #
            def open()
                unless self.open?
                    @active = @connector.login(@url, @options)
                end
                @active
            end
            #
            def close()
                if self.open?
                    @connector.logout()
                    @active = false
                end
                true
            end
            # ### Information Refresh
            def notify(details=nil)
                #
            end
            #
            # ### Basic Entity Support
            def entitiies()
                []
            end
            #
            def entity_status(the_address=nil)
                :online
            end
            # ### Basic Channel Support
            def channels()
                {}
            end
        end
        # ### Matrix
        class BridgeAdapterMatrix < ::GxG::Communications::BridgeAdapter
            def self.protocol()
                :"matrix-https"
            end
            #
            def self.abilities()
                [:message, :file_transfer, :request]
            end
            #
            def self.limits()
                {:message_size => 64512, :file_transfer_size => nil, :request_size => 64512}
            end
            #
            def self.templates()
                {}
            end
            #
            private
            def decode_message(the_message=nil)
                result = message
                if message.is_a?(::GxG::Events::Message)
                    fallback_key = nil
                    key = nil
                    message_sender = message[:sender].to_s
                    @thread_safety.synchronize {
                        if @keychain[(message_sender.to_s)]
                            fallback_key = @keychain[(message_sender.to_s)][:original]
                            key = @keychain[(message_sender.to_s)][:current]
                        end
                    }
                    new_body = nil
                    if key && fallback_key
                        if message[:body].is_a?(::String)
                            begin
                                if message[:body].base64?
                                    new_body = message[:body].decode64.decrypt(key)
                                else
                                    new_body = message[:body].decrypt(key)
                                end
                                new_body = ::Hash::gxg_import(::JSON::parse(new_body, {:symbolize_names => true}))
                            rescue Exception => the_error
                                begin
                                    if message[:body].base64?
                                        new_body = message[:body].decode64.decrypt(fallback_key)
                                    else
                                        new_body = message[:body].decrypt(fallback_key)
                                    end
                                    new_body = ::Hash::gxg_import(::JSON::parse(new_body, {:symbolize_names => true}))
                                rescue Exception => the_error
                                    message[:bridge_unintelligible] = true
                                    log_error({:error => the_error})
                                    new_body = nil
                                end
                            end
                        end
                    else
                        if message[:body].is_a?(::String)
                            if message[:body].base64?
                                new_body = message[:body].decode64
                            else
                                new_body = message[:body]
                            end
                            begin
                                new_body = ::Hash::gxg_import(::JSON::parse(new_body, {:symbolize_names => true}))
                            rescue Exception => the_error
                                log_error({:error => the_error})
                                new_body = nil
                            end
                        end
                    end
                    if new_body.is_a?(::Hash)
                        message[:body] = new_body
                    end
                end
                result
            end
            #
            public
            #
            def initialize(the_process=nil, the_url=nil, options={:sasl => :digest, :digest => true})
                super(the_process, the_url, options)
                unless @options[:sasl]
                    @options = {:sasl => :digest, :digest => true}
                end
                #
                # Channels format: {<uuid> => {:channel => <XMPPConversation>, :entities => [<jid-string>, ...]}}
                @channels = {}
                # Keychain format: {:original => "", :current => ""}
                @keychain = {}
                # Messages format: {<uuid> => [<::GxG::Events::Message>, ...]}
                @messages = {}
                @messages_busy_semaphore = false
                @invitations = {}
                @file_transfers = {}
                #
                @connector = ::GxG::Networking::MatrixClient.new(the_url)
                self.open
                #
                self
            end
            #
            def my_id()
                if @connector
                    @connector.my_jid.to_s
                else
                    nil
                end
            end
            # ### Information Refresh
            def notify(details=nil)
                # Review : totally re-write this --> VFS integration, Matrix-based approach (adapt)
                if details.is_a?(::Hash)
                    if @process
                        if @process.respond_to?(:dispatcher) && @process.respond_to?(:respond_to_event?)
                            case details[:event]
                            when :new_invitation
                                active_list = {}
                                @connector.invitations.each do |the_invitation|
                                    active_list[(the_invitation.uuid)] = {:invitation => the_invitation, :title => the_invitation[:title].to_s, :sender => the_invitation[:sender].to_s, :type => the_invitation[:type].to_s}
                                end
                                @thread_safety.synchronize { @invitations = active_list }
                                #
                                if @process.respond_to_event?(:new_invitation)
                                    @process.dispatcher.post_event(:communications) do
                                        @process.call_event({:new_invitation => {:invitation => details[:invitation], :sender => details[:sender], :at => ::DateTime.now}})
                                    end
                                end
                            when :new_file_transfer
                                # First, update Bridge Manifest
                                active_list = {}
                                @connector.file_transfers.each do |the_transfer|
                                    reference = the_transfer.reference
                                    file_name = the_transfer.file_details[:filename]
                                    file_size = the_transfer.file_details[:size]
                                    sender = the_transfer.info[:sender]
                                    # set download path
                                    unless ::File.exists?(GxG::SYSTEM_PATHS[:temporary] + "/" + reference.to_s)
                                        ::FileUtils.mkpath(GxG::SYSTEM_PATHS[:temporary] + "/" + reference.to_s)
                                    end
                                    the_transfer.download_directory = (GxG::SYSTEM_PATHS[:temporary] + "/" + reference.to_s)
                                    # store entry
                                    active_list[(reference)] = {:transfer => the_transfer, :sender => sender, :file => file_name, :size => file_size, :path => ("/System/Temporary/" + reference.to_s + "/" + file_name)}
                                end
                                @thread_safety.synchronize { @file_transfers = active_list }
                                if @process.respond_to_event?(:new_file_transfer)
                                    @process.dispatcher.post_event(:communications) do
                                        @process.call_event({:new_file_transfer => {:transfer => details[:transfer], :sender => details[:sender], :at => ::DateTime.now}})
                                    end
                                end
                            when :file_transfer_complete, :file_transfer_cancelled, :file_transfer_error
                                notification = {}
                                notification[(details[:event])] = {:transfer => details[:transfer], :at => ::DateTime.now}
                                #
                                active_list = {}
                                @connector.file_transfers.each do |the_transfer|
                                    reference = the_transfer.reference
                                    file_name = the_transfer.file_details[:filename]
                                    file_size = the_transfer.file_details[:size]
                                    sender = the_transfer.info[:sender]
                                    # store entry
                                    active_list[(reference)] = {:transfer => the_transfer, :sender => sender, :file => file_name, :size => file_size, :path => ("/System/Temporary/" + reference.to_s + "/" + file_name)}
                                end
                                @thread_safety.synchronize { @file_transfers = active_list }
                                #
                                if @process.respond_to_event?(details[:event])
                                    @process.call_event(notification)
                                end
                            when :file_transfer_progress
                                if @process.respond_to_event?(:file_transfer_progress)
                                    @process.call_event({:file_transfer_progress => {:transfer => details[:transfer], :progress => details[:progress], :at => ::DateTime.now}})
                                end
                            when :new_message, :new_private_message, :new_announcement, :new_error
                                # ### unless channel exists - add it
                                the_channel = @thread_safety.synchronize { @channels[(details[:conversation].to_sym)] }
                                unless the_channel
                                    found = nil
                                    @connector.conversations.each do |channel_object|
                                        if details[:conversation].to_sym == channel_object.uuid
                                            found = channel_object
                                            break
                                        end
                                    end
                                    if found
                                        @thread_safety.synchronize { @channels[(details[:conversation].to_sym)] = {:channel => found, :title => found.title()}}
                                        the_channel = found
                                    end
                                end
                                # ### get messages
                                if the_channel
                                    unless @thread_safety.synchronize { @messages[(the_channel.uuid)].is_a?(::Array) }
                                        @thread_safety.synchronize { @messages[(the_channel.uuid)] = [] }
                                    end
                                    the_channel.process_received() do |the_message|
                                        # Note: this will pick up other messages from the adapter now, but it is ok - a notification will be generated on EACH message.
                                        the_message[:channel] = the_channel.uuid
                                        @thread_safety.synchronize { @messages[(the_channel.uuid)] << the_message }
                                    end
                                end
                                # Review : differentiate beteween private and open messages? How to do?
                                if @process.respond_to_event?(:new_message)
                                    notification = {}
                                    notification[:new_message] = {:channel => details[:conversation], :message => details[:message], :sender => details[:sender].to_s, :at => ::DateTime.now}
                                    #
                                    @process.dispatcher.post_event(:communications) do
                                        @process.call_event(notification)
                                    end
                                end
                                #
                            end
                        end
                    end
                end
            end
            # ### Keychain
            def set_key(recipient=nil, password=nil)
                result = false
                if recipient.to_s.valid_jid? && password.is_a?(::String)
                    @thread_safety.synchronize {
                        if @keychain[(recipient.to_s)]
                            @keychain[(recipient.to_s)][:current] = password
                        else
                            @keychain[(recipient.to_s)] = {:original => password, :current => password}
                        end
                        result = true
                    }
                end
                result
            end
            # ### Invitations
            def accept_invitation(the_invitation_uuid=nil)
                result = false
                if ::GxG::valid_uuid?(the_invitation_uuid)
                    found = nil
                    @thread_safety.synchronize {
                        found = @invitations[(the_invitation_uuid.to_sym)]
                    }
                    if found
                        found[:invitation].accept()
                        result = true
                    end
                end
                result
            end
            #
            def decline_invitation(the_invitation_uuid=nil)
                result = false
                if ::GxG::valid_uuid?(the_invitation_uuid)
                    found = nil
                    @thread_safety.synchronize {
                        found = @invitations[(the_invitation_uuid.to_sym)]
                    }
                    if found
                        found[:invitation].decline()
                        result = true
                    end
                end
                result
            end
            # ### File Transfers
            def file_transfers()
                result = {}
                @thread_safety.synchronize {
                    @file_transfers.each_pair do |the_uuid, the_record|
                        result[(the_uuid)] = {:sender => the_record[:sender], :file => the_record[:file], :size => the_record[:size], :path => the_record[:path]}
                    end
                }
                result
            end
            #
            def accept_file_transfer(the_transfer_uuid=nil)
                result = false
                if ::GxG::valid_uuid?(the_transfer_uuid)
                    found = nil
                    @thread_safety.synchronize {
                        found = @file_transfers[(the_transfer_uuid.to_sym)]
                    }
                    if found
                        found[:transfer].accept()
                        result = true
                    end
                end
                result
            end
            #
            def decline_file_transfer(the_transfer_uuid=nil)
                result = false
                if ::GxG::valid_uuid?(the_transfer_uuid)
                    found = nil
                    @thread_safety.synchronize {
                        found = @file_transfers[(the_transfer_uuid.to_sym)]
                    }
                    if found
                        found[:transfer].decline()
                        if ::File.exists?(GxG::SYSTEM_PATHS[:temporary] + "/" + found[:transfer].reference.to_s)
                            ::GxG::VFS.rmdir("/System/Temporary/" + found[:transfer].reference.to_s)
                        end
                        result = true
                    end
                end
                result
            end
            #
            def cancel_file_transfer(the_transfer_uuid=nil)
                result = false
                if ::GxG::valid_uuid?(the_transfer_uuid)
                    found = nil
                    @thread_safety.synchronize {
                        found = @file_transfers[(the_transfer_uuid.to_sym)]
                    }
                    if found
                        found[:transfer].cancel()
                        if ::File.exists?(GxG::SYSTEM_PATHS[:temporary] + "/" + found[:transfer].reference.to_s)
                            ::GxG::VFS.rmdir("/System/Temporary/" + found[:transfer].reference.to_s)
                        end
                        result = true
                    end
                end
                result
            end
            # ### Entities
            def entities()
                result = []
                @connector.buddies().each do |record|
                    new_record = {:id => "", :title => "Untitled", :groups => [], :status => :offline}
                    new_record[:id] = record[:jid]
                    new_record[:title] = record[:title]
                    new_record[:groups] = record[:groups]
                    case record[:status]
                    when :chat, :normal, :available
                        new_record[:status] = :online
                    when :dnd
                        new_record[:status] = :busy
                    when :away
                        new_record[:status] = :away
                    when :xa
                        new_record[:status] = :extended_away
                    when :unavailable, :offline
                        new_record[:status] = :offline
                    when :error
                        new_record[:status] = :error
                    end
                    result << new_record
                end
                result
            end
            #
            def entity_status(the_address=nil)
                result = :invalid_address
                if the_address.valid_jid?()
                    result = :unknown_address
                    self.entities.each do |the_record|
                        if the_record[:id] == the_address
                            result = the_record[:status]
                            break
                        end
                    end
                end
                result
            end
            #
            def status()
                result = :offline
                case @adapter.get_status
                when :chat, :normal, :available
                    result = :online
                when :dnd
                    result = :busy
                when :away
                    result = :away
                when :xa
                    result = :extended_away
                when :unavailable, :offline
                    result = :offline
                when :error
                    result = :error
                end
                result                
            end
            #
            def status=(the_status=nil, message=nil)
                result = :available
                case the_status
                when :online
                    result = :available
                when :busy
                    result = :dnd
                when :away
                    result = :away
                when :extended_away
                    result = :xa
                when :offline
                    result = :unavailable
                when :error
                    result = :error
                end
                @adapter.set_status(result, message)
            end
            # ### Basic Channel Support
            def channels()
                result = {}
                @thread_safety.synchronize {
                    @channels.each_pair do |the_uuid, the_record|
                        result[(the_uuid)] = the_record[:title]
                    end
                }
                result
            end
            #
            def associate(recipient=nil)
                result = false
                if recipient.is_a?(::String)
                    if recipient.valid_jid?
                        @adapter.add_buddy(recipient)
                        result = true
                    end
                end
                result
            end
            #
            def disassociate(recipient=nil)
                result = false
                if recipient.is_a?(::String)
                    if recipient.valid_jid?
                        @adapter.remove_buddy(recipient)
                        result = true
                    end
                end
                result
            end
            #
            def open_channel(with_jid=nil, password=nil, configuration={})
                result = nil
                if with_jid.is_a?(::String)
                    if with_jid.valid_jid? && configuration.is_any?(::Hash, ::GxG::Database::PersistedHash)
                        # If channel already exists and they attempt a repeat opening action:
                        @thread_safety.synchronize {
                            @channels.each_pair do |the_uuid, the_record|
                                if with_jid.to_s == the_record.jid.to_s
                                    result = the_record.uuid
                                    break
                                end
                            end
                        }
                        unless result
                            # Channel needs to be constructed:
                            if @connector.create_conversation(with_jid, password, configuration) == true
                                existing_channels = self.channels()
                                found = nil
                                @thread_safety.synchronize {
                                    @connector.conversations.each do |channel_object|
                                        if existing_channels.keys.include?(channel_object.uuid)
                                            next
                                        else
                                            found = channel_object
                                            @channels[(channel_object.uuid)] = {:channel => found, :title => found.title()}
                                            break
                                        end
                                    end
                                }
                                if found
                                    result = channel_object.uuid
                                    if password
                                        if channel_object[:type] == :chat
                                            # on :groupchat password is only used for access, not encryption.
                                            self.set_key(with_jid, password)
                                        end
                                    end
                                end
                                #
                            end
                        end
                    end
                end
                result
            end
            #
            def join_channel(channel_jid=nil, password=nil, options={})
                result = nil
                if channel_jid.is_a?(::String)
                    if channel_jid.valid_jid? && options.is_any?(::Hash, ::GxG::Database::PersistedHash)
                        if @connector.join_conversation(channel_jid, password, options) == true
                            existing_channels = self.channels()
                            found = nil
                            @thread_safety.synchronize {
                                @connector.conversations.each do |channel_object|
                                    if existing_channels.keys.include?(channel_object.uuid)
                                        next
                                    else
                                        found = channel_object
                                        @channels[(channel_object.uuid)] = {:channel => found, :title => found.title()}
                                        break
                                    end
                                end
                            }
                            if found
                                result = channel_object.uuid
                            end
                            #
                        end
                    end
                end
                result
            end
            #
            def close_channel(the_channel_uuid=nil)
                if ::GxG::valid_uuid?(the_channel_uuid)
                    the_channel = nil
                    @thread_safety.synchronize {
                        if @channels[(the_channel_uuid.to_sym)].is_a?(::Hash)
                            the_channel = @channels.delete(the_channel_uuid.to_sym)[:channel]
                        end
                    }
                    if the_channel
                        the_channel.leave("{ \"exit_channel\":\"#{the_channel.my_jid.to_s}\" }")
                        true
                    else
                        false
                    end
                else
                    false
                end
            end
            # ### Messages
            def send_message(the_channel_uuid=nil, message=nil, recipient=nil, use_fallback_key=false)
                result = false
                # 
                if ::GxG::valid_uuid?(the_channel_uuid)
                    the_channel = nil
                    @thread_safety.synchronize {
                        if @channels[(the_channel_uuid.to_sym)].is_a?(::Hash)
                            the_channel = @channels[(the_channel_uuid.to_sym)][:channel]
                        end
                    }
                    if the_channel
                        if message.is_any?(::String, ::Hash, ::GxG::Database::PersistedHash, ::GxG::Events::Message)
                            if message.is_a?(::String)
                                message = new_message({:sender => @connector.my_jid.to_s, :body => {:message => message}.gxg_export.to_json})
                            end
                            if message.is_a?(::Hash)
                                message = new_message({:sender => @connector.my_jid.to_s, :body => message.gxg_export.to_json})
                            end
                            if message.is_a?(::GxG::Database::PersistedHash)
                                message = new_message({:sender => @connector.my_jid.to_s, :body => message.sync_export.gxg_export.to_json})
                            end
                            if message.is_a?(::GxG::Events::Message)
                                if message[:body].is_a?(::Hash)
                                    message[:body] = message[:body].gxg_export.to_json
                                end
                                if message[:body].is_a?(::GxG::Database::PersistedHash)
                                    message[:body] = message[:body].sync_export.gxg_export.to_json
                                end
                            end
                            #
                            if message.is_a?(::GxG::Events::Message)
                                # Reset :sender if a ruby object is the current setting. (bridge addressing translation)
                                unless message[:sender].is_a?(::String)
                                    message[:sender] = @connector.my_jid.to_s
                                end
                                # encrypt body?
                                key = nil
                                if recipient.is_a?(::String)
                                    intended_recipient = recipient
                                else
                                    intended_recipient = the_channel.jid()
                                end                                
                                @thread_safety.synchronize {
                                    if @keychain[(intended_recipient.to_s)]
                                        if use_fallback_key == true
                                            key = @keychain[(intended_recipient.to_s)][:original]
                                        else
                                            key = @keychain[(intended_recipient.to_s)][:current]
                                        end
                                    end
                                }
                                if key.is_a?(::String)
                                    message[:body] = message[:body].encrypt(key).encode64
                                else
                                    message[:body] = message[:body].encode64
                                end
                                # send message
                                result = the_channel.say_something(message, recipient)
                                # Review : use this next little bit of code in the request/reply code:
                                # if result == true
                                #     message.succeed(message)
                                # else
                                #     message.fail(message)
                                # end
                            end
                        else
                            raise ArgumentError, "You MUST provide the message as a String, Hash, GxG::Database::PersistedHash, or GxG::Events::Message; NOT #{message.class} ."
                        end
                    else
                        raise ArgumentError, "Invalid Channel selector, the Channel was not found: #{the_channel.inspect} . Try opening the channel first."
                    end
                else
                    raise ArgumentError, "Invalid Channel selector: #{the_channel.inspect} . You MUST provide a valid UUID."
                end
                result
            end
            #
            def next_message(the_channel_uuid=nil)
                result = nil
                if ::GxG::valid_uuid?(the_channel_uuid)
                    @thread_safety.synchronize {
                        if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
                            result = @messages[(the_channel_uuid.to_sym)].shift
                        end
                    }
                    if result
                        result = decode_message(result)
                    end
                end
                result
            end
            #
            def all_messages(the_channel_uuid=nil)
                result = []
                if ::GxG::valid_uuid?(the_channel_uuid)
                    @thread_safety.synchronize {
                        if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
                            @messages[(the_channel_uuid.to_sym)].size.times do
                                result << decode_message(@messages[(the_channel_uuid.to_sym)].shift)
                            end
                        end
                    }
                end
                result
            end
            #
            def get_message(the_channel_uuid=nil, the_message_uuid=nil)
                result = nil
                if ::GxG::valid_uuid?(the_channel_uuid) && the_message_uuid
                    @thread_safety.synchronize {
                        if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
                            @messages[(the_channel_uuid.to_sym)].each_with_index do |the_message, the_index|
                                if the_message_uuid == the_message.id()
                                    result = @messages[(the_channel_uuid.to_sym)].delete_at(the_index)
                                    break
                                end
                            end
                        end
                    }
                    if result
                        result = decode_message(result)
                    end
                end
                result
            end
            #
            def get_messages_by_context(the_channel_uuid=nil, the_context_uuid=nil)
                result = []
                if ::GxG::valid_uuid?(the_channel_uuid) && the_context_uuid
                    @thread_safety.synchronize {
                        if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
                            @messages[(the_channel_uuid.to_sym)].each_with_index do |the_message, the_index|
                                if the_context_uuid.to_s.to_sym == the_message[:context].to_s.to_sym
                                    result << @messages[(the_channel_uuid.to_sym)].delete_at(the_index)
                                end
                            end
                        end
                    }
                    if result
                        result = decode_message(result)
                    end
                end
                result
            end
            #
            def get_messages_by_sender(the_channel_uuid=nil, the_sender=nil)
                result = []
                if ::GxG::valid_uuid?(the_channel_uuid) && the_sender
                    @thread_safety.synchronize {
                        if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
                            @messages[(the_channel_uuid.to_sym)].each_with_index do |the_message, the_index|
                                if the_sender.to_s == the_message[:sender].to_s
                                    result << @messages[(the_channel_uuid.to_sym)].delete_at(the_index)
                                end
                            end
                        end
                    }
                    if result
                        result = decode_message(result)
                    end
                end
                result
            end
            #
        end
        #
        class Bridge
            def initialize(process=nil, the_url=nil, options=nil)
                # Note: process (required) is a Service or Application instance only
                unless process.is_a?(::GxG::Services::Service)
                    raise ArgumentError, "You MUST provide a Service or Application instance to bind to."
                end
                # Ensure protocol supported
                if the_url.is_a?(::String)
                    the_url = ::URI::parse(the_url)
                end
                unless the_url.is_a?(::URI::Generic)
                    raise ArgumentError, "You MUST provide a valid URL as a String or URI."
                end
                the_type = ::GxG::BRIDGES_AVAILABLE[(the_url.scheme.to_sym)]
                unless the_type
                    raise ArgumentError, "Sorry, #{the_url.scheme.to_sym.inspect} is not a supported protocol."
                end
                # Variables
                @process = process
                @url = the_url
                @adapter = the_type.new(self, @url, options)
                @uuid = ::GxG::uuid_generate.to_sym
                @interface = {}
                self.on(:interface, "Available Commands") do
                    self.interface()
                end
                self
            end
            #
            def uuid()
                @uuid
            end
            # ### Command Interface
            def on(the_event, description=nil, &block)
              unless the_event.is_a?(::Symbol)
                raise ArgumentError, "You must specify an event listener with a unique Symbol."
              end
              unless block.respond_to?(:call)
                raise ArgumentError, "You must provide an event code block to execute."
              end
              unless description
                description = "{ '#{the_event.to_s}': '(your_data_payload)' }"
              end
              @interface[(the_event)] = {:description => description, :procedure => block}
              true
            end
            #
            def call_event(operation_envelope=nil)
              result = nil
              if operation_envelope.is_a?(::Hash)
                the_event = operation_envelope.keys[0]
                if the_event
                  data = operation_envelope[(the_event)]
                  if @interface[(the_event)]
                    begin
                      result = {:result => @interface[(the_event)][:procedure].call(@process, self, data)}
                    rescue Exception => the_error
                      log_error({:error => the_error, :parameters => {:data => data}})
                      result = {:result => nil, :error => the_error.to_s}
                    end
                  else
                    result = {:result => nil, :error => "Command #{the_event.inspect} Not Found"}
                  end
                end
              end
              result
            end
            #
            def interface()
              result = {}
              @interface.each_pair do |the_event, the_record|
                result[(the_event)] = the_record[:description]
              end
              result
            end
            #
            def respond_to_event?(the_event=nil)
              result = false
              if the_event.is_a?(::Symbol)
                if @interface[(the_event)]
                  result = true
                end
              end
              result
            end
            # ### Request/Reply Support
            def request(the_channel_uuid=nil, request_body=nil, address=nil, options={})
                result = nil
                #
                if ::GxG::valid_uuid?(the_channel_uuid) && request_body.is_a?(::GxG::Events::Message) && address
                    payload = nil
                    context = ::GxG::uuid_generate
                    if address.to_s.valid_jid?
                        # Point-to-Point Request
                        payload = new_message({:sender => @adapter.jid().to_s, :body => request_body})
                        payload[:context] = context.to_s
                        if payload
                            @adapter.send_message(the_channel_uuid, payload, address)
                            the_reply_list = @adapter.get_messages_by_context(the_channel_uuid, context)
                            if options.is_a?(::Hash)
                                if options[:timeout].is_a?(::Numeric)
                                    timeout = Time.now.to_f + options[:timeout].to_f
                                else
                                    timeout = Time.now.to_f + 30.0
                                end
                            else
                                timeout = Time.now.to_f + 30.0
                            end
                            until the_reply_list.size > 0 do
                                the_reply_list = @adapter.get_messages_by_context(the_channel_uuid, context)
                                sleep 0.5
                                if Time.now.to_f >= timeout
                                    break
                                end
                            end
                            if the_reply_list.size > 0
                                result = the_reply_list[0]
                            end
                        end
                    end
                end
                #
                result
            end
            #
            def reply(the_channel_uuid=nil, reply_body=nil, address=nil)
                result = {:result => false}
                if ::GxG::valid_uuid?(the_channel_uuid) && reply_body.is_a?(::GxG::Events::Message) && address
                    @adapter.send_message(the_channel_uuid, reply_body, address)
                    result[:result] = true
                end
                result
            end
        end
        #
    end
end
# ### Register BridgeAdapters by protocol
::GxG::Communications::BridgeAdapter.descendants.each do |the_adapter_class|
    ::GxG::BRIDGES_AVAILABLE[((the_adapter_class)::protocol)] = the_adapter_class
end