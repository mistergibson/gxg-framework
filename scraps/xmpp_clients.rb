
# require 'xmpp4r/client'
# require 'xmpp4r/reliable'
# require 'xmpp4r/roster'
# require 'xmpp4r/muc'
# require 'xmpp4r/bytestreams'

# new xmpp client:
# require "blather/client/dsl"
# require "blather/client/dsl/pubsub"
Thread.new { ::EM.run }
# ### MUC extentions for Blather:
# See: https://github.com/maccman/blather and https://github.com/adhearsion/blather/issues/81
# module Blather
#     class Roster
#         def push(elem, send = true, groups = ["Buddies"])
#             jid = elem.respond_to?(:jid) && elem.jid ? elem.jid : JID.new(elem)
#             @items[key(jid)] = node = RosterItem.new(elem)
#             @items[key(jid)].subscription = :both
#             @items[key(jid)].groups = groups
#             @stream.write(node.to_stanza(:set)) if send
#         end
#         alias_method :add, :push
#     end
#     class Client
#         def unbind
#             # Fix bug where closing connection stops EM for ALL Client Instances.
#             # call_handler_for(:disconnected, nil) || (EM.reactor_running? && EM.stop)
#             call_handler_for(:disconnected, nil)
#             true
#         end
#     end
#     #
#     module DSL
#         class MultiUserChat
#           def initialize(client, jid, nickname = nil, password = nil)
#             @client   = client
#             @room     = ::Blather::JID.new(jid)
#             @nickname = nickname || @room.resource
#             @password = password
#             @room.strip!
#           end
          
#           def join(reason = nil)
#             join          = ::Blather::Stanza::Presence::MUCJoin.new
#             join.to       = "#{@room}/#{@nickname}"
#             join.password = @password
#             write join
#           end
          
#           # <presence
#           #     from='wiccarocks@shakespeare.lit/laptop'
#           #     to='darkcave@chat.shakespeare.lit/oldhag'>
#           #   <show>available</show>
#           # </presence>
#           def status=(state)
#             status       = ::Blather::Stanza::Presence::Status.new
#             status.state = state
#             status.to    = @room
#             write status
#           end
          
#           # <message to='room@service'>
#           #   <x xmlns='http://jabber.org/protocol/muc#user'>
#           #     <invite to='jid'>
#           #       <reason>comment</reason>
#           #     </invite>
#           #   </x>
#           # </message>
#           def invite(jid, reason = nil)
#             message = ::Blather::Stanza::Message.new(@room, nil, nil)
#             message << ::Blather::MUC::Invite.new(jid, reason, @password)
            
#             write message
#           end
      
#           # <message to='room@service' type='groupchat'>
#           #   <body>foo</body>
#           # </message>    
#           def say(msg, xhtml = nil)
#             message = ::Blather::Stanza::Message.new(@room, msg, :groupchat)
#             message.xhtml = xhtml if xhtml
#             write message
#           end
          
#           # <message to='room@service' type='groupchat'>
#           #   <subject>foo</subject>
#           # </message>    
#           def subject=(body)
#             message = Blather::Stanza::Message.new(@room, nil, :groupchat)
#             message.subject = body
#             write message
#           end
          
#           def leave
#             self.status = :unavailable
#           end
          
#           # <iq from='crone1@shakespeare.lit/desktop'
#           #     id='begone'
#           #     to='heath@chat.shakespeare.lit'
#           #     type='set'>
#           #   <query xmlns='http://jabber.org/protocol/muc#owner'>
#           #     <destroy jid='darkcave@chat.shakespeare.lit'>
#           #       <reason>Macbeth doth come.</reason>
#           #     </destroy>
#           #   </query>
#           # </iq>
#           def destroy(reason = nil)
#             destroy = ::Blather::MUC::Owner::Destroy.new(@room)
            
#             destroy.reason = reason
#             write destroy
#           end
          
#           def get_configuration(&block)
#             get_configure = ::Blather::MUC::Owner::Configure.new(:get, @room)
#             write_with_handler(get_configure) do |stana|
#               yield stana
#             end
#           end
#           alias_method :configuration, :get_configuration
          
#           def set_configuration(values, &block)
#             set_configure = ::Blather::MUC::Owner::Configure.new(:set, @room)
#             set_configure.data = values
#             write_with_handler(set_configure, &block)
#           end
#           alias_method :configuration=, :set_configuration
          
#           #  <iq type='set' id='purple52b37aa2' to='test3@conference.macbook.local'>
#           #   <query xmlns='http://jabber.org/protocol/muc#owner'>
#           #   <x xmlns='jabber:x:data' type='submit'/></query>
#           # </iq>
#           def set_default_configuration(&block)
#             set_configuration(:default) do
#               yield if block_given?
#             end
#           end
#           alias_method :unlock, :set_default_configuration
          
#           # <iq from='crone1@shakespeare.lit/desktop'
#           #     id='member3'
#           #     to='darkcave@chat.shakespeare.lit'
#           #     type='get'>
#           #   <query xmlns='http://jabber.org/protocol/muc#admin'>
#           #     <item affiliation='member'/>
#           #   </query>
#           # </iq>
#           # 
#           # <iq from='darkcave@chat.shakespeare.lit'
#           #     id='member3'
#           #     to='crone1@shakespeare.lit/desktop'
#           #     type='result'>
#           #   <query xmlns='http://jabber.org/protocol/muc#admin'>
#           #     <item affiliation='member'
#           #           jid='hag66@shakespeare.lit'
#           #           nick='thirdwitch'
#           #           role='participant'/>
#           #   </query>
#           # </iq>
#           def members(&block)
#             members = ::Blather::MUC::Admin::Members.new(@room)
            
#             write_with_handler(members, &block)
#           end
          
#           def write(stanza)
#             @client.write(stanza)
#           end
          
#           def write_with_handler(stanza, &block)
#             @client.write_with_handler(stanza, &block)
#           end
#         end # end Class Blather::DSL::MultiUserChat
#     end # end Module Blather::DSL
#     # ### Support for MUC Presense

#     module MUC
#         #
#         class Join < ::Blather::XMPPNode
#           register :x, "http://jabber.org/protocol/muc"
          
#           def self.new(password = nil)
#             join = super :x
#             join.password = password
#             join
#           end
          
#           def password=(password)
#             return if password.blank?
#             create_password.content = password
#           end
          
#           protected
#             def create_password
#                 unless create_password = find_first('ns:password', :ns => self.class.registered_ns)
#                     self << (create_password = XMPPNode.new('password', self.document))
#                 end
#               create_password
#             end
#         end #Join
#         #  <x xmlns='http://jabber.org/protocol/muc#user'>
#         #    <invite to='jid'>
#         #      <reason>comment</reason>
#         #    </invite>
#         #  </x>
#         class Invite < ::Blather::Stanza
#             register :muc_invite, :x, "http://jabber.org/protocol/muc#user"
            
#             def self.import(node)
#                 self.new(node.element_name).inherit(node)
#             end
            
#             def inherit(node)
#                 create_invite.remove
#                 self.from = node[:from]
#                 invite = node.find_first('ns:x/ns:invite', :ns => self.class.registered_ns)
#                 self << invite
#                 self
#             end
            
#             def self.new(jid = nil, reason = nil, password = nil)
#                 invite = super :x
#                 invite.invite_to = jid
#                 invite.reason    = reason
#                 invite.password  = password
#                 invite
#             end
            
#             def invite_to=(jid)
#                 create_invite[:to] = JID.new(jid)
#             end
            
#             def invite_to
#                 ::Blather::JID.new(create_invite[:to])
#             end
            
#             def invite_from
#             create_invite[:from]
#             end
            
#             def reason=(reason)
#                 return if reason.blank?
#                 create_reason.content = reason
#             end
            
#             def reason
#                 create_reason.content
#             end
            
#             def password=(password)
#                 return if password.blank?
#                 create_password.content = password
#             end
            
#             def password
#                 create_password.content
#             end
            
#             protected
#             def create_password
#                 unless create_password = find_first('ns:password', :ns => self.class.registered_ns)
#                 self << (create_password = XMPPNode.new('password', self.document))
#                 end
#                 create_password
#             end
            
#             def create_invite
#                 unless create_invite = find_first('ns:invite', :ns => self.class.registered_ns)
#                 self << (create_invite = XMPPNode.new('invite', self.document))
#                 end
#                 create_invite
#             end
        
#             def create_reason
#                 unless create_reason = create_invite.find_first('ns:reason', :ns => self.class.registered_ns)
#                 self.create_invite << (create_reason = XMPPNode.new('reason', self.document))
#                 end
#                 create_reason
#             end
            
#             def create_password
#                 unless create_password = find_first('ns:password', :ns => self.class.registered_ns)
#                 self << (create_password = XMPPNode.new('password', self.document))
#                 end
#                 create_password
#             end
#         end #Invite
#         class Owner < Blather::Stanza::Iq::Query
#           register :owner, :owner, 'http://jabber.org/protocol/muc#owner'
      
#           def self.new(type = nil, to = nil)
#             node           = super(type)
#             node.to        = to
#             node
#           end
          
#           class Configure < Owner
#             DATA_NAMESPACE = 'jabber:x:data'
            
#             def data=(data = :default)
#               create_data[:type] = 'submit'
#               unless data.blank? || data == :default
#                 raise "Invalid data format" unless data.is_a?(Hash)
#                 data.each {|key, value|
#                   create_field = XMPPNode.new('field', self.document)
#                   create_field[:var] = key
                  
#                   create_field_value = XMPPNode.new('value', self.document)
#                   if [TrueClass, FalseClass].include?(value.class)
#                     value = value ? 1 : 0
#                   end
#                   create_field_value.content = value.to_s
                  
#                   create_field << create_field_value
#                   create_data  << create_field
#                 }      
#               end
#             end
            
#             def data
#               items = create_data.find('//ns:field', :ns => self.class.registered_ns)
#               items.inject({}) do |hash, item|
#                 key       = item[:var]
#                 value     = item.find_first('ns:value', :ns => self.class.registered_ns)
#                 value     = value.content
#                 hash[key] = value
#                 hash
#               end
#             end
      
#             protected    
#               def create_data
#                 unless create_data = query.find_first('ns:x', :ns => DATA_NAMESPACE)
#                   query << (create_data = XMPPNode.new('x', self.document))
#                   create_data.namespace = DATA_NAMESPACE
#                 end
#                 create_data
#               end
#           end
          
#           # <iq from='crone1@shakespeare.lit/desktop'
#           #     id='begone'
#           #     to='heath@chat.shakespeare.lit'
#           #     type='set'>
#           #   <query xmlns='http://jabber.org/protocol/muc#owner'>
#           #     <destroy jid='darkcave@chat.shakespeare.lit'>
#           #       <reason>Macbeth doth come.</reason>
#           #     </destroy>
#           #   </query>
#           # </iq>
#           class Destroy < Owner
            
#             def self.new(*args)
#               query = super(:set, *args)
#               query.create_destroy
#               query
#             end
            
#             def reason=(reason)
#               return if reason.blank?
#               create_reason.content = reason
#             end
      
#             def create_reason # @private
#               unless create_reason = create_destroy.find_first('ns:reason', :ns => self.class.registered_ns)
#                 create_destroy << (create_reason = XMPPNode.new('reason', self.document))
#               end
#               create_reason
#             end
          
#             def create_destroy # @private
#               unless create_destroy = query.find_first('ns:destroy', :ns => self.class.registered_ns)
#                 query << (create_destroy = XMPPNode.new('destroy', self.document))
#               end
#               create_destroy
#             end
#           end
          
#         end
#         class Admin < Blather::Stanza::Iq::Query
#           register :admin, :admin, 'http://jabber.org/protocol/muc#admin'
      
#           def self.new(type = nil, to = nil)
#             node           = super(type)
#             node.to        = to
#             node
#           end
          
#           # <iq from='crone1@shakespeare.lit/desktop'
#           #     id='member3'
#           #     to='darkcave@chat.shakespeare.lit'
#           #     type='get'>
#           #   <query xmlns='http://jabber.org/protocol/muc#admin'>
#           #     <item affiliation='member'/>
#           #   </query>
#           # </iq>
#           class Members < Admin
#             def self.new(*args)
#               query = super(:get, *args)
#               query.create_item
#               query
#             end
            
#             def create_item # @private
#               unless create_item = query.find_first('ns:item', :ns => self.class.registered_ns)
#                 query << (create_item = XMPPNode.new('item', self.document))
#                 create_item[:affiliation] = 'member'
#               end
#               create_item
#             end
#           end
          
#         end # Admin
#     end # end module MUC
#     #
#     class Stanza
#         class Presence
#             class MUCJoin < ::Blather::Stanza::Presence
#               MUC_NS = "http://jabber.org/protocol/muc"
              
#               register :muc_join, :muc_join
              
#               def password
#                 create_muc.content_from :password
#                 create_password.content
#               end
              
#               def password=(value)
#                 create_muc.set_content_for :password
#               end
              
#               private
#                 def create_muc
#                     unless create_muc = find_first('ns:x', :ns => MUC_NS)
#                         self << (create_muc = ::Blather::XMPPNode.new('x', self.document))
#                         create_muc.namespace = MUC_NS
#                     end
#                    create_muc
#                 end
#             end #
#             #
#             class MUCUser < Presence
#                 class Status < ::Blather::XMPPNode
#                     def self.new(code)
#                       new_node = super :status
#                       new_node.code = code
#                       new_node
#                     end
              
#                     def code
#                       read_attr :code
#                     end
              
#                     def code=(var)
#                       write_attr :code, var
#                     end
#                 end
    
#                 MUC_NS = "http://jabber.org/protocol/muc#user"
                
#                 register :muc_user, :muc_user
                
#                 def affiliation
#                   create_ia[:affiliation]
#                 end
                
#                 def affiliation=(val)
#                   create_ia[:affiliation] = val
#                 end
                
#                 def role
#                   create_ia[:role]
#                 end
                
#                 def role=(val)
#                   create_ia[:role] = val
#                 end
                
#                 def jid
#                   create_ia[:jid]
#                 end
                
#                 def jid=(val)
#                   create_ia[:jid] = val
#                 end
                
#                 private
#                 def create_muc
#                     unless create_muc = find_first('ns:x', :ns => MUC_NS)
#                        self << (create_muc = ::Blather::XMPPNode.new('x', self.document))
#                        create_muc.namespace = MUC_NS
#                     end
#                      create_muc
#                 end
                  
#                 def create_ia
#                     unless create_ia = create_muc.find_first('ns:item', :ns => self.class.registered_ns)
#                       create_muc << (create_ia = XMPPNode.new('item', self.document))
#                     end
#                     create_ia
#                 end
#             end
#         end
#     end
#     #
# end # end Module Blather

    # XMPP Classes:
    # Review : Blather switchover:
    # require ::File.expand_path("./xmpp_client.rb",::File.dirname(__FILE__))
    # # ### Invitations
    # class XmppAgentInvitation
    #   def initialize(parent=nil, invitation=nil)
    #     @uuid = ::GxG::uuid_generate.to_sym
    #     @pending = true
    #     @parent = parent
    #     @invitation = invitation
    #     #
    #     if @invitation.is_a?(::Blather::Stanza::Presence)
    #         @details = {:sender => @invitation.from.to_s, :type => :association}
    #     else
    #         @details = {:sender => @invitation.from.to_s, :type => :unkown}
    #     end
    #     #
    #     self
    #   end
    #   # Review : debug only
    #   def invitation()
    #     @invitation
    #   end
    #   #
    #   def uuid()
    #     @uuid
    #   end
    #   #
    #   def inspect()
    #     @details.inspect
    #   end
    #   #
    #   def pending?()
    #     @pending
    #   end
    #   #
    #   def keys()
    #     @details.keys()
    #   end
    #   #
    #   def [](the_key)
    #     @details[(the_key)]
    #   end
    #   #
    #   def accept()
    #     if @invitation
    #         @parent.write(@invitation.approve!)
    #         @pending = false
    #         @parent.refresh_invitations()
    #         true
    #     else
    #         false
    #     end
    #   end
    #   #
    #   def decline()
    #     if @invitation
    #         @parent.write(@invitation.cancel!)
    #         @pending = false
    #         @parent.refresh_invitations()
    #         true
    #     else
    #         false
    #     end
    #   end
    # end
    # # ### File Transfer
    # class XmppAgentFileTransfer
    #     # Review : totally rewrite this
    #   def initialize(manager, direction, details, parent)
    #     @reference = ::GxG::uuid_generate.to_sym
    #     @session_id = nil
    #     @pending = true
    #     @inprogress = false
    #     @percent_completed = 0
    #     @status_thread_safety = ::Mutex.new
    #     @manager = manager
    #     @direction = direction
    #     @info = {:reference => @reference}
    #     @bytestream = nil
    #     @file_details = nil
    #     @cancel = false
    #     the_value = ::GxG::SYSTEM.maximum_buffer_size.get_at_path("/:ipv4/:tcp/:write/:valid")
    #     if the_value.is_a?(::Range)
    #       @valid_write_buffer_sizes = the_value
    #     else
    #       @valid_write_buffer_sizes = (4096..65536)
    #     end
    #     @buffer_size = 4096
    #     @client = parent
    #     if @direction == :download
    #       @invitation = details[:iq]
    #       @sender = details[:iq].from
    #       @info[:sender] = @sender.to_s
    #       @info[:recipient] = @client.jid.to_s
    #       @file_details = {:filename => details[:file_info].fname, :path => (details[:download_directory] + "/" + details[:file_info].fname), :size => details[:file_info].size, :md5 => details[:file_info].hash, :description => details[:file_info].description}
    #       @download_directory = details[:download_directory]
    #       @info[:details] = @file_details
    #       @recipient = nil
    #       #
    #       #
    #     end
    #     if @direction == :upload
    #       @info[:sender] = @client.jid.to_s
    #       @info[:recipient] = details[:jid].to_s
    #       @recipient = ::Jabber::JID.new(details[:jid])
    #       @file_details = {:filename => ::File.basename(details[:path]), :path => details[:path], :size => ::File.size(details[:path]), :md5 => ::Digest::MD5.file(details[:path]), :description => details[:description]}
    #       @info[:details] = @file_details
    #       @invitation = nil
    #       @download_directory = nil
    #     end
    #     self
    #   end
    #   #
    #   def inspect()
    #     "<Transfer: #{@direction.inspect} - #{@reference}, with Session ID: #{@session_id} for File #{@file_details[:filename]}>"
    #   end
    #   # 
    #   def info()
    #     @info.clone
    #   end
    #   #
    #   def reference()
    #     @reference.clone
    #   end
    #   #
    #   def session_id()
    #     @session_id.clone
    #   end
    #   #
    #   def pending?()
    #     @status_thread_safety.synchronize { @pending }
    #   end
    #   #
    #   def buffer_size()
    #     @status_thread_safety.synchronize { @buffer_size }
    #   end
    #   #
    #   def buffer_size=(the_size=4096)
    #     begin
    #       unless the_size.is_a?(::Integer)
    #         raise ArgumentError, "You MUST provide an Integer to set buffer size."
    #       end
    #       if @status_thread_safety.synchronize { @direction == :upload }
    #         unless @valid_write_buffer_sizes.include?(the_size)
    #           raise ArgumentError, "You MUST provide an Integer between #{@valid_read_buffer_sizes.first} and #{@valid_read_buffer_sizes.last}."
    #           @status_thread_safety.synchronize { @buffer_size = the_size }
    #         end
    #       else
    #         log_warn("Buffer size is only set on upload file transfers.")
    #       end
    #       the_size
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {}})
    #       nil
    #     end
    #   end
    #   #
    #   def cancelled?()
    #     @status_thread_safety.synchronize { @cancel }
    #   end
    #   #
    #   def cancel()
    #     if @client
    #       begin
    #         if @status_thread_safety.synchronize { @pending == true }
    #           @status_thread_safety.synchronize { @pending = false }
    #         end
    #         if @status_thread_safety.synchronize { @inprogress == true }
    #           @status_thread_safety.synchronize { @inprogress = false }
    #         end
    #         @status_thread_safety.synchronize { @cancel = true }
    #         @client.refresh_file_transfers
    #         true
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #     else
    #       false
    #     end
    #   end
    #   #
    #   def accept()
    #     if @client
    #       if @status_thread_safety.synchronize { @pending == true && @direction == :download }
    #         Thread.new {
    #           begin
    #             bytes_received = 0
    #             total_size = @file_details[:size]
    #             @bytestream = @manager.accept(@invitation)
    #             if @bytestream
    #               @bytestream.accept()
    #               @status_thread_safety.synchronize {
    #                 @pending = false
    #                 @inprogress = true
    #                 @session_id = @bytestream.session_id.to_s
    #               }
    #               #
    #               cancel_callback = Proc.new do |the_iq|
    #                 if the_iq.type == :error
    #                   the_error = ::Jabber::ServerError.new(the_iq.error)
    #                   if @invitation.id.to_s == the_iq.id.to_s
    #                     the_transfer = @client.find_file_transfer(@reference)
    #                     if the_transfer
    #                       the_transfer.cancel
    #                     end
    #                   end
    #                   log_error({:error => the_error, :parameters => {:iq => the_iq}})
    #                 end
    #               end
    #               @client.set_xfr_callback(@session_id,&cancel_callback)
    #               #
    #               the_file = ::File.open(@file_details[:path], "w+b",0664)
    #               the_file.pos = 0
    #               buffer = @bytestream.read()
    #               while buffer && @status_thread_safety.synchronize { @cancel == false } do
    #                 the_file.write(buffer.to_s)
    #                 bytes_received += buffer.to_s.size
    #                 @status_thread_safety.synchronize { @percent_completed = ((bytes_received.to_f / total_size.to_f) * 100.0).to_i }
    #                 @client.notify({:event => :file_transfer_progress, :transfer => @reference, :progress => @status_thread_safety.synchronize { @percent_completed }})
    #                 buffer = @bytestream.read()
    #               end
    #               the_file.close
    #               @bytestream.close
    #               @status_thread_safety.synchronize {
    #                 @inprogress = false
    #                 @pending = false
    #               }
    #               the_path = @file_details[:path]
    #               if @status_thread_safety.synchronize { @cancel == true }
    #                 ::File.delete(the_path)
    #                 @client.notify({:event => :file_transfer_cancelled, :transfer => @reference})
    #               else
    #                 if @file_details[:md5]
    #                   unless @file_details[:md5] == ::Digest::MD5.file(the_path)
    #                     raise Exception, "MD5 Checksum Failure - file corruption on file: #{the_path}"
    #                   end
    #                   @client.notify({:event => :file_transfer_complete, :transfer => @reference})
    #                 end
    #               end
    #             else
    #               @status_thread_safety.synchronize {
    #                 @inprogress = false
    #                 @pending = false
    #               }
    #               the_file = nil
    #               raise Exception, "Failed to negotiate a transfer method."
    #             end
    #           rescue Exception => the_error
    #             @status_thread_safety.synchronize {
    #               @inprogress = false
    #               @pending = false
    #             }
    #             if the_file
    #               the_file.close
    #             end
    #             if @bytestream
    #               @bytestream.close
    #             end
    #             log_error({:error => the_error, :parameters => {}})
    #             @client.notify({:event => :file_transfer_error, :transfer => @reference})
    #           end
    #           if @session_id
    #             @client.clear_xfr_callback(@session_id)
    #           end
    #           @client.refresh_file_transfers
    #         }
    #       end
    #       true
    #     else
    #       false
    #     end
    #   end
    #   #
    #   def decline()
    #     if @client
    #       if @status_thread_safety.synchronize { @pending == true && @direction == :download }
    #         begin
    #           @manager.decline(@invitation)
    #           @status_thread_safety.synchronize { @pending = false }
    #         rescue Exception => the_error
    #           log_error({:error => the_error, :parameters => {}})
    #         end
    #       end
    #       true
    #     else
    #       false
    #     end
    #   end
    #   #
    #   def in_progress?()
    #     @status_thread_safety.synchronize { @inprogress }
    #   end
    #   #
    #   def percent_completed()
    #     @status_thread_safety.synchronize { @percent_completed.clone }
    #   end
    #   #
    #   def file_details()
    #     @status_thread_safety.synchronize { @file_details.clone }
    #   end
    #   #
    #   def download_directory()
    #     @status_thread_safety.synchronize { @download_directory.clone }
    #   end
    #   #
    #   def download_directory=(the_path=nil)
    #     begin
    #       unless the_path.is_a?(::String)
    #         raise ArgumentError, "You MUST supply a String as valid directory path."
    #       end
    #       the_path = ::File.expand_path(the_path)
    #       unless the_path.valid_path?()
    #         raise ArgumentError, "You MUST supply a valid directory path."
    #       end
    #       unless ::File.exist?(the_path)
    #         raise ArgumentError, "You MUST supply a valid directory path - Directory does not exist."
    #       end
    #       @status_thread_safety.synchronize {
    #         unless @inprogress == true
    #           if @direction == :download
    #             @download_directory = ::File.expand_path(the_path)
    #             @file_details[:path] = (@download_directory + "/" + @file_details[:filename])
    #           end
    #         end
    #         }
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #   end
    #   #
    #   def upload_file(proxy=nil)
    #     if @client
    #       if @direction == :upload
    #         unless @status_thread_safety.synchronize { @inprogress == true }
    #           Thread.new {
    #             begin
    #               bytes_sent = 0
    #               buffer_size = @status_thread_safety.synchronize { @buffer_size }
    #               the_file_source = ::Jabber::FileTransfer::FileSource.new(@file_details[:path])
    #               the_file_source.length = buffer_size
    #               total_size = the_file_source.size
    #               @bytestream = nil
    #               response = @manager.offer(@recipient,the_file_source,@file_details[:description],nil,@reference.to_s)
    #               if response.is_a?(::Hash)
    #                 @bytestream = response[:bytestream]
    #                 the_iq_id = response[:iq_id]
    #                 if @bytestream
    #                   if @bytestream.is_a?(::Jabber::Bytestreams::SOCKS5BytestreamsInitiator)
    #                     if proxy.is_any?(::String, ::Jabber::JID)
    #                       @bytestream.add_streamhost(proxy)
    #                     end
    #                   end
    #                   if @bytestream.is_a?(::Jabber::Bytestreams::IBBInitiator)
    #                     @bytestream.block_size = buffer_size
    #                   end
    #                   #
    #                   @status_thread_safety.synchronize {
    #                     @pending = false
    #                     @inprogress = true
    #                   }
    #                   open_response = @bytestream.open()
    #                   if open_response
    #                     puts "Got: (open_response) - #{open_response.inspect}"
    #                     if open_response.type == :result
    #                       #
    #                       @session_id = @bytestream.session_id.to_s
    #                       #
    #                       cancel_callback = Proc.new do |the_iq|
    #                         if the_iq.type == :error
    #                           the_error = ::Jabber::ServerError.new(the_iq.error)
    #                           if the_iq_id.to_s == the_iq.id.to_s
    #                             the_transfer = @client.find_file_transfer(@reference)
    #                             if the_transfer
    #                               the_transfer.cancel
    #                             end
    #                           end
    #                           log_error({:error => the_error, :parameters => {:iq => the_iq}})
    #                         end
    #                       end
    #                       @client.set_xfr_callback(@session_id,&cancel_callback)
    #                       #
    #                       ::GxG.apportioned_ranges(total_size,buffer_size).each do |the_range|
    #                         if @status_thread_safety.synchronize { @cancel == true }
    #                           the_file_source.close
    #                           break
    #                         end
    #                         the_file_source.seek(the_range.first)
    #                         bytes_sent += @bytestream.write(the_file_source.read(the_range.size)).to_i
    #                         @status_thread_safety.synchronize { @percent_completed = ((bytes_sent.to_f / total_size.to_f) * 100.0).to_i }
    #                         #
    #                       end
    #                       @bytestream.flush
    #                       @bytestream.close
    #                       @status_thread_safety.synchronize { @inprogress = false }
    #                     else
    #                       # Error?
    #                       @status_thread_safety.synchronize {
    #                         @pending = false
    #                         @inprogress = false
    #                       }
    #                     end
    #                   else
    #                     raise Exception, "Failed to open the stream."
    #                   end
    #                 end
    #               else
    #                 @status_thread_safety.synchronize {
    #                   @pending = false
    #                   @inprogress = false
    #                 }
    #               end
    #             rescue Exception => the_error
    #               the_file_source.close
    #               @bytestream.close
    #               @status_thread_safety.synchronize { @inprogress = false }
    #               log_error({:error => the_error, :parameters => {:proxy => proxy}})
    #             end
    #             @client.clear_xfr_callback(@reference.to_s)
    #             if @session_id
    #               @client.clear_xfr_callback(@session_id)
    #             end
    #             @client.refresh_file_transfers
    #           }
    #         end
    #       end
    #     end
    #   end
    #   #
    # end
    # #
    # # ### Conversation Channel
    # class XmppAgentConversation
    #   #
    #   def default_room_configuration(options={})
    #     unless options.is_a?(::Hash)
    #       options = {}
    #     end
    #     default_config = {
    #       'FORM_TYPE' => 'http://jabber.org/protocol/muc#roomconfig',
    #       'form' => 'config',
    #       'muc#roomconfig_roomname' => nil,
    #       'muc#roomconfig_roomdesc' => nil,
    #       'leave' => 'has left',
    #       'join' => 'has become available',
    #       'rename' => 'is now known as',
    #       'muc#roomconfig_changesubject' => 0,
    #       'muc#roomconfig_maxusers' => 0,
    #       'privacy' => 0,
    #       'muc#roomconfig_publicroom' => 1,
    #       'muc#roomconfig_persistentroom' => 1,
    #       'legacy' => 0,
    #       'muc#roomconfig_moderatedroom' => 0,
    #       'defaulttype' => 0,
    #       'privmsg' => 0,
    #       'muc#roomconfig_membersonly' => 0,
    #       'muc#roomconfig_allowinvites' => 1,
    #       'muc#roomconfig_passwordprotectedroom' => 0,
    #       'muc#roomconfig_roomsecret' => nil,
    #       'muc#roomconfig_whois' => 'moderators',
    #       'muc#roomconfig_enablelogging' => 0,
    #       'logformat' => 'xml'
    #     }
    #     default_config.merge(options)
    #   end
    #   #
    #   def initialize(parent=nil, details={})
    #     if ::GxG::valid_uuid?(details[:context])
    #         @uuid = details[:context].to_s.to_sym
    #     else
    #         @uuid = ::GxG::uuid_generate.to_sym
    #     end
    #     @parent = parent
    #     # @details should have a JID for the sender-jid/room-jid
    #     # @details should indicate whether a private direct message or MUC ROOM message (:chat? or :groupchat?)
    #     @details = details
    #     #
    #     @received = []
    #     @received_thread_safety = ::Mutex.new
    #     # Add call backs
    #     # @parent.notify({:event => :new_message, :conversation => @uuid, :message => message.id})
    #     # @parent.notify({:event => :new_private_message, :conversation => @uuid, :message => message.id})
    #     self
    #   end
    #   #
    #   def uuid()
    #     @uuid
    #   end
    #   #
    #   def jid()
    #     @details[:sender].to_s
    #   end
    #   #
    #   def my_jid()
    #     result = nil
    #     if @parent
    #       result = @parent.jid().to_s
    #     end
    #     result
    #   end
    #   #
    #   def [](the_key=nil)
    #     result = nil
    #     if the_key.is_a?(::Symbol)
    #         result = @details[(the_key)]
    #     end
    #     result
    #   end
    #   #
    #   def title()
    #     result = nil
    #     # Review : TODO - return ROOM title
    #     result
    #   end
    #   #
    #   def inspect()
    #     {:jid => this().jid, :title => this().title}.inspect
    #   end
    #   #
    #   def closed?()
    #     # Review : integrate with new system
    #     false
    #   end
    #   #
    #   def process_received(&block)
    #     begin
    #         if block.respond_to?(:call)
    #             count = 0
    #             @received_thread_safety.synchronize {
    #                 count = @received.size
    #             }
    #             record = nil
    #             count.times do
    #                 @received_thread_safety.synchronize {
    #                     record = @received.shift
    #                 }
    #                 if record
    #                     block.call(record)
    #                 end
    #             end
    #             true
    #         else
    #             false
    #         end
    #     rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #         false
    #     end
    #   end
    #   #
    #   def add_message(the_message=nil)
    #     if the_message
    #         @received_thread_safety.synchronize { @received << the_message }
    #         true
    #     else
    #         false
    #     end
    #   end
    #   #
    #   def join(the_jid=nil, password=nil, options={})
    #     result = false
    #     begin
    #         # Review : TODO - MUC join
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {:the_jid => the_jid, :options => options}})
    #     end
    #     result
    #   end
    #   #
    #   def leave(exit_string=nil)
    #     result = false
    #     begin
    #         # Review : TODO - MUC leave
    #         # @parent.refresh_conversations
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {:exit_string => exit_string}})
    #     end
    #     result
    #   end
    #   #
    #   def chat_buddies()
    #     result = []
    #     begin
    #         # Review : TODO - like XmppAgent.buddies but for this ROOM only.
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {}})
    #     end
    #     result
    #   end
    #   #
    #   def say_something(the_message=nil, to_jid=nil)
    #     result = false
    #     begin
    #         if @details[:type] == :chat
    #             recipient = (to_jid || the_message[:to]).to_s
    #             @parent.say(::Blather::JID.new(recipient), @parent.gxg_message_to_xmpp(the_message))
    #         else
    #             # Review : TODO - send chat message to ROOM
    #         end
    #         result = true
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {:message => the_message, :to => to_jid}})
    #     end
    #     result
    #   end
    #   #
    #   def send_invitations(the_recipients=nil, reason=nil)
    #     result = false
    #     begin
    #         # Review : TODO - ROOM invitation list processing list.each { |i| send i }
    #         # "You MUST provide an Array of JID Strings."
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {:recipients => the_recipients, :message => reason}})
    #     end
    #     result
    #   end
    #   #
    #   def configuration()
    #     result = nil
    #     begin
    #         # Review : TODO - get ROOM configuration
    #         #   if @handler
    #         #     if @handler.owner?
    #         #       current_configuration = {}
    #         #       iq = ::Jabber::Iq.new(:get, @handler.jid.to_s)
    #         #       iq.to = @handler.jid.to_s
    #         #       iq.from = @handler.my_jid.to_s
    #         #       iq.add(::Jabber::MUC::IqQueryMUCOwner.new)
    #         #       field_keys = this().default_room_configuration.keys
    #         #       response = @stream.send_with_id(iq)
    #         #       if response
    #         #         if (response.query && response.query.x(::Jabber::Dataforms::XData))
    #         #           field_keys.each do |the_key|
    #         #             field = response.query.x(::Jabber::Dataforms::XData).field(the_key.to_s)
    #         #             if field.is_a?(::Jabber::Dataforms::XDataField)
    #         #               current_configuration[(the_key.to_s)] = field.value
    #         #             end
    #         #           end
    #         #         end
    #         #       end
    #         #       result = current_configuration
    #         # else
    #         #   raise Exception, "You are not the owner of this conversation room."
    #         # end
    #         #   end
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {}})
    #     end
    #     result
    #   end
    #   #
    #   def change_configuration(the_configuration=nil)
    #     result = false
    #     begin
    #         # Review : TODO - alter ROOM configuration if admin/owner
    #         #   if @handler
    #         #     if @handler.owner?
    #         #       unless the_configuration.is_a?(::Hash)
    #         #         raise ArgumentError, "You MUST provide a configuration Hash."
    #         #       end
    #         #       the_configuration = this().default_room_configuration(the_configuration)
    #         #       @handler.submit_room_configuration(the_configuration)
    #         #       result = true
    #         #     else
    #         #       raise Exception, "You are not the owner of this conversation room."
    #         #     end
    #         #   end
    #     rescue Exception => the_error
    #       log_error({:error => the_error, :parameters => {:configuration => the_configuration}})
    #     end
    #     result
    #   end
    #   #
    # end
    # # ### XMPP Client
    # class XmppAgent
    #     # ### 
    #     def self.online_availability_values()
    #       {:online => :chat, :busy => :dnd, :away => :away, :extended_away => :xa, :offline => :unavailable, :error => :error}
    #     end
    #     #
    #     def self.registration_fields()
    #       # XEP-0077 Support
    #       {:username => 'Account name associated with the user', :nick => 'Familiar name of the user', :password => 'Password or secret for the user', :name => 'Full name of the user', :first => 'First name or given name of the user', :last => 'Last name, surname, or family name of the user', :email => 'Email address of the user', :address => 'Street portion of a physical or mailing address', :city => 'Locality portion of a physical or mailing address', :state => 'Region portion of a physical or mailing address', :zip => 'Postal code portion of a physical or mailing address', :phone => 'Telephone number of the user', :url => 'URL to web page describing the user', :date => 'Some date (e.g., birth date, hire date, sign-up date)'}.clone
    #     end
    #     #
    #     def self.registration_info(the_url=nil)
    #       result = nil
    #       begin
    #         if the_url.is_a?(::URI::Generic)
    #             the_jid = "anonymous"
    #             if the_url.hostname()
    #                 the_jid << ("@" + the_url.hostname.to_s)
    #             else
    #                 raise ArgumentError, "You MUST provide a vailid host or IP Address in a valid URI."
    #             end
    #             # Review : convert this code to Blather compatible
    #             # Note : see https://www.rubydoc.info/gems/blather/Blather/Stanza/Iq for researching ideas.
    #             # Note : see https://www.rubydoc.info/gems/xmpp4r/Jabber/Client#register-instance_method for researching ideas.
    #             result = []
    #             #   client = ::Jabber::Client.new(the_jid)
    #             #   client.connect(the_url.hostname.to_s, (the_url.port || 5222))
    #             #   info = client.register_info()
    #             #   if client.status == 2
    #             #     client.close
    #             #   end
    #             #   if info.is_a?(::Array)
    #             #     fields = ::GxG::Networking::XmppClient::registration_fields()
    #             #     result = {:instructions => info[0], :registration_fields => {}}
    #             #     info[1].each do |the_raw_key|
    #             #       result[:registration_fields][(the_raw_key.to_sym)] = fields[(the_raw_key.to_sym)]
    #             #     end
    #             #   end
    #         else
    #           raise ArgumentError, "You MUST provide a vailid URL."
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {:url => the_url}})
    #       end
    #       result
    #     end
    #     #
    #     def self.remove_registration(the_url=nil)
    #         # Review : convert this code to Blather compatible
    #         # Note : see https://www.rubydoc.info/gems/blather/Blather/Stanza/Iq for researching ideas.
    #         # Note : see https://www.rubydoc.info/gems/xmpp4r/Jabber/Client#register-instance_method for researching ideas.
    #         result = false
    #         begin
    #             if the_url.is_a?(::URI::Generic)
    #             if the_url.password() == nil
    #                 raise ArgumentError, "You MUST provide a vailid password."
    #             end
    #             the_jid = ""
    #             if the_url.user()
    #                 the_jid << the_url.user.to_s
    #             else
    #                 raise ArgumentError, "You MUST provide a vailid user name."
    #             end
    #             if the_url.hostname()
    #                 the_jid << ("@" + the_url.hostname.to_s)
    #             else
    #                 raise ArgumentError, "You MUST provide a vailid host or IP Address."
    #             end
    #             if the_url.path()
    #                 the_jid << ("/" + File.basename(the_url.path.to_s))
    #             end
    #             # Here ???
    #             # Connect
    #             client = ::Blather::Client::setup(the_jid, the_url.password.to_s, the_url.hostname.to_s, (the_url.port || 5222))
    #             client.run
    #             # xxx
    #             # client.remove_registration
    #             # xxx
    #             client.close
    #             result = true
    #             else
    #             raise ArgumentError, "You MUST provide a vailid URL."
    #             end
    #         rescue Exception => the_error
    #             log_error({:error => the_error, :parameters => {:url => the_url, :fields => fields}})
    #         end
    #         result
    #     end
    #     #
    #     def self.register_with_server(the_url=nil, fields={})
    #         # Review : convert this code to Blather compatible
    #         # Note : see https://www.rubydoc.info/gems/blather/Blather/Stanza/Iq for researching ideas.
    #         # Note : see https://www.rubydoc.info/gems/xmpp4r/Jabber/Client#register-instance_method for researching ideas.
    #         result = false
    #         begin
    #             if the_url.is_a?(::URI::Generic)
    #             if the_url.password() == nil
    #                 raise ArgumentError, "You MUST provide a vailid password."
    #             else
    #                 fields['password'] = the_url.password.to_s
    #             end
    #             the_jid = ""
    #             if the_url.user()
    #                 the_jid << the_url.user.to_s
    #                 fields['username'] = the_url.user.to_s
    #             else
    #                 raise ArgumentError, "You MUST provide a vailid user name."
    #             end
    #             if the_url.hostname()
    #                 the_jid << ("@" + the_url.hostname.to_s)
    #             else
    #                 raise ArgumentError, "You MUST provide a vailid host or IP Address."
    #             end
    #             if the_url.path()
    #                 the_jid << ("/" + File.basename(the_url.path.to_s))
    #             end
    #             # xxx
    #             # client = ::Jabber::Client.new(the_jid)
    #             # client.connect(the_url.hostname.to_s, (the_url.port || 5222))
    #             # valid_fields = ::GxG::Networking::XmppClient::registration_fields().keys
    #             # the_fields = {}
    #             # fields.each_pair do |key, entry|
    #             #     if valid_fields.include?(key.to_sym)
    #             #     the_fields[(key.to_s)] = entry
    #             #     end
    #             # end
    #             # if the_fields.keys.size > 0
    #             #     client.register(the_url.password.to_s, the_fields)
    #             # else
    #             #     client.register(the_url.password.to_s)
    #             # end
    #             # if client.status == 2
    #             #     client.close
    #             # end
    #             result = true
    #             else
    #             raise ArgumentError, "You MUST provide a vailid URL."
    #             end
    #         rescue Exception => the_error
    #             log_error({:error => the_error, :parameters => {:url => the_url, :fields => fields}})
    #         end
    #         result
    #     end
    #     #
    #     # ### Support Methods
    #     def write(stanza)
    #         if @client
    #             @client.write stanza
    #         end
    #         true
    #     end
    #     #
    #     def <<(stanza)
    #         if @client
    #             @client.write stanza
    #         end
    #         self
    #     end
    #     #
    #     def publish_and_subscribe
    #         @pubsub
    #     end
    #     # ### Setup a before filter
    #     #
    #     # @param [Symbol] handler (optional) the stanza handler the filter should
    #     # run before
    #     # @param [guards] guards (optional) a set of guards to check the stanza
    #     # against
    #     # @yield [Blather::Stanza] stanza
    #     def before(handler = nil, *guards, &block)
    #         if @client
    #             @client.register_filter :before, handler, *guards, &block
    #         end
    #     end
    #     # ### Setup an after filter
    #     #
    #     # @param [Symbol] handler (optional) the stanza handler the filter should
    #     # run after
    #     # @param [guards] guards (optional) a set of guards to check the stanza
    #     # against
    #     # @yield [Blather::Stanza] stanza
    #     def after(handler = nil, *guards, &block)
    #         if @client
    #             @client.register_filter :after, handler, *guards, &block
    #         end
    #     end
    #     # ### Set handler for a stanza type
    #     #
    #     # @param [Symbol] handler the stanza type it should handle
    #     # @param [guards] guards (optional) a set of guards to check the stanza
    #     # against
    #     # @yield [Blather::Stanza] stanza
    #     def handle(handler, *guards, &block)
    #         if @client
    #             @client.register_handler handler, *guards, &block
    #         end
    #     end
    #     # ### Wrapper for "handle :ready" (just a bit of syntactic sugar)
    #     #
    #     # This is run after the connection has been completely setup
    #     def when_ready(&block)
    #         self.handle :ready, &block
    #     end        
    #     # ### Wrapper for "handle :disconnected"
    #     #
    #     # This is run after the connection has been shut down.
    #     #
    #     # @example Reconnect after a disconnection
    #     #     disconnected { client.run }
    #     def disconnected(&block)
    #         self.handle :disconnected, &block
    #     end
    #     # ### Set current status
    #     #
    #     # @param [Blather::Stanza::Presence::State::VALID_STATES] state the current
    #     # state
    #     # @param [#to_s] msg the status message to use
    #     def set_status(state = nil, msg = nil)
    #         if @client
    #             @client.status = state, msg
    #         end
    #     end
    #     #
    #     def get_status()
    #         if @client
    #             @client.status
    #         else
    #             :unavailable
    #         end
    #     end
    #     # ### Direct access to the roster
    #     #
    #     # @return [Blather::Roster]
    #     def my_roster
    #         if @client
    #             @client.roster
    #         end
    #     end        
    #     # ### Write data to the stream
    #     #
    #     # @param [#to_xml, #to_s] stanza the data to send down the wire.
    #     def write_to_stream(stanza)
    #         self.write stanza
    #     end
    #     # ### Helper method to join a MUC room
    #     #
    #     # @overload join(room_jid, nickname)
    #     #   @param [Blather::JID, #to_s] room the JID of the room to join
    #     #   @param [#to_s] nickname the nickname to join the room as
    #     #  @overload join(room_jid, nickname)
    #     #   @param [#to_s] room the name of the room to join
    #     #   @param [Blather::JID, #to_s] service the service domain the room is hosted at
    #     #   @param [#to_s] nickname the nickname to join the room as
    #     def join(room, service, nickname = nil)
    #         join = Blather::Stanza::Presence::MUC.new
    #         if nickname
    #             join.to = "#{room}@#{service}/#{nickname}"
    #         else
    #             join.to = "#{room}/#{service}"
    #         end
    #         self.write join
    #     end
    #     # ### Helper method to make sending basic messages easier
    #     #
    #     # @param [Blather::JID, #to_s] to the JID of the message recipient
    #     # @param [#to_s] msg the message to send
    #     # @param [#to_sym] the stanza method to use
    #     def say(to, msg, using = :chat)
    #         self.write Blather::Stanza::Message.new(to, msg, using)
    #     end        
    #     # ### The JID according to the server
    #     #
    #     # @return [Blather::JID]
    #     def jid
    #         if @client
    #             @client.jid
    #         else
    #             nil
    #         end
    #     end
    #     # other supporting JID methods
    #     def jid_node()
    #         jid = self.jid
    #         if jid
    #             jid.node()
    #         else
    #             nil
    #         end
    #     end
    #     def jid_domain()
    #         jid = self.jid
    #         if jid
    #             jid.domain()
    #         else
    #             nil
    #         end
    #     end
    #     def jid_resource()
    #         jid = self.jid
    #         if jid
    #             jid.resource()
    #         else
    #             nil
    #         end
    #     end
    #     # ### Halt the handler chain
    #     #
    #     # Use this to stop the propogation of the stanza though the handler chain.
    #     #
    #     # @example Ignore all IQ stanzas
    #     #
    #     #     before(:iq) { halt }
    #     def halt
    #         # Review : how to actually use this? I see no way to call 'throw' yet. (research)
    #         # throw :halt
    #     end        
    #     # ### Pass responsibility to the next handler
    #     #
    #     # Use this to jump out of the current handler and let the next registered
    #     # handler take care of the stanza
    #     #
    #     # @example Pass a message to the next handler
    #     #
    #     # This is contrive and should be handled with guards, but pass a message
    #     # to the next handler based on the content
    #     #
    #     #     message { |s| puts "message caught" }
    #     #     message { |s| pass if s.body =~ /pass along/ }
    #     def pass
    #         # Review : how to actually use this? I see no way to call 'throw' yet. (research)
    #         # throw :pass
    #     end
    #     # ### Request items or info from an entity
    #     #     discover (items|info), [jid], [node] do |response|
    #     #     end
    #     def discover(what, who, where, &callback)
    #         if @client
    #             stanza = Blather::Stanza.class_from_registration(:query, "http://jabber.org/protocol/disco##{what}").new
    #             stanza.to = who
    #             stanza.node = where
          
    #             @client.register_tmp_handler stanza.id, &callback
    #             @client.write stanza
    #         end
    #     end
    #     # ### Set the capabilities of the client
    #     #
    #     # @param [String] node the URI
    #     # @param [Array<Hash>] identities an array of identities
    #     # @param [Array<Hash>] features an array of features
    #     def set_caps(node, identities, features)
    #         if @client
    #             @client.caps.node = node
    #             @client.caps.identities = identities
    #             @client.caps.features = features
    #         end
    #     end        
    #     # Send capabilities to the server
    #     def send_caps
    #         if @client
    #             @client.register_handler :disco_info, :type => :get, :node => @client.caps.node do |s|
    #               r = @client.caps.dup
    #               r.to = s.from
    #               r.id = s.id
    #               @client.write r
    #             end
    #             @client.write client.caps.c
    #         end
    #     end
    #     # ### Conversion Tools
    #     def xmpp_message_to_gxg(the_message=nil)
    #         # need: :to, :body, :state, :subject, :context, :type
    #         # ::Celluloid::UUID::random_generate().to_s
    #         unless the_message.is_a?(Blather::Stanza::Message)
    #           raise ArgumentError, "You MUST provide a valid message object: Blather::Stanza::Message."
    #         end
    #         gxg_message = ::GxG::Events::Message.new({:sender => :unknown})
    #         gxg_message[:id] = (the_message.id || ::GxG::uuid_generate.to_sym)
    #         gxg_message[:sender] = the_message.from.to_s
    #         gxg_message[:to] = the_message.to.to_s
    #         gxg_message[:type] = the_message.type
    #         if the_message.thread.is_a?(::Hash)
    #             gxg_message[:context] = the_message.thread.values[0]
    #         else
    #             gxg_message[:context] = the_message.thread
    #         end
    #         gxg_message[:subject] = the_message.subject
    #         gxg_message[:body] = the_message.body
    #         gxg_message
    #     end
    #     #
    #     def gxg_message_to_xmpp(the_message=nil)
    #       # need: :to, :body, :state, :subject, :context, :type
    #       # ::Celluloid::UUID::random_generate().to_s
    #       unless the_message.is_a?(::GxG::Events::Message)
    #         raise ArgumentError, "You MUST provide a valid message object: GxG::Events::Message or new_message Hash."
    #       end
    #       xmpp_message = Blather::Stanza::Message.new(the_message[:to], the_message[:body])
    #       # chat states: active composing gone inactive paused
    #       # xmpp_message.set_chat_state(the_message[:state].to_s.to_sym)
    #       xmpp_message.id = (the_message[:id].to_s)
    #       xmpp_message.from = (the_message[:sender].to_s)
    #       xmpp_message.to = (the_message[:to].to_s)
    #       if the_message[:context].to_s.size > 0
    #         xmpp_message.thread = (the_message[:context].to_s)
    #       end
    #       xmpp_message.subject = (the_message[:subject].to_s)
    #       #
    #       # The following <type> Symbols are allowed:
    #       # * :chat
    #       # * :error
    #       # * :groupchat
    #       # * :headline
    #       # * :normal
    #       xmpp_message.type = (the_message[:type] || :chat)
    #       xmpp_message.body = the_message[:body]
    #       xmpp_message
    #     end
    #     #
    #     # ### Initialization
    #     def initialize(options={})
    #       @client = nil
    #       @pubsub = nil
    #       @roster = nil
    #       @browser = nil
    #       @transfer_manager = nil
    #       @xfr_callbacks = nil
    #       @conversations = []
    #       @conversation_thread_safety = ::Mutex.new
    #       @invitations = []
    #       @invitation_thread_safety = ::Mutex.new
    #       @download_directory = ::File.expand_path(".")
    #       @file_transfers = []
    #       @file_transfers_thread_safety = ::Mutex.new
    #       @notification_object = options[:notify]
    #       self
    #     end
    #     # Review : debug only method
    #     def client()
    #         @client
    #     end
    #     #
    #     def notify(notification_type=nil)
    #       if notification_type
    #         if @notification_object
    #           if @notification_object.respond_to?(:notify)
    #             @notification_object.notify(notification_type)
    #           end
    #         end
    #       end
    #     end
    #     #
    #     def login(the_url=nil, options={})
    #         result = false
    #         begin
    #             if the_url.is_a?(::URI::Generic)
    #                 if the_url.password() == nil && the_url.user != "anonymous"
    #                 raise ArgumentError, "You MUST provide a vailid password."
    #                 end
    #                 the_jid = ""
    #                 if the_url.user()
    #                 the_jid << the_url.user.to_s
    #                 else
    #                 raise ArgumentError, "You MUST provide a vailid user name."
    #                 end
    #                 if the_url.hostname()
    #                 the_jid << ("@" + the_url.hostname.to_s)
    #                 else
    #                 raise ArgumentError, "You MUST provide a vailid host or IP Address."
    #                 end
    #                 if the_url.path()
    #                 the_jid << ("/" + File.basename(the_url.path.to_s))
    #                 end
    #                 # Connect
    #                 @client = ::Blather::Client::setup(the_jid, the_url.password.to_s, the_url.hostname.to_s, (the_url.port || 5222))
    #                 # @client.run
    #                 # Initialize Supports
    #                 @pubsub = ::Blather::DSL::PubSub.new(@client, self.jid_domain)
    #                 # Auto-reconnect if disconnected
    #                 self.handle :disconnected do
    #                   @client.run
    #                 end
    #                 # ### Setup Message Reception: (skipping compose etc messages for now.)
    #                 # Handlers Map : https://github.com/adhearsion/blather#handlers-hierarchy
    #                 # Private Message (type :normal)
    #                 self.handle :message, :normal?, :body do |message|
    #                   the_message = self.xmpp_message_to_gxg(message)
    #                   the_channel = self.conversations(the_message[:sender].to_s)[0]
    #                   unless the_channel
    #                       the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_message[:sender], :type => :chat})
    #                       @conversation_thread_safety.synchronize { @conversations << the_channel }
    #                   end
    #                   the_channel.add_message(the_message)
    #                   self.notify({:event => :new_private_message, :conversation => the_channel.uuid, :message => the_message.id, :sender => the_message[:sender].to_s})
    #                   true
    #                 end
    #                 # Private Message (type :chat)
    #                 self.handle :message, :chat?, :body do |message|
    #                     the_message = self.xmpp_message_to_gxg(message)
    #                     the_channel = self.conversations(the_message[:sender].to_s)[0]
    #                     unless the_channel
    #                         the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_message[:sender], :type => :chat})
    #                         @conversation_thread_safety.synchronize { @conversations << the_channel }
    #                     end
    #                     the_channel.add_message(the_message)
    #                     self.notify({:event => :new_private_message, :conversation => the_channel.uuid, :message => the_message.id, :sender => the_message[:sender].to_s})
    #                     true
    #                 end
    #                 # Group Message
    #                 self.handle :message, :groupchat?, :body do |message|
    #                     the_message = self.xmpp_message_to_gxg(message)
    #                     the_channel = self.conversations(the_message[:sender].to_s)[0]
    #                     unless the_channel
    #                         the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_message[:sender], :type => :groupchat})
    #                         @conversation_thread_safety.synchronize { @conversations << the_channel }
    #                     end
    #                     the_channel.add_message(the_message)
    #                     self.notify({:event => :new_message, :conversation => the_channel.uuid, :message => the_message.id, :sender => the_message[:sender].to_s})
    #                     true
    #                 end
    #                 # Announcement Message
    #                 self.handle :message, :headline?, :body do |message|
    #                   the_message = self.xmpp_message_to_gxg(message)
    #                   the_channel = self.conversations(the_message[:sender].to_s)[0]
    #                   unless the_channel
    #                       the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_message[:sender], :type => :chat})
    #                       @conversation_thread_safety.synchronize { @conversations << the_channel }
    #                   end
    #                   the_channel.add_message(the_message)
    #                   self.notify({:event => :new_announcement, :conversation => the_channel.uuid, :message => the_message.id, :sender => the_message[:sender].to_s})
    #                   true
    #                 end
    #                 # Error Message
    #                 self.handle :message, :error?, :body do |message|
    #                   the_message = self.xmpp_message_to_gxg(message)
    #                   the_channel = self.conversations(the_message[:sender].to_s)[0]
    #                   unless the_channel
    #                       the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_message[:sender], :type => :chat})
    #                       @conversation_thread_safety.synchronize { @conversations << the_channel }
    #                   end
    #                   the_channel.add_message(the_message)
    #                   self.notify({:event => :new_error, :conversation => the_channel.uuid, :message => the_message.id, :sender => the_message[:sender].to_s})
    #                   true
    #                 end
    #                 # Presence
    #                 self.handle :iq do |update|
    #                     if update.respond_to?(:type)
    #                         if update.is_a?(::Blather::Stanza::Iq::Ping)
    #                             # Auto-reply to Pings:
    #                             reply = update.reply
    #                             reply.type = :result
    #                             # Review : how to add a data payload to the reply?
    #                             self.write_to_stream(reply)
    #                         else
    #                             if update.is_a?(::Blather::Stanza::Iq)
    #                                 # reply = update.reply
    #                                 # reply.type = :result
    #                                 # # Review : how to add a data payload to the reply?
    #                                 # self.write_to_stream(reply)
    #                                 # puts "Got: #{update.class.inspect}\n-----------------------------------------\n#{update.inspect}\n Sent: #{reply.inspect}\n-----------------------------------------\n"
    #                             end
    #                         end
    #                     end
    #                     # Note : returning 'false' signals that subsequent process of this stanza is desired.
    #                     false
    #                 end
    #                 # Invitation
    #                 self.handle :subscription do |invitation|
    #                     gxg_invitation = ::GxG::Networking::XmppAgentInvitation.new(self, invitation)
    #                     @invitation_thread_safety.synchronize { @invitations << gxg_invitation }
    #                     self.notify({:event => :new_invitation, :invitation => gxg_invitation.uuid, :sender => gxg_invitation.from.to_s})
    #                     true
    #                 end
    #                 # Presence
    #                 self.handle :presence do |presence_update|
    #                     the_sender = "#{presence_update.from.node.to_s}@#{presence_update.from.domain.to_s}"
    #                     self.my_roster.each do |roster_item|
    #                         if roster_item.jid.to_s == the_sender
    #                             roster_item.status = presence_update
    #                             break
    #                         end
    #                     end
    #                     false
    #                 end
    #                 # File Transfer
    #                 self.handle :file_transfer do |invitation|
    #                     # gxg_invitation = ::GxG::Networking::XmppAgentInvitation.new(self, invitation)
    #                     # @invitation_thread_safety.synchronize { @invitations << gxg_invitation }
    #                     puts "Got (file transfer) : #{invitation.inspect}"
    #                     false
    #                 end
    #                 # Multi-User Chat (MUC) Invitation
    #                 self.handle :muc_join do |invitation|
    #                     # gxg_invitation = ::GxG::Networking::XmppAgentInvitation.new(self, invitation)
    #                     # @invitation_thread_safety.synchronize { @invitations << gxg_invitation }
    #                     puts "Got (MUC join) : #{invitation.inspect}"
    #                     true
    #                 end
    #                 self.handle :muc_user do |invitation|
    #                     # try also: :muc_user, :invite?
    #                     # gxg_invitation = ::GxG::Networking::XmppAgentInvitation.new(self, invitation)
    #                     # @invitation_thread_safety.synchronize { @invitations << gxg_invitation }
    #                     puts "Got (MUC user) : #{invitation.inspect}"
    #                     true
    #                 end
    #                 # Connect
    #                 @client.run
    #                 result = true
    #                 timeout = Time.now.to_f + 30.0
    #                 until @client.connected? do
    #                     if Time.now.to_f >= timeout
    #                         result = false
    #                         break
    #                     end
    #                 end
    #             end
    #         rescue Exception => the_error
    #             puts the_error.to_s
    #         end
    #         #
    #         result
    #     end
    #     #
    #     def logout
    #         if @client
    #             @client.clear_handlers :disconnected
    #             @client.close
    #             @client = nil
    #         end
    #         #
    #         true
    #     end
    #     #
    #     def buddies()
    #         result = []
    #         begin
    #             if @client
    #                 @client.roster.items.each_pair do |key_object, data|
    #                     new_record = {:jid => "", :title => "Untitled", :groups => [], :status => :offline}
    #                     new_record[:jid] = key_object.to_s
    #                     new_record[:title] = data.name.to_s
    #                     new_record[:groups] = data.groups
    #                     if data.status()
    #                         new_record[:status] = data.status().state()
    #                     end
    #                     result << new_record
    #                 end
    #             end
    #         rescue Exception => the_error
    #             log_error({:error => the_error, :parameters => {}})
    #         end
    #         result
    #     end
    #     #
    #     def add_buddy(the_jid=nil)
    #       result = false
    #       begin
    #         if @client
    #           if the_jid.is_a?(::String)
    #             unless the_jid.valid_jid?
    #               raise ArgumentError, "You MUST provide a valid JID string."
    #             end
    #             @client.write(Blather::Stanza::Presence::Subscription.new(::Blather::JID.new(the_jid), "subscribe"))
    #             result = true
    #           end
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {:the_jid => the_jid}})
    #       end
    #       result
    #     end
    #     #
    #     def remove_buddy(the_jid=nil)
    #       result = false
    #       begin
    #         if @client
    #           if the_jid.is_a?(::String)
    #             unless the_jid.valid_jid?
    #               raise ArgumentError, "You MUST provide a valid JID string."
    #             end
    #             @client.write(Blather::Stanza::Presence::Subscription.new(::Blather::JID.new(the_jid), "unsubscribe"))
    #             result = true
    #           end
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {:the_jid => the_jid}})
    #       end
    #       result
    #     end
    #     #
    #     def invitations()
    #       result = []
    #       begin
    #         if @client
    #           @invitation_thread_safety.synchronize {
    #             @invitations.each do |entry|
    #               if entry.pending?
    #                 result << entry
    #               end
    #             end
    #           }
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #       result
    #     end
    #     #
    #     def refresh_invitations()
    #       result = false
    #       begin
    #         if @client
    #           deadlist = []
    #           @invitation_thread_safety.synchronize {
    #             @invitations.each_index do |index|
    #               unless @invitations[(index)].pending?
    #                 deadlist << index
    #               end
    #             end
    #             if deadlist.size > 0
    #               deadlist.reverse.each do |the_index|
    #                 @invitations.delete_at(the_index)
    #               end
    #             end
    #             result = true
    #           }
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #       result
    #     end
    #     #
    #     def refresh_conversations()
    #       result = false
    #       begin
    #         if @client
    #           deadlist = []
    #           @conversation_thread_safety.synchronize {
    #             @conversations.each_index do |index|
    #               if @conversations[(index)].closed?
    #                 deadlist << index
    #               end
    #             end
    #             if deadlist.size > 0
    #               deadlist.reverse.each do |the_index|
    #                 @conversations.delete_at(the_index)
    #               end
    #             end
    #             result = true
    #           }
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #       result
    #     end
    #     #
    #     def conversations(select_jid=nil)
    #       result = []
    #       begin
    #         if @client
    #           @conversation_thread_safety.synchronize {
    #             @conversations.each do |entry|
    #                 if select_jid
    #                     if select_jid.to_s == entry.jid.to_s
    #                         unless entry.closed?
    #                             result << entry
    #                             break
    #                         end
    #                     end
    #                 else
    #                     unless entry.closed?
    #                         result << entry
    #                     end
    #                 end
    #             end
    #           }
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #       result
    #     end
    #     #
    #     def create_conversation(the_jid=nil, password=nil, configuration={})
    #       result = false
    #       begin
    #         if @client
    #           unless the_jid.is_a?(::String)
    #             raise ArgumentError, "You MUST provide a valid JID String."
    #           end
    #           unless the_jid.valid_jid?()
    #             raise ArgumentError, "You MUST provide a valid JID String. The one you provided is malformed."
    #           end
    #           if (self.buddies.collect {|entry| entry[:jid]}).include?(the_jid)
    #             # private channel
    #             the_channel = self.conversations(the_jid)[0]
    #             unless the_channel
    #                 the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_jid, :type => :chat})
    #                 @conversation_thread_safety.synchronize { @conversations << the_channel }
    #             end
    #           else
    #             # groupchat channel
    #             the_channel = self.conversations(the_jid)[0]
    #             unless the_channel
    #                 the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_jid, :type => :groupchat})
    #                 @conversation_thread_safety.synchronize { @conversations << the_channel }
    #             end
    #             if the_channel
    #                 the_channel.join(the_jid)
    #                 if configuration.is_any?(::Hash, ::GxG::Database::PersistedHash)
    #                   if configuration.keys.size > 0
    #                     the_channel.change_configuration(configuration)
    #                   end
    #                 end
    #             end
    #           end
    #           result = true
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {:jid => the_jid}})
    #       end
    #       result
    #     end
    #     #
    #     def join_conversation(the_jid=nil, password=nil, options={})
    #       result = false
    #       begin
    #         if @client
    #           unless the_jid.is_a?(::String)
    #             raise ArgumentError, "You MUST provide a valid JID String."
    #           end
    #           unless the_jid.valid_jid?()
    #             raise ArgumentError, "You MUST provide a valid JID String. The one you provided is malformed."
    #           end
    #           the_channel = self.conversations(the_jid)[0]
    #           unless the_channel
    #               the_channel = ::GxG::Networking::XmppAgentConversation.new(self, {:sender => the_jid, :type => :groupchat})
    #               @conversation_thread_safety.synchronize { @conversations << the_channel }
    #               the_channel.join(the_jid)
    #           end
    #           result = true
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {:jid => the_jid}})
    #       end
    #       result
    #     end
    #     #
    #     def download_directory()
    #       @file_transfers_thread_safety.synchronize { @download_directory }
    #     end
    #     #
    #     def download_directory=(the_path=nil)
    #       unless the_path.is_a?(::String)
    #         raise ArgumentError, "You MUST supply a String as valid file path."
    #       end
    #       the_path = ::File.expand_path(the_path)
    #       unless the_path.valid_path?()
    #         raise ArgumentError, "You MUST supply a valid file path."
    #       end
    #       unless ::File.exist?(the_path)
    #         raise ArgumentError, "You MUST supply a valid file path - File does not exist."
    #       end
    #       @file_transfers_thread_safety.synchronize { @download_directory = the_path }
    #     end
    #     #
    #     def send_file(the_jid=nil,the_path=nil, description=nil, buffer_size=4096, proxy=nil)
    #       if @client
    #         begin
    #           unless the_jid.is_a?(::String)
    #             raise ArgumentError, "You MUST supply a valid JID String to specify the recipient of the file."
    #           end
    #           unless the_path.is_a?(::String)
    #             raise ArgumentError, "You MUST supply a String as valid file path."
    #           end
    #           the_path = ::File.expand_path(the_path)
    #           unless the_path.valid_path?()
    #             raise ArgumentError, "You MUST supply a valid file path."
    #           end
    #           unless ::File.exist?(the_path)
    #             raise ArgumentError, "You MUST supply a valid file path - File does not exist."
    #           end
    #           unless description.is_a?(::String)
    #             description = "File Transfer: #{::File.basename(the_path)}"
    #           end
    #           unless buffer_size.is_a?(::Integer)
    #             raise ArgumentError, "You MUST provide an Integer to set buffer size."
    #           end
    #           valid_buffer_size_range = ::GxG::SYSTEM.maximum_buffer_size.get_at_path("/:ipv4/:tcp/:write/:valid")
    #           unless valid_buffer_size_range.is_a?(::Range)
    #             valid_buffer_size_range = (4096..65536)
    #           end
    #           unless valid_buffer_size_range.include?(buffer_size)
    #             raise ArgumentError, "You MUST provide an Integer between #{valid_buffer_size_range.first} and #{valid_buffer_size_range.last}."
    #           end
    #           # Review : rebuild/rewrite this section and XmppAgentFileTransfer
    #             #   the_transfer = ::GxG::Networking::XmppAgentFileTransfer.new(@transfer_manager, :upload, {:jid => the_jid, :path => the_path, :description => description}, this())
    #             #   @file_transfers_thread_safety.synchronize {
    #             #     @file_transfers << the_transfer
    #             #   }
    #             #   the_transfer.buffer_size = buffer_size
    #             #   the_transfer.upload_file(proxy)
    #             #   the_transfer.reference
    #         rescue Exception => the_error
    #           log_error({:error => the_error, :parameters => {:jid => the_jid, :path => the_path, :description => description, :buffer_size => buffer_size}})
    #         end
    #       else
    #         nil
    #       end
    #     end
    #     #
    #     def file_transfers()
    #       result = []
    #       if @client
    #         begin
    #           @file_transfers.each do |entry|
    #             if (entry.pending? || entry.in_progress? || entry.percent_completed < 100)
    #               result << entry
    #             end
    #           end
    #         rescue Exception => the_error
    #           log_error({:error => the_error, :parameters => {}})
    #         end
    #       end
    #       result
    #     end
    #     #
    #     def refresh_file_transfers()
    #       result = false
    #       begin
    #         if @client
    #           manifest = []
    #           deadlist = []
    #           @file_transfers_thread_safety.synchronize {
    #             @file_transfers.each do |entry|
    #               manifest << entry
    #             end
    #           }
    #           manifest.each_with_index do |entry, index|
    #             unless (entry.pending?() || entry.in_progress?())
    #               deadlist << index
    #             end
    #           end
    #           @file_transfers_thread_safety.synchronize {
    #             if deadlist.size > 0
    #               deadlist.reverse.each do |the_index|
    #                 @file_transfers.delete_at(the_index)
    #               end
    #             end
    #           }
    #           result = true
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #       result
    #     end
    #     #
    #     def find_file_transfer(reference=nil, use_session = false)
    #       result = nil
    #       begin
    #         if @client
    #           manifest = []
    #           @file_transfers_thread_safety.synchronize {
    #             @file_transfers.each do |entry|
    #               manifest << entry
    #             end
    #           }
    #           manifest.each do |entry|
    #             if use_session == true
    #               if (reference == entry.session_id())
    #                 result = entry
    #                 break
    #               end
    #             else
    #               if (reference == entry.reference())
    #                 result = entry
    #                 break
    #               end
    #             end
    #           end
    #         end
    #       rescue Exception => the_error
    #         log_error({:error => the_error, :parameters => {}})
    #       end
    #       result
    #     end
    #     #
    #     #
    # end
    
    # ### XMPP
        # class BridgeAdapterXMPP < ::GxG::Communications::BridgeAdapter
        #     def self.protocol()
        #         :xmpp
        #     end
        #     #
        #     def self.abilities()
        #         [:message, :file_transfer, :request]
        #     end
        #     #
        #     def self.limits()
        #         {:message_size => 1048576, :file_transfer_size => nil, :request_size => 65536}
        #     end
        #     #
        #     def self.templates()
        #         {}
        #     end
        #     #
        #     private
        #     def decode_message(the_message=nil)
        #         result = message
        #         if message.is_a?(::GxG::Events::Message)
        #             fallback_key = nil
        #             key = nil
        #             message_sender = message[:sender].to_s
        #             @thread_safety.synchronize {
        #                 if @keychain[(message_sender.to_s)]
        #                     fallback_key = @keychain[(message_sender.to_s)][:original]
        #                     key = @keychain[(message_sender.to_s)][:current]
        #                 end
        #             }
        #             new_body = nil
        #             if key && fallback_key
        #                 if message[:body].is_a?(::String)
        #                     begin
        #                         if message[:body].base64?
        #                             new_body = message[:body].decode64.decrypt(key)
        #                         else
        #                             new_body = message[:body].decrypt(key)
        #                         end
        #                         new_body = ::Hash::gxg_import(::JSON::parse(new_body, {:symbolize_names => true}))
        #                     rescue Exception => the_error
        #                         begin
        #                             if message[:body].base64?
        #                                 new_body = message[:body].decode64.decrypt(fallback_key)
        #                             else
        #                                 new_body = message[:body].decrypt(fallback_key)
        #                             end
        #                             new_body = ::Hash::gxg_import(::JSON::parse(new_body, {:symbolize_names => true}))
        #                         rescue Exception => the_error
        #                             message[:bridge_unintelligible] = true
        #                             log_error({:error => the_error})
        #                             new_body = nil
        #                         end
        #                     end
        #                 end
        #             else
        #                 if message[:body].is_a?(::String)
        #                     if message[:body].base64?
        #                         new_body = message[:body].decode64
        #                     else
        #                         new_body = message[:body]
        #                     end
        #                     begin
        #                         new_body = ::Hash::gxg_import(::JSON::parse(new_body, {:symbolize_names => true}))
        #                     rescue Exception => the_error
        #                         log_error({:error => the_error})
        #                         new_body = nil
        #                     end
        #                 end
        #             end
        #             if new_body.is_a?(::Hash)
        #                 message[:body] = new_body
        #             end
        #         end
        #         result
        #     end
        #     #
        #     public
        #     #
        #     def initialize(the_process=nil, the_url=nil, options={:sasl => :digest, :digest => true})
        #         super(the_process, the_url, options)
        #         unless @options[:sasl]
        #             @options = {:sasl => :digest, :digest => true}
        #         end
        #         #
        #         # Channels format: {<uuid> => {:channel => <XMPPConversation>, :entities => [<jid-string>, ...]}}
        #         @channels = {}
        #         # Keychain format: {:original => "", :current => ""}
        #         @keychain = {}
        #         # Messages format: {<uuid> => [<::GxG::Events::Message>, ...]}
        #         @messages = {}
        #         @messages_busy_semaphore = false
        #         @invitations = {}
        #         @file_transfers = {}
        #         #
        #         @connector = ::GxG::Networking::XmppClient.new({:notify => self})
        #         self.open
        #         #
        #         self
        #     end
        #     #
        #     def my_id()
        #         if @connector
        #             @connector.my_jid.to_s
        #         else
        #             nil
        #         end
        #     end
        #     # ### Information Refresh
        #     def notify(details=nil)
        #         if details.is_a?(::Hash)
        #             if @process
        #                 if @process.respond_to?(:dispatcher) && @process.respond_to?(:respond_to_event?)
        #                     case details[:event]
        #                     when :new_invitation
        #                         active_list = {}
        #                         @connector.invitations.each do |the_invitation|
        #                             active_list[(the_invitation.uuid)] = {:invitation => the_invitation, :title => the_invitation[:title].to_s, :sender => the_invitation[:sender].to_s, :type => the_invitation[:type].to_s}
        #                         end
        #                         @thread_safety.synchronize { @invitations = active_list }
        #                         #
        #                         if @process.respond_to_event?(:new_invitation)
        #                             @process.dispatcher.post_event(:communications) do
        #                                 @process.call_event({:new_invitation => {:invitation => details[:invitation], :sender => details[:sender], :at => ::DateTime.now}})
        #                             end
        #                         end
        #                     when :new_file_transfer
        #                         # First, update Bridge Manifest
        #                         active_list = {}
        #                         @connector.file_transfers.each do |the_transfer|
        #                             reference = the_transfer.reference
        #                             file_name = the_transfer.file_details[:filename]
        #                             file_size = the_transfer.file_details[:size]
        #                             sender = the_transfer.info[:sender]
        #                             # set download path
        #                             unless ::File.exists?(GxG::SERVER_PATHS[:temporary] + "/" + reference.to_s)
        #                                 ::FileUtils.mkpath(GxG::SERVER_PATHS[:temporary] + "/" + reference.to_s)
        #                             end
        #                             the_transfer.download_directory = (GxG::SERVER_PATHS[:temporary] + "/" + reference.to_s)
        #                             # store entry
        #                             active_list[(reference)] = {:transfer => the_transfer, :sender => sender, :file => file_name, :size => file_size, :path => ("/System/Temporary/" + reference.to_s + "/" + file_name)}
        #                         end
        #                         @thread_safety.synchronize { @file_transfers = active_list }
        #                         if @process.respond_to_event?(:new_file_transfer)
        #                             @process.dispatcher.post_event(:communications) do
        #                                 @process.call_event({:new_file_transfer => {:transfer => details[:transfer], :sender => details[:sender], :at => ::DateTime.now}})
        #                             end
        #                         end
        #                     when :file_transfer_complete, :file_transfer_cancelled, :file_transfer_error
        #                         notification = {}
        #                         notification[(details[:event])] = {:transfer => details[:transfer], :at => ::DateTime.now}
        #                         #
        #                         active_list = {}
        #                         @connector.file_transfers.each do |the_transfer|
        #                             reference = the_transfer.reference
        #                             file_name = the_transfer.file_details[:filename]
        #                             file_size = the_transfer.file_details[:size]
        #                             sender = the_transfer.info[:sender]
        #                             # store entry
        #                             active_list[(reference)] = {:transfer => the_transfer, :sender => sender, :file => file_name, :size => file_size, :path => ("/System/Temporary/" + reference.to_s + "/" + file_name)}
        #                         end
        #                         @thread_safety.synchronize { @file_transfers = active_list }
        #                         #
        #                         if @process.respond_to_event?(details[:event])
        #                             @process.call_event(notification)
        #                         end
        #                     when :file_transfer_progress
        #                         if @process.respond_to_event?(:file_transfer_progress)
        #                             @process.call_event({:file_transfer_progress => {:transfer => details[:transfer], :progress => details[:progress], :at => ::DateTime.now}})
        #                         end
        #                     when :new_message, :new_private_message, :new_announcement, :new_error
        #                         # ### unless channel exists - add it
        #                         the_channel = @thread_safety.synchronize { @channels[(details[:conversation].to_sym)] }
        #                         unless the_channel
        #                             found = nil
        #                             @connector.conversations.each do |channel_object|
        #                                 if details[:conversation].to_sym == channel_object.uuid
        #                                     found = channel_object
        #                                     break
        #                                 end
        #                             end
        #                             if found
        #                                 @thread_safety.synchronize { @channels[(details[:conversation].to_sym)] = {:channel => found, :title => found.title()}}
        #                                 the_channel = found
        #                             end
        #                         end
        #                         # ### get messages
        #                         if the_channel
        #                             unless @thread_safety.synchronize { @messages[(the_channel.uuid)].is_a?(::Array) }
        #                                 @thread_safety.synchronize { @messages[(the_channel.uuid)] = [] }
        #                             end
        #                             the_channel.process_received() do |the_message|
        #                                 # Note: this will pick up other messages from the adapter now, but it is ok - a notification will be generated on EACH message.
        #                                 the_message[:channel] = the_channel.uuid
        #                                 @thread_safety.synchronize { @messages[(the_channel.uuid)] << the_message }
        #                             end
        #                         end
        #                         # Review : differentiate beteween private and open messages? How to do?
        #                         if @process.respond_to_event?(:new_message)
        #                             notification = {}
        #                             notification[:new_message] = {:channel => details[:conversation], :message => details[:message], :sender => details[:sender].to_s, :at => ::DateTime.now}
        #                             #
        #                             @process.dispatcher.post_event(:communications) do
        #                                 @process.call_event(notification)
        #                             end
        #                         end
        #                         #
        #                     end
        #                 end
        #             end
        #         end
        #     end
        #     # ### Keychain
        #     def set_key(recipient=nil, password=nil)
        #         result = false
        #         if recipient.to_s.valid_jid? && password.is_a?(::String)
        #             @thread_safety.synchronize {
        #                 if @keychain[(recipient.to_s)]
        #                     @keychain[(recipient.to_s)][:current] = password
        #                 else
        #                     @keychain[(recipient.to_s)] = {:original => password, :current => password}
        #                 end
        #                 result = true
        #             }
        #         end
        #         result
        #     end
        #     # ### Invitations
        #     def accept_invitation(the_invitation_uuid=nil)
        #         result = false
        #         if ::GxG::valid_uuid?(the_invitation_uuid)
        #             found = nil
        #             @thread_safety.synchronize {
        #                 found = @invitations[(the_invitation_uuid.to_sym)]
        #             }
        #             if found
        #                 found[:invitation].accept()
        #                 result = true
        #             end
        #         end
        #         result
        #     end
        #     #
        #     def decline_invitation(the_invitation_uuid=nil)
        #         result = false
        #         if ::GxG::valid_uuid?(the_invitation_uuid)
        #             found = nil
        #             @thread_safety.synchronize {
        #                 found = @invitations[(the_invitation_uuid.to_sym)]
        #             }
        #             if found
        #                     found[:invitation].decline()
        #                     result = true
        #                 end
        #             end
        #             result
        #         end
        #         # ### File Transfers
        #         def file_transfers()
        #             result = {}
        #             @thread_safety.synchronize {
        #                 @file_transfers.each_pair do |the_uuid, the_record|
        #                     result[(the_uuid)] = {:sender => the_record[:sender], :file => the_record[:file], :size => the_record[:size], :path => the_record[:path]}
        #                 end
        #             }
        #             result
        #         end
        #         #
        #         def accept_file_transfer(the_transfer_uuid=nil)
        #             result = false
        #             if ::GxG::valid_uuid?(the_transfer_uuid)
        #                 found = nil
        #                 @thread_safety.synchronize {
        #                     found = @file_transfers[(the_transfer_uuid.to_sym)]
        #                 }
        #                 if found
        #                     found[:transfer].accept()
        #                     result = true
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def decline_file_transfer(the_transfer_uuid=nil)
        #             result = false
        #             if ::GxG::valid_uuid?(the_transfer_uuid)
        #                 found = nil
        #                 @thread_safety.synchronize {
        #                     found = @file_transfers[(the_transfer_uuid.to_sym)]
        #                 }
        #                 if found
        #                     found[:transfer].decline()
        #                     if ::File.exists?(GxG::SERVER_PATHS[:temporary] + "/" + found[:transfer].reference.to_s)
        #                         ::GxG::VFS.rmdir("/System/Temporary/" + found[:transfer].reference.to_s)
        #                     end
        #                     result = true
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def cancel_file_transfer(the_transfer_uuid=nil)
        #             result = false
        #             if ::GxG::valid_uuid?(the_transfer_uuid)
        #                 found = nil
        #                 @thread_safety.synchronize {
        #                     found = @file_transfers[(the_transfer_uuid.to_sym)]
        #                 }
        #                 if found
        #                     found[:transfer].cancel()
        #                     if ::File.exists?(GxG::SERVER_PATHS[:temporary] + "/" + found[:transfer].reference.to_s)
        #                         ::GxG::VFS.rmdir("/System/Temporary/" + found[:transfer].reference.to_s)
        #                     end
        #                     result = true
        #                 end
        #             end
        #             result
        #         end
        #         # ### Entities
        #         def entities()
        #             result = []
        #             @connector.buddies().each do |record|
        #                 new_record = {:id => "", :title => "Untitled", :groups => [], :status => :offline}
        #                 new_record[:id] = record[:jid]
        #                 new_record[:title] = record[:title]
        #                 new_record[:groups] = record[:groups]
        #                 case record[:status]
        #                 when :chat, :normal, :available
        #                     new_record[:status] = :online
        #                 when :dnd
        #                     new_record[:status] = :busy
        #                 when :away
        #                     new_record[:status] = :away
        #                 when :xa
        #                     new_record[:status] = :extended_away
        #                 when :unavailable, :offline
        #                     new_record[:status] = :offline
        #                 when :error
        #                     new_record[:status] = :error
        #                 end
        #                 result << new_record
        #             end
        #             result
        #         end
        #         #
        #         def entity_status(the_address=nil)
        #             result = :invalid_address
        #             if the_address.valid_jid?()
        #                 result = :unknown_address
        #                 self.entities.each do |the_record|
        #                     if the_record[:id] == the_address
        #                         result = the_record[:status]
        #                         break
        #                     end
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def status()
        #             result = :offline
        #             case @adapter.get_status
        #             when :chat, :normal, :available
        #                 result = :online
        #             when :dnd
        #                 result = :busy
        #             when :away
        #                 result = :away
        #             when :xa
        #                 result = :extended_away
        #             when :unavailable, :offline
        #                 result = :offline
        #             when :error
        #                 result = :error
        #             end
        #             result                
        #         end
        #         #
        #         def status=(the_status=nil, message=nil)
        #             result = :available
        #             case the_status
        #             when :online
        #                 result = :available
        #             when :busy
        #                 result = :dnd
        #             when :away
        #                 result = :away
        #             when :extended_away
        #                 result = :xa
        #             when :offline
        #                 result = :unavailable
        #             when :error
        #                 result = :error
        #             end
        #             @adapter.set_status(result, message)
        #         end
        #         # ### Basic Channel Support
        #         def channels()
        #             result = {}
        #             @thread_safety.synchronize {
        #                 @channels.each_pair do |the_uuid, the_record|
        #                     result[(the_uuid)] = the_record[:title]
        #                 end
        #             }
        #             result
        #         end
        #         #
        #         def associate(recipient=nil)
        #             result = false
        #             if recipient.is_a?(::String)
        #                 if recipient.valid_jid?
        #                     @adapter.add_buddy(recipient)
        #                     result = true
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def disassociate(recipient=nil)
        #             result = false
        #             if recipient.is_a?(::String)
        #                 if recipient.valid_jid?
        #                     @adapter.remove_buddy(recipient)
        #                     result = true
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def open_channel(with_jid=nil, password=nil, configuration={})
        #             result = nil
        #             if with_jid.is_a?(::String)
        #                 if with_jid.valid_jid? && configuration.is_any?(::Hash, ::GxG::Database::PersistedHash)
        #                     # If channel already exists and they attempt a repeat opening action:
        #                     @thread_safety.synchronize {
        #                         @channels.each_pair do |the_uuid, the_record|
        #                             if with_jid.to_s == the_record.jid.to_s
        #                                 result = the_record.uuid
        #                                 break
        #                             end
        #                         end
        #                     }
        #                     unless result
        #                         # Channel needs to be constructed:
        #                         if @connector.create_conversation(with_jid, password, configuration) == true
        #                             existing_channels = self.channels()
        #                             found = nil
        #                             @thread_safety.synchronize {
        #                                 @connector.conversations.each do |channel_object|
        #                                     if existing_channels.keys.include?(channel_object.uuid)
        #                                         next
        #                                     else
        #                                         found = channel_object
        #                                         @channels[(channel_object.uuid)] = {:channel => found, :title => found.title()}
        #                                         break
        #                                     end
        #                                 end
        #                             }
        #                             if found
        #                                 result = channel_object.uuid
        #                                 if password
        #                                     if channel_object[:type] == :chat
        #                                         # on :groupchat password is only used for access, not encryption.
        #                                         self.set_key(with_jid, password)
        #                                     end
        #                                 end
        #                             end
        #                             #
        #                         end
        #                     end
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def join_channel(channel_jid=nil, password=nil, options={})
        #             result = nil
        #             if channel_jid.is_a?(::String)
        #                 if channel_jid.valid_jid? && options.is_any?(::Hash, ::GxG::Database::PersistedHash)
        #                     if @connector.join_conversation(channel_jid, password, options) == true
        #                         existing_channels = self.channels()
        #                         found = nil
        #                         @thread_safety.synchronize {
        #                             @connector.conversations.each do |channel_object|
        #                                 if existing_channels.keys.include?(channel_object.uuid)
        #                                     next
        #                                 else
        #                                     found = channel_object
        #                                     @channels[(channel_object.uuid)] = {:channel => found, :title => found.title()}
        #                                     break
        #                                 end
        #                             end
        #                         }
        #                         if found
        #                             result = channel_object.uuid
        #                         end
        #                         #
        #                     end
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def close_channel(the_channel_uuid=nil)
        #             if ::GxG::valid_uuid?(the_channel_uuid)
        #                 the_channel = nil
        #                 @thread_safety.synchronize {
        #                     if @channels[(the_channel_uuid.to_sym)].is_a?(::Hash)
        #                         the_channel = @channels.delete(the_channel_uuid.to_sym)[:channel]
        #                     end
        #                 }
        #                 if the_channel
        #                     the_channel.leave("{ \"exit_channel\":\"#{the_channel.my_jid.to_s}\" }")
        #                     true
        #                 else
        #                     false
        #                 end
        #             else
        #                 false
        #             end
        #         end
        #         # ### Messages
        #         def send_message(the_channel_uuid=nil, message=nil, recipient=nil, use_fallback_key=false)
        #             result = false
        #             # 
        #             if ::GxG::valid_uuid?(the_channel_uuid)
        #                 the_channel = nil
        #                 @thread_safety.synchronize {
        #                     if @channels[(the_channel_uuid.to_sym)].is_a?(::Hash)
        #                         the_channel = @channels[(the_channel_uuid.to_sym)][:channel]
        #                     end
        #                 }
        #                 if the_channel
        #                     if message.is_any?(::String, ::Hash, ::GxG::Database::PersistedHash, ::GxG::Events::Message)
        #                         if message.is_a?(::String)
        #                             message = new_message({:sender => @connector.my_jid.to_s, :body => {:message => message}.gxg_export.to_json})
        #                         end
        #                         if message.is_a?(::Hash)
        #                             message = new_message({:sender => @connector.my_jid.to_s, :body => message.gxg_export.to_json})
        #                         end
        #                         if message.is_a?(::GxG::Database::PersistedHash)
        #                             message = new_message({:sender => @connector.my_jid.to_s, :body => message.sync_export.gxg_export.to_json})
        #                         end
        #                         if message.is_a?(::GxG::Events::Message)
        #                             if message[:body].is_a?(::Hash)
        #                                 message[:body] = message[:body].gxg_export.to_json
        #                             end
        #                             if message[:body].is_a?(::GxG::Database::PersistedHash)
        #                                 message[:body] = message[:body].sync_export.gxg_export.to_json
        #                             end
        #                         end
        #                         #
        #                         if message.is_a?(::GxG::Events::Message)
        #                             # Reset :sender if a ruby object is the current setting. (bridge addressing translation)
        #                             unless message[:sender].is_a?(::String)
        #                                 message[:sender] = @connector.my_jid.to_s
        #                             end
        #                             # encrypt body?
        #                             key = nil
        #                             if recipient.is_a?(::String)
        #                                 intended_recipient = recipient
        #                             else
        #                                 intended_recipient = the_channel.jid()
        #                             end                                
        #                             @thread_safety.synchronize {
        #                                 if @keychain[(intended_recipient.to_s)]
        #                                     if use_fallback_key == true
        #                                         key = @keychain[(intended_recipient.to_s)][:original]
        #                                     else
        #                                         key = @keychain[(intended_recipient.to_s)][:current]
        #                                     end
        #                                 end
        #                             }
        #                             if key.is_a?(::String)
        #                                 message[:body] = message[:body].encrypt(key).encode64
        #                             else
        #                                 message[:body] = message[:body].encode64
        #                             end
        #                             # send message
        #                             result = the_channel.say_something(message, recipient)
        #                             # Review : use this next little bit of code in the request/reply code:
        #                             # if result == true
        #                             #     message.succeed(message)
        #                             # else
        #                             #     message.fail(message)
        #                             # end
        #                         end
        #                     else
        #                         raise ArgumentError, "You MUST provide the message as a String, Hash, GxG::Database::PersistedHash, or GxG::Events::Message; NOT #{message.class} ."
        #                     end
        #                 else
        #                     raise ArgumentError, "Invalid Channel selector, the Channel was not found: #{the_channel.inspect} . Try opening the channel first."
        #                 end
        #             else
        #                 raise ArgumentError, "Invalid Channel selector: #{the_channel.inspect} . You MUST provide a valid UUID."
        #             end
        #             result
        #         end
        #         #
        #         def next_message(the_channel_uuid=nil)
        #             result = nil
        #             if ::GxG::valid_uuid?(the_channel_uuid)
        #                 @thread_safety.synchronize {
        #                     if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
        #                         result = @messages[(the_channel_uuid.to_sym)].shift
        #                     end
        #                 }
        #                 if result
        #                     result = decode_message(result)
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def all_messages(the_channel_uuid=nil)
        #             result = []
        #             if ::GxG::valid_uuid?(the_channel_uuid)
        #                 @thread_safety.synchronize {
        #                     if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
        #                         @messages[(the_channel_uuid.to_sym)].size.times do
        #                             result << decode_message(@messages[(the_channel_uuid.to_sym)].shift)
        #                         end
        #                     end
        #                 }
        #             end
        #             result
        #         end
        #         #
        #         def get_message(the_channel_uuid=nil, the_message_uuid=nil)
        #             result = nil
        #             if ::GxG::valid_uuid?(the_channel_uuid) && the_message_uuid
        #                 @thread_safety.synchronize {
        #                     if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
        #                         @messages[(the_channel_uuid.to_sym)].each_with_index do |the_message, the_index|
        #                             if the_message_uuid == the_message.id()
        #                                 result = @messages[(the_channel_uuid.to_sym)].delete_at(the_index)
        #                                 break
        #                             end
        #                         end
        #                     end
        #                 }
        #                 if result
        #                     result = decode_message(result)
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def get_messages_by_context(the_channel_uuid=nil, the_context_uuid=nil)
        #             result = []
        #             if ::GxG::valid_uuid?(the_channel_uuid) && the_context_uuid
        #                 @thread_safety.synchronize {
        #                     if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
        #                         @messages[(the_channel_uuid.to_sym)].each_with_index do |the_message, the_index|
        #                             if the_context_uuid.to_s.to_sym == the_message[:context].to_s.to_sym
        #                                 result << @messages[(the_channel_uuid.to_sym)].delete_at(the_index)
        #                             end
        #                         end
        #                     end
        #                 }
        #                 if result
        #                     result = decode_message(result)
        #                 end
        #             end
        #             result
        #         end
        #         #
        #         def get_messages_by_sender(the_channel_uuid=nil, the_sender=nil)
        #             result = []
        #             if ::GxG::valid_uuid?(the_channel_uuid) && the_sender
        #                 @thread_safety.synchronize {
        #                     if @messages[(the_channel_uuid.to_sym)].is_a?(::Array)
        #                         @messages[(the_channel_uuid.to_sym)].each_with_index do |the_message, the_index|
        #                             if the_sender.to_s == the_message[:sender].to_s
        #                                 result << @messages[(the_channel_uuid.to_sym)].delete_at(the_index)
        #                             end
        #                         end
        #                     end
        #                 }
        #                 if result
        #                     result = decode_message(result)
        #                 end
        #             end
        #             result
        #         end
        #         #
        #     end
        #