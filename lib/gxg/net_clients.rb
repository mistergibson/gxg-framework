require 'net/http'
require 'net/ftp'
require 'net/ssh'
require 'net/scp'
require 'net/sftp'
require 'xmlrpc/client'
require 'handsoap'
require 'rest-client'
require 'net/pop'
require 'net/smtp'
require 'net/imap'
require 'gmail_xoauth'
require 'mail'
require 'matrix_sdk'
require 'nextcloud'
# GxG:
module GxG
  #
  module Networking
    #
    class ClientDispatcher
      def initialize()
        @thread_safety = ::Mutex.new
        @client_database = {}
      end
      #
      def new_client(the_url=nil, options={})
        result = nil
        if the_url.is_any?(::String, ::Symbol, ::URI::Generic)
          if the_url.is_any?(::String, ::Symbol)
            the_url = ::URI.parse(the_url.to_s)
          else
            the_url = the_url.clone
          end
          client_scheme = the_url.scheme.to_s
          client_class = @thread_safety.synchronize {
            if @client_database[(client_scheme.to_sym)].is_a?(::Hash)
              @client_database[(client_scheme.to_sym)][:client]
            else
              nil
            end
          }
          if client_class
            if the_url.scheme.to_s.include?("-")
              the_url.scheme = the_url.scheme.to_s.split("-")[1]
            end
            if client_class.respond_to?(:connect)
              result = client_class::connect(the_url, options)
            else
              result = client_class.new(the_url, options)
            end
          else
            log_warn("Unable to find a client for protocol: #{client_scheme}")
          end
        else
          log_warn("Unable to find a client for protocol: #{the_url.inspect}")
        end
        result
      end
      #
      def register_client(the_scheme=nil, client_class=nil)
        result = false
        if the_scheme.is_any?(::Symbol, ::String) && client_class.is_a?(::Class)
          if the_scheme.to_s.include?("-")
            protocol = the_scheme.to_s.split("-")[0]
            service =  the_scheme.to_s.split("-")[1]
          else
            protocol = the_scheme.to_s
            service = protocol
          end
          #
          ::GxG::SYSTEM.service_ports_register_client(service, the_scheme.to_s)
          @thread_safety.synchronize {
            @client_database[(the_scheme.to_s.to_sym)] = {:client => client_class}
          }
          #
          result = true
        end
        result
      end
      #
      def unregister_client()
      end
    end
    DISPATCHER = ::GxG::Networking::ClientDispatcher.new
    # To Generate OAuth2 Tokens, See: https://github.com/google/gmail-oauth2-tools
    # IMAP Classes:
    class ImapClient
      # ???
      def connector()
        @client
      end
      #
      def initialize(the_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI."
        end
        @user = the_url.user
        @password = the_url.password
        @client = nil
        @host = the_url.hostname
        if options[:use_ssl] == true || the_url.scheme.to_s == "imaps"
          @port = (the_url.port || 993)
        else
          @port = (the_url.port || 143)
        end
        #
        @capability = []
        #
        @mounted = nil
        @mount_mode = :read
        #
        if options[:use_ssl] == true
          if options[:ignore_ssl_errors] == true
            @client = Net::IMAP.new(@host, @port, true, nil, false)
          else
            @client = Net::IMAP.new(@host, @port, true)
          end
        else
          @client = Net::IMAP.new(@host, @port)
        end
        @capability = @client.capability
        #
        self
      end
      #
      def inspect()
        "<ImapClient: User: #{@user.inspect} Host: #{@host.inspect} Connected: #{! @client.disconnected?}>"
      end
      #
      def capability()
        @capability.clone
      end
      #
      def login(user_id=nil, password=nil, options={:method => :auth})
        result = false
        if user_id.is_a?(::Hash)
          options = user_id
          user_id = nil
          password = nil
        end
        begin
          if @client
            unless @client.disconnected?
              unless user_id
                user_id = @user
                unless user_id
                  raise ArgumentError, "You MUST provide a USER id, like this: <user_id>,<password>,(<options>)"
                end
              end
              unless password
                password = @password
                unless password
                  raise ArgumentError, "You MUST provide a PASSWORD/OAUTH-TOKEN, like this: <user_id>,<password/oauth-token>,(<options>)"
                end
              end
              case options[:method]
              when :auth
                @client.login(user_id, password)
              when :login
                @client.authenticate("LOGIN", user_id, password)
              when :cram_md5
                @client.authenticate("CRAM-MD5", user_id, password)
              when :oauth2
                @client.authenticate("XOAUTH2", user_id, password)
              else
                raise ArgumentError, "Authentication method #{options[:method].inspect} not supported. Choose one of these: [:auth, :login, :cram_md5, :oauth2]"
              end
              #
              result = true
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:user => user_id, :options => options}})
        end
        result
      end
      #
      def logout()
        result = false
        if @client
          begin
            @client.logout
            @client.disconnect
            result = @client.disconnected?
            @client = nil
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {}})
          end
        end
        result
      end
      #
      def mounted?
        result = false
        if @client
          if @mounted
            result = true
          end
        end
        result
      end
      #
      def mount_mode()
        if self.mounted?
          @mount_mode
        else
          :unmounted
        end
      end
      #
      def mount(mailbox=nil,mode=:read_write)
        result = false
        if @client
          begin
            unless [:read, :read_write].include?(mode)
              raise ArgumentError, "Mode #{mode.inspect} is invalid. Choose one of these: [:read, :read_write]."
            end
            if self.mounted?
              if @mounted == mailbox
                if self.mount_mode() == :read && mode == :read_write
                  response = @client.select(mailbox)
                  if response.is_a?(::Net::IMAP::TaggedResponse)
                    if response.name == "OK"
                      @mounted = mailbox
                      @mount_mode = :read_write
                      result = true
                    else
                      raise Exception, "Failed to re-mount #{mailbox.inspect} as :read_write."
                    end
                  else
                    raise Exception, "Failed to re-mount #{mailbox.inspect} as :read_write."
                  end
                else
                  result = true
                end
              else
                raise Exception, "You must unmount mailbox #{@mounted.inspect} first, then mount #{mailbox.inspect}."
              end
            else
              # mount
              if mode == :read_write
                response = @client.select(mailbox)
                if response.is_a?(::Net::IMAP::TaggedResponse)
                  if response.name == "OK"
                    @mounted = mailbox
                    @mount_mode = :read_write
                    result = true
                  else
                    raise Exception, "Failed to mount #{mailbox.inspect} as :read_write."
                  end
                else
                  raise Exception, "Failed to mount #{mailbox.inspect} as :read_write."
                end
              else
                # mount :read only
                response = @client.examine(mailbox)
                if response.is_a?(::Net::IMAP::TaggedResponse)
                  if response.name == "OK"
                    @mounted = mailbox
                    @mount_mode = :read
                    result = true
                  else
                    raise Exception, "Failed to mount #{mailbox.inspect} as :read."
                  end
                else
                  raise Exception, "Failed to mount #{mailbox.inspect} as :read."
                end
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox, :mode => mode}})
          end
        end
        result
      end
      #
      def unmount()
        result = false
        if self.mounted?()
          @mounted = nil
          @mount_mode = :read
          result = true
        end
        result
      end
      #
      def status(mailbox=nil)
        result = {:connected => false, :unseen => 0, :recent => 0, :messages => 0}
        if @client
          begin
            result[:connected] = (! @client.disconnected?)
            the_mailbox = (mailbox || @mounted)
            unless the_mailbox
              raise ArgumentError, "You must either MOUNT an inbox, or specify one to get status."
            end
            if result[:connected] == true
              raw_response = @client.status(the_mailbox, ["UNSEEN","MESSAGES", "RECENT"])
              if raw_response.is_a?(::Hash)
                result[:unseen] = raw_response["UNSEEN"]
                result[:recent] = raw_response["RECENT"]
                result[:messages] = raw_response["MESSAGES"]
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:reference => reference, :mailbox => mailbox}})
          end
        end
        result
      end
      # 
      def list(reference=nil, mailbox=nil)
        result = []
        if @client
          begin
            unless reference
              raise ArgumentError, "You MUST sepcify a REFERENCE to list."
            end
            unless mailbox
              raise ArgumentError, "You MUST sepcify a MAILBOX to list."
            end
            raw_list = @client.list(reference, mailbox)
            if raw_list
              raw_list.each do |entry|
                if entry.is_a?(::Net::IMAP::MailboxList)
                  result << {:name => entry.name, :flags => entry.attr, :delimiter => entry.delim}
                end
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:reference => reference, :mailbox => mailbox}})
          end
        end
        result
      end
      #
      def xlist(reference=nil, mailbox=nil)
        result = []
        if @client
          begin
            unless reference
              raise ArgumentError, "You MUST sepcify a REFERENCE to list."
            end
            unless mailbox
              raise ArgumentError, "You MUST sepcify a MAILBOX to list."
            end
            raw_list = @client.xlist(reference, mailbox)
            if raw_list
              raw_list.each do |entry|
                if entry.is_a?(::Net::IMAP::MailboxList)
                  result << {:name => entry.name, :flags => entry.attr, :delimiter => entry.delim}
                end
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:reference => reference, :mailbox => mailbox}})
          end
        end
        result
      end
      #
      def upload_message(mailbox=nil, gxg_message=nil, flags=[:Seen], timestamp=::Time.now)
        result = false
        if @client
          begin
            if mailbox.is_a?(::GxG::Events::Message)
              if gxg_message.is_any?(::Symbol,::Array)
                flags = gxg_message
              end
              gxg_message = mailbox
              mailbox = nil
            end
            unless mailbox
              mailbox = @mounted
              unless @mount_mode == :read_write
                raise Exception, "You should re-mount #{@mounted.inspect} as :read_write, or select another MAILBOX."
              end
            end
            unless mailbox
              raise ArgumentError, "You MUST sepcify a MAILBOX to append the message to."
            end
            if flags.is_a?(::Symbol)
              flags = [(flags)]
            end
            if flags.is_a?(::Array)
              unless flags.include?(:Seen)
                flags << :Seen
              end
            end
            unless gxg_message.is_a?(::GxG::Events::Message)
              raise ArgumentError, "You MUST provide a ::GxG::Events::Message object as the message. See: <SmtpClient>.message_template()"
            end
            # Build suitable mail message
            message = Mail.new
            the_fields = []
            gxg_message[:header].each_pair do |the_key, the_value|
              if the_value.is_a?(::Array)
                the_value.each do |the_field_value|
                  the_fields << "#{the_key.to_s}: #{the_field_value.to_s}"
                end
              else
                the_fields << "#{the_key.to_s}: #{the_value.to_s}"
              end
            end
            message.header = the_fields.join("\r\n")
            message.from = gxg_message[:sender]
            message.reply_to = gxg_message[:sender]
            if gxg_message[:id].to_s.include?("@")
              message.message_id = gxg_message[:id].to_s
            else
              message.message_id = "<#{gxg_message[:id].to_s}@#{::Socket.gethostname}.mail>"
            end
            message.to = gxg_message[:to]
            if gxg_message[:cc]
              message.cc = gxg_message[:cc]
            end
            if gxg_message[:bcc]
              message.bcc = gxg_message[:bcc]
            end
            message.subject = gxg_message[:subject]
            message.date = (gxg_message[:date].to_s || ::DateTime.now.to_s)
            if gxg_message[:attachments].size > 0
              multipart = true
            else
              part_count = 0
              gxg_message[:body].each do |part|
                unless part[:prologue] || part[:epilogue]
                  part_count += 1
                end
              end
              if part_count > 1
                multipart = true
              else
                multipart = false
              end
            end
            if multipart
              gxg_message[:body].each do |part|
                unless part[:prologue] || part[:epilogue]
                  type_info = "Content-Type: #{part[:content_type][:type]}"
                  if part[:content_type][:parameters].keys.size > 0
                    part[:content_type][:parameters].each_pair do |the_key, the_value|
                      type_info << "; '#{the_key.to_s}': '#{the_value.to_s}'"
                    end
                  end
                  new_part = Mail::Part.new(type_info)
                  new_part.body = part[:content]
                  message.add_part(new_part)
                end
              end
              # Add file attachments:
              gxg_message[:attachments].each do |attachment|
                if attachment[:content].size == 0
                  file_size = ::File.size(attachment[:path])
                  file_handle = ::File.open(attachment[:path],"rb")
                  ::GxG::apportioned_ranges(file_size,65536).each do |the_range|
                    file_handle.seek(the_range.first)
                    attachment[:content] << file_handle.read(the_range.size)
                  end
                  file_handle.close
                end
                message.add_file({:filename => attachment[:filename], :content => attachment[:content].to_s})
              end
            else
              gxg_message[:body].each do |part|
                unless part[:prologue] || part[:epilogue]
                  message.body = part[:content]
                  break
                end
              end
            end
            # Send it
            @client.append(mailbox, message.to_s, flags, timestamp)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox, :message => gxg_message, :flags => flags}})
          end
        end
        result
      end
      #
      def fetch_message(uid=nil)
        result = nil
        if @client
          begin
            unless self.mounted?
              raise Exception, "You MUST mount a Mailbox prior to calling this operation."
            end
            unless uid.is_a?(::Integer)
              raise ArgumentError, "You MUST provide an Integer to specify the Message UID Number."
            end
            parse_message = Proc.new do |the_raw_message|
              header = {}
              body = []
              attachments = []
              parser = ::Mail.new(the_raw_message)
              parser.header_fields.each do |field|
                the_key = field.name.to_s.to_sym
                the_data = field.to_s.transcode({:replace => "."},::Encoding::UTF_8)
                the_data.gsub!("         ","")
                the_data.gsub!("        ","")
                the_data.gsub!("   ","")
                the_data.gsub!("\r\n","")
                if header[(the_key)]
                  unless header[(the_key)].is_a?(::Array)
                    header[(the_key)] = [(header[(the_key)])]
                  end
                  header[(the_key)] << the_data
                else
                  header[(the_key)] = the_data
                end
              end
              if parser.multipart?
                link_db = []
                body << {:preamble => parser.body.preamble}
                parser.parts.each do |part|
                  if part.multipart?
                    link_db << part
                  else
                    if part.attachment?
                      attachments << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :filename => part.filename, :path => nil, :content => ::GxG::ByteArray.new(part.decoded)}
                    else
                      body << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :content => part.body.to_s.transcode({:replace => "."},::Encoding::UTF_8)}
                    end
                  end
                end
                while link_db.size > 0 do
                  part = link_db.shift
                  if part.multipart?
                    part.parts.each do |the_sub_part|
                      link_db << the_sub_part
                    end
                  else
                    if part.attachment?
                      attachments << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :filename => part.filename, :path => nil, :content => ::GxG::ByteArray.new(part.decoded)}
                    else
                      body << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :content => part.body.to_s.transcode({:replace => "."},::Encoding::UTF_8)}
                    end
                  end
                end
                body << {:epilogue => parser.body.epilogue}
              else
                body << {:preamble => parser.body.preamble.to_s.transcode({:replace => "."},::Encoding::UTF_8)}
                mime_type = "text/plain"
                parameters = {"charset" => "UTF-8"}
                body_text = parser.body.to_s.transcode({:replace => "."},::Encoding::UTF_8)
                if body_text.xml?
                  mime_type = "text/xml"
                end
                if body_text.html?
                  mime_type = "text/html"
                end
                body << {:content_type => {:type => mime_type, :parameters => parameters}, :content => body_text}
                body << {:epilogue => parser.body.epilogueto_s.transcode({:replace => "."},::Encoding::UTF_8)}
              end
              gxg_message = new_message
              gxg_message[:sender] = parser.from
              gxg_message[:id] = parser.message_id
              gxg_message[:to] = parser.to
              gxg_message[:cc] = parser.cc
              gxg_message[:bcc] = parser.bcc
              gxg_message[:subject] = parser.subject
              gxg_message[:date] = parser.date
              gxg_message[:header] = header
              gxg_message[:body] = body
              gxg_message[:attachments] = attachments
              gxg_message
            end
            #
            raw_response = @client.uid_fetch(uid,"BODY[]")
            if raw_response.is_a?(::Array)
              if raw_response.size > 0
                result = parse_message.call(raw_response[0].attr()["BODY[]"])
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:unique_id => uid}})
          end
        end
        result
      end
      #
      def set_message_attributes(uid=nil, attributes=nil, flags=nil)
        result = false
        if @client
          begin
            unless uid.is_any?(::Integer, ::Array)
              raise ArgumentError, "You MUST specify a UID to set an ATTRIBUTE."
            end
            unless attributes.is_a?(::String)
              raise ArgumentError, "You MUST specify what ATTRIBUTE to set."
            end
            unless flags.is_a?(::Array)
              raise ArgumentError, "You MUST specify what FLAGS to set/unset."
            end
            @client.uid_store(uid, attributes, flags)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid, :attributes => attributes, :flags => flags}})
          end
        end
        result
      end
      #
      def add_message_flags(uid=nil, flags=nil)
        result = false
        if @client
          begin
            unless uid.is_any?(::Integer, ::Array)
              raise ArgumentError, "You MUST specify a UID name to set FLAGS."
            end
            unless flags.is_a?(::Array)
              raise ArgumentError, "You MUST specify what FLAGS to set."
            end
            self.set_message_attributes(uid, "+FLAGS", flags)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid, :flags => flags}})
          end
        end
        result
      end
      #
      def remove_message_flags(uid=nil, flags=nil)
        result = false
        if @client
          begin
            unless uid.is_any?(::Integer, ::Array)
              raise ArgumentError, "You MUST specify a UID name to clear FLAGS."
            end
            unless flags.is_a?(::Array)
              raise ArgumentError, "You MUST specify what FLAGS to clear."
            end
            self.set_message_attributes(uid, "-FLAGS", flags)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid, :flags => flags}})
          end
        end
        result
      end
      #
      def remove_messages(uid=nil)
        result = false
        if @client
          begin
            unless uid.is_any?(::Integer, ::Array)
              raise ArgumentError, "You MUST specify a UID to remove."
            end
            self.add_message_flags(uid, [:Deleted])
            @client.expunge
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid}})
          end
        end
        result
      end
      #
      def copy_to_mailbox(uid=nil, mailbox=nil)
        result = false
        if @client
          begin
            unless uid.is_any?(::Integer, ::Array)
              raise ArgumentError, "You MUST specify a UID to copy the message."
            end
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX to copy the message to."
            end
            self.uid_copy(uid, mailbox)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid, :mailbox => mailbox}})
          end
        end
        result
      end
      #
      def move_to_mailbox(uid=nil, mailbox=nil)
        result = false
        if @client
          begin
            unless uid.is_any?(::Integer, ::Array)
              raise ArgumentError, "You MUST specify a UID to move the message."
            end
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX to move the message to."
            end
            self.uid_move(uid, mailbox)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid, :mailbox => mailbox}})
          end
        end
        result
      end
      #
      def fetch_manifest(uid_set=[])
        result = []
        if @client
          begin
            unless self.mounted?
              raise Exception, "You MUST mount a Mailbox prior to calling this operation."
            end
            if uid_set.is_a?(::Integer)
              uid_set = [(uid_set)]
            end
            unless uid_set.is_a?(::Array)
              raise ArgumentError, "You MUST provide an Array of Message UID Integers."
            end
            #
            parse_header = Proc.new do |the_raw_message|
              header = {}
              parser = ::Mail.new(the_raw_message)
              parser.header_fields.each do |field|
                the_key = field.name.to_s.to_sym
                the_data = field.to_s.transcode({:replace => "."},::Encoding::UTF_8)
                the_data.gsub!("         ","")
                the_data.gsub!("        ","")
                the_data.gsub!("   ","")
                the_data.gsub!("\r\n","")
                if header[(the_key)]
                  unless header[(the_key)].is_a?(::Array)
                    header[(the_key)] = [(header[(the_key)])]
                  end
                  header[(the_key)] << the_data
                else
                  header[(the_key)] = the_data
                end
              end
              header
            end
            #
            uid_set.each do |uid|
              record = {:uid => uid, :date => nil, :from => "", :to => "", :subject => ""}
              raw_response = @client.uid_fetch(uid,"BODY[HEADER]")
              if raw_response.is_a?(::Array)
                if raw_response.size > 0
                  header = parse_header.call(raw_response[0].attr()["BODY[HEADER]"])
                  record[:date] = ::DateTime.parse(header[:Date].to_s)
                  record[:from] = header[:From]
                  record[:to] = header[:To]
                  record[:subject] = header[:Subject]
                  result << record
                end
              end
              #
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:uid_set => uid_set}})
          end
        end
        result
      end
      #
      def uid_list(criteria=["NEW"])
        result = []
        if @client
          begin
            unless self.mounted?
              raise Exception, "You MUST mount a Mailbox prior to calling this operation."
            end
            unless criteria.is_a?(::Array)
              raise ArgumentError, "You MUST provide a search criteria in the form of an Array of Strings."
            end
            result = @client.uid_search(criteria)
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:criteria => criteria}})
          end
        end
        result
      end
      #
      def theaded_list(algorithm=nil,search_keys=nil, charset="UTF-8")
        result = []
        if @client
          begin
            unless self.mounted?
              raise Exception, "You MUST mount a Mailbox prior to calling this operation."
            end
            unless ["orderedsubject","references"].include?(algorithm.to_s.downcase)
              raise ArgumentError, "The algorithm you specified is invalid. Choose one of these: ['ORDEREDSUBJECT', 'REFERENCES']"
            end
            algorithm = algorithm.to_s.upcase
            unless search_keys.is_a?(::Array)
              raise ArgumentError, "You MUST provide search keys in the form of an Array of Strings."
            end
            unless charset
              raise ArgumentError, "You MUST provide a CHARSET specifier. Try one of these: ['US-ASCII', 'UTF-8']"
            end
            result = @client.uid_thread(algorithm, search_keys, charset)
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:algorithm => algorithm, :search_keys => search_keys, :charset => charset}})
          end
        end
        result
      end
      #
      def sort(sort_keys=["DATE"], search_keys=["ALL"], charset="UTF-8")
        result = []
        if @client
          begin
            unless self.mounted?
              raise Exception, "You MUST mount a Mailbox prior to calling this operation."
            end
            unless @mount_mode == :read_write
              raise Exception, "You need to re-mount #{@mounted.inspect} as :read_write to peform this operation."
            end
            result = @client.uid_sort(sort_keys, search_keys, charset)
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:sort_keys => sort_keys, :search_keys => search_keys, :charset => charset}})
          end
        end
        result
      end
      #
      def create_mailbox(mailbox=nil)
        result = []
        if @client
          begin
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX name to create it."
            end
            result = @client.create(mailbox)
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox}})
          end
        end
        result
      end
      #
      def remove_mailbox(mailbox=nil)
        result = []
        if @client
          begin
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX name to delete it."
            end
            result = @client.delete(mailbox)
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox}})
          end
        end
        result
      end
      #
      def rename_mailbox(mailbox=nil, new_name=nil)
        result = false
        if @client
          begin
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX name to rename it."
            end
            unless new_name
              raise ArgumentError, "You MUST specify a NEW_NAME name to rename the MAILBOX."
            end
            @client.rename(mailbox, new_name)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox, :new_name => new_name}})
          end
        end
        result
      end
      #
      def subscribe(mailbox=nil)
        result = false
        if @client
          begin
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX name to subscribe to."
            end
            @client.subscribe(mailbox)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox}})
          end
        end
        result
      end
      #
      def unsubscribe(mailbox=nil)
        result = false
        if @client
          begin
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX name to unsubscribe from."
            end
            @client.unsubscribe(mailbox)
            result = true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox}})
          end
        end
        result
      end
      #
      def list_subscriptions(reference=nil, mailbox=nil)
        result = []
        if @client
          begin
            raw_list = @client.lsub(reference, mailbox)
            if raw_list
              raw_list.each do |entry|
                if entry.is_a?(::Net::IMAP::MailboxList)
                  result << {:name => entry.name, :flags => entry.attr, :delimiter => entry.delim}
                end
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:reference => reference, :mailbox => mailbox}})
          end
        end
        result
      end
      #
      def get_quota(mailbox=nil)
        result = nil
        if @client
          begin
            unless mailbox
              raise ArgumentError, "You MUST specify a MAILBOX name."
            end
            raw_response = @client.getquotaroot(mailbox)[1]
            if raw_response.is_a?(::Net::IMAP::MailboxQuota)
              result = {:usage => raw_response.usage.to_i, :quota => raw_response.quota.to_i}
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:mailbox => mailbox}})
          end
        end
        result
      end
      #
    end
    #
    ::GxG::Networking::DISPATCHER.register_client("imap", ::GxG::Networking::ImapClient)
    ::GxG::Networking::DISPATCHER.register_client("imaps", ::GxG::Networking::ImapClient)
    # SMTP Classes:
    class SmtpClient
      # 
      def initialize(the_url=nil,options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI."
        end
        @user = the_url.user
        @password = the_url.password
        @client = nil
        @host = the_url.hostname
        if options[:use_ssl] == true  || the_url.scheme == "ssmtp"
          @port = (the_url.port || 465)
          if options[:ssl_method]
            # Valid: [:TLSv1, :TLSv1_server, :TLSv1_client, :TLSv1_1, :TLSv1_1_server, :TLSv1_1_client, :TLSv1_2, :TLSv1_2_server, :TLSv1_2_client, :SSLv23, :SSLv23_server, :SSLv23_client]
            unless OpenSSL::SSL::SSLContext::METHODS.include?(options[:ssl_method])
              raise ArgumentError, "Encryption method #{options[:ssl_method].inspect} is not valid. Choose one of these: #{OpenSSL::SSL::SSLContext::METHODS.inspect}"
            end
            openssl_context = OpenSSL::SSL::SSLContext.new(options[:ssl_method])
          else
            openssl_context = ::Net::SMTP.default_ssl_context
          end
          if options[:ignore_ssl_errors] == true
            openssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
          else
            openssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          end
        else
          @port = (the_url.port || 25)
          openssl_context = nil
        end
        @client = ::Net::SMTP.new(@host, @port)
        if openssl_context
          @client.enable_ssl(openssl_context)
        end
        #
        self
      end
      #
      def host()
        @host.clone
      end
      #
      def port()
        @port.clone
      end
      #
      def login(user_id=nil, password=nil, options={:authentication_method=> :plain})
        result = false
        if user_id.is_a?(::Hash)
          options = user_id
          user_id = nil
          password = nil
        end
        unless options.is_a?(::Hash)
          raise ArgumentError, "You MUST provide a options as a Hash"
        end
        authentication_method = (options[:authentication_method] || :plain)
        if @client
          begin
            unless user_id
              user_id = @user
              unless user_id
                raise ArgumentError, "You MUST provide a USER id, like this: <user_id>,<password/oauth-token>,(<options>)"
              end
            end
            unless password
              password = @password
              unless password
                raise ArgumentError, "You MUST provide a PASSWORD/OAUTH-TOKEN, like this: <user_id>,<password/oauth-token>,(<options>)"
              end
            end
            unless @client.started?
              unless [:plain, :login, :cram_md5, :oauth2].include?(authentication_method.to_s.to_sym)
                raise ArgumentError, "Authentication method #{authentication_method.inspect} is invalid. Choose one of these: [:plain, :login, :cram_md5, :oauth2]"
              end
              # Internal cosmetics for interface consistency.
              if authentication_method == :oauth2
                authentication_method = :xoauth2
              end
              @client.start(@host, user_id, password, authentication_method)
            end
            result = true
          rescue Exception => the_error
            # Internal cosmetics for interface consistency.
            if authentication_method == :xoauth2
              authentication_method = :oauth2
            end
            log_error({:error => the_error, :parameters => {:user => user_id, :authentication => authentication_method}})
          end
        end
        result
      end
      #
      def logout()
        if @client
          begin
            @client.finish
            @client = nil
            true
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {}})
            false
          end
        else
          false
        end
      end
      #
      def attachment_template(the_path="", content_parameters={"name" => ""})
        result = nil
        begin
          unless the_path.to_s.valid_path?
            raise ArgumentError, "You MUST provide a valid file system path to the file."
          end
          unless content_parameters.is_a?(::Hash)
            raise ArgumentError, "You MUST provide content_parameters as a Hash."
          end
          unless content_parameters["name"].to_s.size > 0
            content_parameters["name"] = ::File.basename(the_path)
          end
          discovered_mime = ::MimeMagic.by_magic(::File.open(the_path,"rb"))
          if discovered_mime
            discovered_mime = discovered_mime.type
          else
            discovered_mime = "application/octet-stream"
          end
          result = {:content_type => {:type => discovered_mime, :parameters => content_parameters}, :filename => (::File.basename(the_path)), :path => the_path, :content => ::GxG::ByteArray.new}
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:path => the_path, :content_parameters => content_parameters}})
        end
        result
      end
      #
      def message_template(mime_type="text/plain", content_parameters={"charset"=>"UTF-8"})
        result = nil
        begin
          unless ['text/plain', 'text/html', 'text/xhtml', 'text/xml'].include?(mime_type.to_s)
            raise ArgumentError, "Content Type specified was invalid. Choose one of these: ['text/plain', 'text/html', 'text/xhtml', 'text/xml']"
          end
          unless content_parameters.is_a?(::Hash)
            raise ArgumentError, "You MUST provide content_parameters as a Hash."
          end
          gxg_message = new_message
          gxg_message[:sender] = ""
          gxg_message[:id] = "<#{gxg_message[:id].to_s}@#{::Socket.gethostname}.mail>"
          gxg_message[:to] = ""
          gxg_message[:cc] = nil
          gxg_message[:bcc] = nil
          gxg_message[:subject] = ""
          gxg_message[:date] = ::DateTime.now
          gxg_message[:header] = {}
          gxg_message[:body] = [{:prologue => ""},{:content_type => {:type => mime_type.to_s, :parameters => content_parameters}, :content => ""},{:epilogue => ""}]
          gxg_message[:attachments] = []
          result = gxg_message
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:content_type => mime_type, :content_parameters => content_parameters}})
        end
        result
      end
      #
      def send_message(gxg_message=nil)
        result = false
        if @client
          begin
            unless @client.started?
              raise Exception, "SMTP session not started yet."
            end
            unless gxg_message.is_a?(::GxG::Events::Message)
              raise ArgumentError, "You MUST provide a valid message object of class ::GxG::Events::Message. Suggested: <SmtpClient>.message_template(<Mime-Type-String>)"
            end
            # Build suitable mail message
            message = Mail.new
            the_fields = []
            gxg_message[:header].each_pair do |the_key, the_value|
              if the_value.is_a?(::Array)
                the_value.each do |the_field_value|
                  the_fields << "#{the_key.to_s}: #{the_field_value.to_s}"
                end
              else
                the_fields << "#{the_key.to_s}: #{the_value.to_s}"
              end
            end
            message.header = the_fields.join("\r\n")
            message.from = gxg_message[:sender]
            message.reply_to = gxg_message[:sender]
            if gxg_message[:id].to_s.include?("@")
              message.message_id = gxg_message[:id].to_s
            else
              message.message_id = "<#{gxg_message[:id].to_s}@#{::Socket.gethostname}.mail>"
            end
            message.to = gxg_message[:to]
            if gxg_message[:cc]
              message.cc = gxg_message[:cc]
            end
            if gxg_message[:bcc]
              message.bcc = gxg_message[:bcc]
            end
            message.subject = gxg_message[:subject]
            message.date = (gxg_message[:date].to_s || ::DateTime.now.to_s)
            if gxg_message[:attachments].size > 0
              multipart = true
            else
              part_count = 0
              gxg_message[:body].each do |part|
                unless part[:prologue] || part[:epilogue]
                  part_count += 1
                end
              end
              if part_count > 1
                multipart = true
              else
                multipart = false
              end
            end
            if multipart
              gxg_message[:body].each do |part|
                unless part[:prologue] || part[:epilogue]
                  type_info = "Content-Type: #{part[:content_type][:type]}"
                  if part[:content_type][:parameters].keys.size > 0
                    part[:content_type][:parameters].each_pair do |the_key, the_value|
                      type_info << "; '#{the_key.to_s}': '#{the_value.to_s}'"
                    end
                  end
                  new_part = Mail::Part.new(type_info)
                  new_part.body = part[:content]
                  message.add_part(new_part)
                end
              end
              # Add file attachments:
              gxg_message[:attachments].each do |attachment|
                if attachment[:content].size == 0
                  file_size = ::File.size(attachment[:path])
                  file_handle = ::File.open(attachment[:path],"rb")
                  ::GxG::apportioned_ranges(file_size,65536).each do |the_range|
                    file_handle.seek(the_range.first)
                    attachment[:content] << file_handle.read(the_range.size)
                  end
                  file_handle.close
                end
                message.add_file({:filename => attachment[:filename], :content => attachment[:content].to_s})
              end
            else
              gxg_message[:body].each do |part|
                unless part[:prologue] || part[:epilogue]
                  message.body = part[:content]
                  break
                end
              end
            end
            # Send it
            @client.send_message(message.to_s, gxg_message[:sender], message.destinations) 
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:message => gxg_message}})
          end
        end
        result
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("smtp", ::GxG::Networking::SmtpClient)
    ::GxG::Networking::DISPATCHER.register_client("ssmtp", ::GxG::Networking::SmtpClient)
    # POP3 Classes:
    class Pop3Client
      #
      def initialize(the_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI."
        end
        @user = the_url.user
        @password = the_url.password
        @client = nil
        @host = the_url.hostname
        if options[:use_ssl] == true || the_url.scheme.to_s == "pop3s"
          @port = (port || 995)
        else
          @port = (port || 110)
        end
        @client = ::Net::POP3.new(@host, @port, (options[:use_apop] || false))
        if options[:use_ssl] == true
          if options[:ignore_ssl_errors] == true
            @client.enable_ssl(OpenSSL::SSL::VERIFY_NONE)
          else
            @client.enable_ssl(OpenSSL::SSL::VERIFY_PEER)
          end
        end
        #
        self
      end
      #
      def login(user_id=nil,password=nil,options={})
        if @client
          unless user_id
            user_id = @user
          end
          unless password
            password = @password
          end
          unless password
            raise ArgumentError, "You MUST provide a PASSWORD, like this: <user_id>,<password>,(<options>)"
          end
          @client.start(user_id, password)
          true
        else
          false
        end
        #
      end
      #
      def logout()
        if @client
          @client.finish
          @client = nil
          true
        end
      end
      #
      def message_count()
        # Return the number of emails on the server.
        if @client
          @client.n_mails()
        else
          0
        end
      end
      #
      def retrieve_messages(options={:read_only=>false},&block)
        result = []
        begin
          if @client
            if @client.started?
              if @client.active?
                parse_message = Proc.new do |the_raw_message|
                  header = {}
                  body = []
                  attachments = []
                  parser = ::Mail.new(the_raw_message.pop)
                  parser.header_fields.each do |field|
                    the_key = field.name.to_s.to_sym
                    the_data = field.to_s.transcode({:replace => "."},::Encoding::UTF_8)
                    the_data.gsub!("         ","")
                    the_data.gsub!("        ","")
                    the_data.gsub!("   ","")
                    the_data.gsub!("\r\n","")
                    if header[(the_key)]
                      unless header[(the_key)].is_a?(::Array)
                        header[(the_key)] = [(header[(the_key)])]
                      end
                      header[(the_key)] << the_data
                    else
                      header[(the_key)] = the_data
                    end
                  end
                  if parser.multipart?
                    link_db = []
                    body << {:preamble => parser.body.preamble}
                    parser.parts.each do |part|
                      if part.multipart?
                        link_db << part
                      else
                        if part.attachment?
                          attachments << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :filename => part.filename, :path => nil, :content => ::GxG::ByteArray.new(part.decoded)}
                        else
                          body << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :content => part.body.to_s.transcode({:replace => "."},::Encoding::UTF_8)}
                        end
                      end
                    end
                    while link_db.size > 0 do
                      part = link_db.shift
                      if part.multipart?
                        part.parts.each do |the_sub_part|
                          link_db << the_sub_part
                        end
                      else
                        if part.attachment?
                          attachments << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :filename => part.filename, :path => nil, :content => ::GxG::ByteArray.new(part.decoded)}
                        else
                          body << {:content_type => {:type => part.mime_type, :parameters => part.content_type_parameters}, :content => part.body.to_s.transcode({:replace => "."},::Encoding::UTF_8)}
                        end
                      end
                    end
                    body << {:epilogue => parser.body.epilogue}
                  else
                    body << {:preamble => parser.body.preamble.to_s.transcode({:replace => "."},::Encoding::UTF_8)}
                    mime_type = "text/plain"
                    parameters = {"charset" => "UTF-8"}
                    body_text = parser.body.to_s.transcode({:replace => "."},::Encoding::UTF_8)
                    if body_text.xml?
                      mime_type = "text/xml"
                    end
                    if body_text.html?
                      mime_type = "text/html"
                    end
                    body << {:content_type => {:type => mime_type, :parameters => parameters}, :content => body_text}
                    body << {:epilogue => parser.body.epilogueto_s.transcode({:replace => "."},::Encoding::UTF_8)}
                  end
                  gxg_message = new_message
                  gxg_message[:sender] = parser.from
                  gxg_message[:id] = parser.message_id
                  gxg_message[:to] = parser.to
                  gxg_message[:cc] = parser.cc
                  gxg_message[:bcc] = parser.bcc
                  gxg_message[:subject] = parser.subject
                  gxg_message[:date] = parser.date
                  gxg_message[:header] = header
                  gxg_message[:body] = body
                  gxg_message[:attachments] = attachments
                  gxg_message
                end
                @client.each_mail do |raw_message|
                  if block.respond_to?(:call)
                    block.call(parse_message.call(raw_message))
                  else
                    result << parse_message.call(raw_message)
                  end
                  unless options[:read_only] == true
                    raw_message.delete
                  end
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("pop3", ::GxG::Networking::Pop3Client)
    ::GxG::Networking::DISPATCHER.register_client("pop3s", ::GxG::Networking::Pop3Client)
    # REST Classes:
    class RestClient
      #
      def self.set_system_proxy(the_url=nil)
        result = false
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid proxy URI."
          end
          ::RestClient.proxy = the_url.to_s
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url}})
        end
        result
      end
      #
      def self.clear_system_proxy()
        result = false
        begin
          ::RestClient.proxy = nil
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def intitialize(the_url=nil, options={})
        # REST Servers to test with:
        # http://services.groupkt.com/country/get/all
        # http://services.groupkt.com/state/get/{countryCode}/all
        # https://httpbin.org/get
        #
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI."
        end
        @url = the_url.clone
        if options[:query].is_a?(::Hash)
          @url.query = ::URI.encode_www_form(options[:query])
        end
        unless options[:follow_redirects] == false
          options.merge({:follow_redirects => true})
        end
        #
        if @url.scheme.downcase == "https"
          options[:use_ssl] = true
        end
        if the_url.user.to_s.size > 0
          @authenticated = true
          @user = the_url.user
          @password = the_url.password
        else
          @authenticated = false
          @user = nil
          @password = nil
        end
        @pem_option = nil
        if options[:pem_source].is_any?(::File, ::GxG::Database::PersistedArray)
          pem_data = nil
          if options[:pem_source].is_a?(::File)
            options[:pem_source].rewind
            pem_data = options[:pem_source].read()
          else
            buffer = ::GxG::ByteArray.new
            options[:pem_source].each_index do |segment|
              buffer << options[:pem_source][(segment)].to_s
              options[:pem_source].unload(segment)
            end
            pem_data = buffer.to_s
          end
          if pem_data
            @pem_option = {:ssl_client_cert => OpenSSL::X509::Certificate.new(pem_data), :ssl_client_key => OpenSSL::PKey::RSA.new(pem_data, options[:pem_password]), :verify_ssl => OpenSSL::SSL::VERIFY_PEER}
          end
        end
        @proxy_option = nil
        if options[:proxy].is_a?(::URI::Generic)
          @proxy_option = options[:proxy]
        end
        # Review : update initialization parameters to track client changes.
        # ????
        if the_url.scheme.downcase.to_s == "https"
          @client = ::GxG::Networking::HttpsClient.new
        else
          @client = ::GxG::Networking::HttpClient.new
        end
        @host = the_url.hostname
        #
        @cookies = nil
        self
      end
      #
      def clear_cache()
        @cookies = nil
        true
      end
      #
      def get(the_url=nil, options={}, &block)
        result = nil
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI."
          end
          if options.is_a?(::Hash)
            options = @options.merge(options)
          else
            options = @options
          end
          header_options = (options[:header_options] || {}).merge({:accept => :json})
          if @cookies
            unless header_options[:cookies]
              header_options[:cookies] = @cookies
            end
          end
          if @pem_option
            header_options = header_options.merge(@pem_option)
          end
          if @proxy_option
            header_options[:proxy] = @proxy_option
          end
          if options[:save_to].is_a?(::File, ::GxG::Database::PersistedArray)
            client = ::GxG::Networking::HttpClient.new(the_url, options)
            response = client.get(the_url, {:save_to => options[:save_to], :proxy => options[:proxy]})
            if response == true
              result = options[:save_to]
              if block.respond_to?(:call)
                block.call(result)
              end
            end
          else
            if options[:parameters].is_a?(::Hash)
              response = ::RestClient.get(the_url.to_s, header_options.merge({:params => options[:parameters]}), &block)
            else
              response = ::RestClient.get(the_url.to_s, header_options, &block)
            end
            #
            unless @cookies
              if response.cookies.is_a?(::Hash)
                if response.cookies.keys.size > 0
                  @cookies = response.cookies
                end
              end
            end
            result = response
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def put(the_url=nil, data=nil, options={}, &block)
        result = false
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI."
          end
          unless data.is_a?(::Hash)
            raise Exception, "You MUST provide data to PUT to the server (in the form of a Hash)."
          end
          if options.is_a?(::Hash)
            options = @options.merge(options)
          else
            options = @options
          end
          if @cookies
            unless header_options[:cookies]
              header_options[:cookies] = @cookies
            end
          end
          if @pem_option
            header_options = header_options.merge(@pem_option)
          end
          if @proxy_option
            header_options[:proxy] = @proxy_option
          end
          header_options = (options[:header_options] || {}).merge({:accept => :json})
          if options[:to_json]
            data = data.to_json()
            header_options[:content_type] = :json
          else
            # Review : completely redo file uploads with PUT ????
            # BufferedSegments
            if options[:upload_file].is_any?(::File, ::GxG::Database::PersistedArray)
              if options[:upload_file].is_a?(::GxG::Database::PersistedArray)
                the_upload = ::GxG::Storage::BufferedSegments.new(options[:upload_file])
              else
                the_upload = options[:upload_file]
              end
              data[(::GxG::uuid_generate().to_sym)] = the_upload
            else
              data.each_pair do |the_key, the_value|
                if the_value.is_a?(::GxG::Database::PersistedArray)
                  data[(the_key)] = ::GxG::Storage::BufferedSegments.new(the_value)
                end
              end
            end
          end
          result = ::RestClient.put(the_url.to_s, data, header_options, &block)
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def post(the_url=nil, form_data=nil, options={}, &block)
        result = false
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI."
          end
          unless form_data.is_a?(::Hash)
            raise Exception, "You MUST provide valid form data (in the form of a Hash)."
          end
          unless options.is_a?(::Hash)
            options = {}
          end
          header_options = (options[:header_options] || {}).merge({:accept => :json})
          if @cookies
            unless header_options[:cookies]
              header_options[:cookies] = @cookies
            end
          end
          if @pem_option
            header_options = header_options.merge(@pem_option)
          end
          if @proxy_option
            header_options[:proxy] = @proxy_option
          end
          if options[:upload_file].is_any?(::File, ::GxG::Database::PersistedArray)
            if the_value.is_a?(::GxG::Database::PersistedArray)
              the_upload = ::GxG::Storage::BufferedSegments.new(the_value)
            else
              the_upload = options[:upload_file]
            end
            form_data[:file] = the_upload
            form_data[:multipart] = true
          else
            form_data.each_pair do |the_key, the_value|
              if the_value.is_a?(::GxG::Database::PersistedArray)
                form_data[(the_key)] = ::GxG::Storage::BufferedSegments.new(the_value)
              end
            end
          end
          result = ::RestClient.post(the_url.to_s, form_data, header_options, &block)
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def delete(the_url=nil, options={}, &block)
        result = false
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI."
          end
          unless options.is_a?(::Hash)
            options = {}
          end
          header_options = (options[:header_options] || {}).merge({:accept => :json})
          if @cookies
            unless header_options[:cookies]
              header_options[:cookies] = @cookies
            end
          end
          if @pem_option
            header_options = header_options.merge(@pem_option)
          end
          if @proxy_option
            header_options[:proxy] = @proxy_option
          end
          result = ::RestClient.delete(the_url.to_s, header_options, &block)
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("rest-https", ::GxG::Networking::RestClient)
    ::GxG::Networking::DISPATCHER.register_client("rest-http", ::GxG::Networking::RestClient)
    # SOAP Classes:
    class SoapDriver < ::Handsoap::Service
      # Example sites to test with:
      # http://www.restfulwebservices.net/rest/WeatherForecastService.svc?wsdl
      # http://www.restfulwebservices.net/wcf/WeatherForecastService.svc?wsdl
      # https://graphical.weather.gov/xml/DWMLgen/wsdl/ndfdXML.wsdl
      # http://www.webservicex.com/CurrencyConvertor.asmx?wsdl
      #
      def initialize(the_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI."
        end
        super()
        @user = nil
        @password = nil
        @interface = []
        @tns_url = nil
        ::Handsoap::http_driver = :net_http
        ::Handsoap::xml_query_driver = :rexml
        if the_url.query.to_s.downcase.include?("wsdl") || (the_url.path.to_s.downcase.include?("wsdl"))
          point = (the_url.scheme.to_s + "://")
          if the_url.user
            point << the_url.user
            @user = the_url.user
          end
          if the_url.password
            point << (":" << the_url.password)
            @password = the_url.password
          end
          if the_url.hostname
            if the_url.user
              point << ("@" << the_url.hostname)
            else
              point << the_url.hostname
            end
          end
          if the_url.path
            point << the_url.path
          end
          # Process WSDL, determine actual version number from that.
          http_tool = ::GxG::Networking::HttpClient.new(the_url, options)
          response = http_tool.get(the_url)
          if response
            wsdl_data = response.body.transcode({:replace => "."},::Encoding::UTF_8)
            if wsdl_data.include?("http://schemas.xmlsoap.org/soap/envelope/")
              wsdl_version = 1
            else
              wsdl_version = 2
            end
            ::GxG::Networking::SoapDriver::endpoint({:uri => (point), :version => (wsdl_version)})
            # Build Interface Data:
            document = ::Oga.parse_xml(wsdl_data)
            nodes = document.css("definitions")
            nodes.each do |node|
              next unless node.is_a?(Oga::XML::Element)
              node.attributes.each do |attribute|
                if ["tns", "targetNamespace"].include?(attribute.name)
                  @tns_url = attribute.value
                  break
                end
              end
              if @tns_url
                break
              end
            end
            unless @tns_url
              raise Exception, "Failed to load namespace (required)."
            end
            nodes = document.css("portType")
            base_names = []
            nodes.each do |node|
              next unless node.is_a?(::Oga::XML::Element)
              node.children.each do |the_operation|
                next unless the_operation.is_a?(::Oga::XML::Element)
                basename = nil
                the_operation.attributes.each do |attribute|
                  if attribute.name == "name"
                    basename = attribute.value
                    break
                  end
                end
                if basename
                  record = {:base => (basename), :message => (("tns:" << basename).to_sym), :input => nil, :output => nil}
                  the_operation.children.each do |the_io|
                    next unless the_io.is_a?(::Oga::XML::Element)
                    if ["input", "output"].include?(the_io.name)
                      the_io.attributes.each do |the_message|
                        if the_message.name == "message"
                          record[(the_io.name.to_sym)] = the_message.value
                        end
                      end
                    end
                  end
                  if record[:input] || record[:output]
                    base_names << record
                  end
                end
              end
            end
            messages = document.css("message")
            base_names.each do |the_method|
              record = {:method => (the_method[:message]), :input => nil, :output => nil}
              messages.each do |the_message|
                next unless the_message.is_a?(::Oga::XML::Element)
                the_message.attributes.each do |the_attribute|
                  direction_key = nil
                  if the_method[:input].gsub(/^.+:/, "") == the_attribute.value
                    direction_key = :input
                  end
                  if the_method[:output].gsub(/^.+:/, "") == the_attribute.value
                    direction_key = :output
                  end
                  if direction_key
                    parameters = {}
                    the_message.children.each do |the_part|
                      next unless the_part.is_a?(::Oga::XML::Element)
                      if the_part.name == "part"
                        the_name = nil
                        the_type = nil
                        the_part.attributes.each do |the_parameter|
                          if the_parameter.name == "name"
                            the_name = the_parameter.value
                          end
                          if the_parameter.name == "type"
                            the_type = the_parameter.value
                          end
                          if the_parameter.name == "element"
                            the_type = the_parameter.value
                          end
                          if (the_name && the_type)
                            parameters[(the_name.to_sym)] = the_type
                            the_name = nil
                            the_type = nil
                          end
                        end
                      end
                    end
                    if parameters.keys.size > 0
                      record[(direction_key)] = parameters
                    end
                  end
                end
              end
              if record[:input] || record[:output]
                @interface << record
              end
            end
            #
          else
            raise Exception, "Failed to retrieve WSDL data."
          end
        else
          raise ArgumentError, "No WSDL endpoint detected (required)."
        end
        #
        self
      end
      # Handsoap support hooks:
      def on_create_document(the_document=nil)
        if @tns_url
          the_document.alias('tns', @tns_url)
        end
      end
      #
      def on_before_dispatch(the_document=nil)
        #
      end
      #
      def on_response_document(the_document=nil)
        if @tns_url
          the_document.add_namespace('ns', @tns_url)
        end
      end
      #
      def interface()
        @interface
      end
      #
    end
    #
    class SoapClient
      # Standard:
      def initialize(the_url=nil, options={})
        @client = ::GxG::Networking::SoapDriver.new(the_url, options)
        self
      end
      #
      def login(the_url=nil, options={})
        result = false
        begin
          # Review - investigate how to do basic-auth or other method on a SOAP server.
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def logout()
        @client = nil
        true
      end
      #
      def closed?()
        if @client
          false
        else
          true
        end
      end
      #
      def callmethod(*args)
        result = nil
        begin
          if args.size == 1
            the_method = args[0].to_s
            arguments = {}
          else
            if args.size > 1
              the_method = args[0].to_s
              unless args[1].is_any?(::Hash, ::Array)
                raise ArgumentError, "You MUST provide a Hash or Array to specify parameters for this method."
              end
              arguments = args[1]
            else
              raise ArgumentError, "You MUST provide a valid SOAP method."
            end
          end
          if @client
            response_tag = (the_method.gsub(/^.+:/, "") + "Response")
            response = @client.invoke(the_method) do |message|
              if arguments.is_a?(::Hash)
                arguments.each_pair do |the_key, the_value|
                  message.add(the_key.to_s, the_value)
                end
              end
              if arguments.is_a?(::Array)
                arguments.each do |the_value|
                  message.add("literal", the_value)
                end
              end
            end
            data = ::Oga::parse_xml(response.to_xml).css(response_tag)
            if data
              found_numbers = data.text.numeric_values
              found_value = []
              if found_numbers.is_a?(::Array)
                found_numbers.each do |the_subarray|
                  if the_subarray.is_a?(::Array)
                    if the_subarray[0].is_a?(::Hash)
                      the_key = the_subarray[0].keys[0]
                      found_value << the_subarray[0][(the_key)]
                    end
                  end
                end
              end
              result = {}
              result[(response_tag.to_sym)] = data.text
              #              if found_value.size > 0
              #                if found_value.size == 1
              #                  result[(response_tag.to_sym)] = found_value[0]
              #                else
              #                  result[(response_tag.to_sym)] = found_value
              #                end
              #              else
              #                result[(response_tag.to_sym)] = data.text
              #              end
            else
              raise Exception, "Failed to interpret response data. Data: #{data.inspect}"
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:method => the_method, :arguments => arguments}})
        end
        result
      end
      #
      def interface()
        if @client
          @client.interface
        end
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("soap-https", ::GxG::Networking::SoapClient)
    ::GxG::Networking::DISPATCHER.register_client("soap-http", ::GxG::Networking::SoapClient)
    # XMLRPC Classes:
    class XmlrpcClient
      #
      def initialize(the_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI."
        end
        if options[:use_ssl] == true || the_url.scheme.to_s.downcase == 'https'
          client_parameters = [(the_url.hostname), (the_url.path), (the_url.port || 443)]
        else
          client_parameters = [(the_url.hostname), (the_url.path), (the_url.port || 80)]
        end
        if options[:proxy].is_a?(::URI::Generic)
          client_parameters << options[:proxy].host
          client_parameters << options[:proxy].port
        else
          client_parameters << nil
          client_parameters << nil
        end
        if the_url.user && the_url.password
          client_parameters << the_url.user
          client_parameters << the_url.password
        else
          client_parameters << nil
          client_parameters << nil
        end
        if options[:use_ssl] == true || the_url.scheme.to_s.downcase == 'https'
          client_parameters << true
        else
          client_parameters << nil
        end
        if options[:timeout].is_a?(::Numeric)
          client_parameters << options[:timeout].to_i
        else
          client_parameters << 30
        end
        @client = ::XMLRPC::Client.new(*client_parameters)
        @interface = nil
        self.interface()
        self
      end
      #
      def login(the_url=nil, options={})
        result = false
        begin
          # Review - research how/when;/if you do basic-auth or other method of authentication for XML-RPC.
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url}})
        end
        result
      end
      #
      def logout()
        @client = nil
        true
      end
      #
      def closed?()
        if @client
          false
        else
          true
        end
      end
      #
      def callmethod(the_method = nil, arguments = nil)
        # The +method+ parameter is converted into a String and should
        # be a valid XML-RPC method-name.
        #
        # Each parameter of +args+ must be of one of the following types,
        # where Hash, Struct and Array can contain any of these listed _types_:
        #
        # * Fixnum, Bignum
        # * TrueClass, FalseClass, +true+, +false+
        # * String, Symbol
        # * Float
        # * Hash, Struct
        # * Array
        # * Date, Time, XMLRPC::DateTime
        # * XMLRPC::Base64
        # * A Ruby object which class includes XMLRPC::Marshallable
        #   (only if Config::ENABLE_MARSHALLABLE is +true+).
        #   That object is converted into a hash, with one additional key/value
        #   pair <code>___class___</code> which contains the class name
        #   for restoring that object later.
        result = nil
        begin
          unless the_method.is_a?(::String)
            raise ArgumentError, "You MUST provide a valid method String."
          end
          if @client
            calldata = []
            calldata << the_method
            #
            # TODO: scour arguments structure for type conversions to be done.
            if arguments.is_a?(::Array)
              arguments.each do |entry|
                calldata << entry
              end
            else
              if arguments
                calldata << arguments
              end
            end
            result = @client.call(*calldata)
            # TODO: scour result structure for type conversions to gxg standard.
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:method => the_method, :arguments => arguments}})
        end
        result
      end
      #
      def interface()
        begin
          if @client
            unless @interface
              @interface = @client.call("interface")
            end
            unless @interface
              @interface = @client.call("Interface")
            end
          end
        rescue Exception => the_error
          # log_error({:error => the_error, :parameters => {}})
        end
        @interface
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("xmlrpc-https", ::GxG::Networking::XmlrpcClient)
    ::GxG::Networking::DISPATCHER.register_client("xmlrpc-http", ::GxG::Networking::XmlrpcClient)
    # ### SSH Client
    class SshClient
      def initialize(he_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI"
        end
        if the_url.password
          options[:password] = the_url.password
        end
        @client = ::Net::SSH.start(the_url.hostname, the_url.user, options)
        self
      end
      #
      def login(the_url=nil, options={})
        result = false
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI"
          end
          if the_url.password
            options[:password] = the_url.password
          end
          @client = ::Net::SSH.start(the_url.hostname, the_url.user, options)
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def send_command(the_command=nil)
        result = nil
        begin
          if @client
            unless the_command.is_a?(::String)
              raise ArgumentError, "You MUST provide a command as a String."
            end
            result = @client.exec!(the_command)
          end
          #
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:command => the_command}})
        end
        result
      end
      #
      def channel_operations(&block)
        result = nil
        begin
          if @client
            unless block.respond_to?(:call)
              raise ArgumentError, "You MUST provide a valid Block/Proc to execute."
            end
            result = @client.open_channel(&block)
          end
          #
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:block => block}})
        end
        result
      end
      #
      def logout()
        result = false
        begin
          if @client
            @client.exec!("exit")
            @client = nil
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def closed?()
        if @client
          false
        else
          true
        end
      end
      #
      def async_upload(the_local_source=nil, the_destination=nil, options={}, &progress_block)
        result = false
        begin
          if @client
            unless the_local_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            if progress_block.respond_to?(:call)
              channel = @client.scp.upload(the_local_source, the_destination, options, &progress_block)
            else
              channel = @client.scp.upload(the_local_source, the_destination, options)
            end
            channel.wait
            # True result means the request was sent, not that it completed.
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:local_path => the_local_source, :remote_path => the_destination, :options => options}})
        end
        result
      end
      #
      def upload(the_local_source=nil, the_destination=nil, options={}, &progress_block)
        # options:
        #:recursive - the local parameter refers to a local directory, which should be uploaded to a new directory named remote
        # on the remote server.
        #
        #:preserve - the atime and mtime of the file should be preserved.
        #
        #:verbose - the process should result in verbose output on the server end (useful for debugging).
        #
        #:chunk_size - the size of each "chunk" that should be sent. Defaults to 2048. Changing this value may
        # improve throughput at the expense of decreasing interactivity.
        result = false
        begin
          if @client
            unless the_local_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            if progress_block.respond_to?(:call)
              result = @client.scp.upload!(the_local_source, the_destination, options, &progress_block)
            else
              result = @client.scp.upload!(the_local_source, the_destination, options)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:local_path => the_local_source, :remote_path => the_destination, :options => options}})
        end
        result
      end
      #
      def async_download(the_remote_source=nil, the_destination=nil, options={}, &progress_block)
        result = false
        begin
          if @client
            unless the_remote_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            if progress_block.respond_to?(:call)
              channel = @client.scp.download(the_remote_source, the_destination, options, &progress_block)
            else
              channel = @client.scp.download(the_remote_source, the_destination, options)
            end
            channel.wait
            # True result means the request was sent, not that it completed.
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:remote_path => the_remote_source, :local_path => the_destination, :options => options}})
        end
        result
      end
      #
      def download(the_remote_source=nil, the_destination=nil, options={}, &progress_block)
        # options:
        #:recursive - the local parameter refers to a local directory, which should be uploaded to a new directory named remote
        # on the remote server.
        #
        #:preserve - the atime and mtime of the file should be preserved.
        #
        #:verbose - the process should result in verbose output on the server end (useful for debugging).
        #
        result = false
        begin
          if @client
            unless the_remote_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path (or file name) as a String."
            end
            if progress_block.respond_to?(:call)
              result = @client.scp.download!(the_remote_source, the_destination, options, &progress_block)
            else
              result = @client.scp.download!(the_remote_source, the_destination, options)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:remote_path => the_remote_source, :local_path => the_destination, :options => options}})
        end
        result
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("ssh", ::GxG::Networking::SshClient)
    #
    class SftpClient
      # Review : make BufferedSegments compatible
      def initialize(the_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI"
        end
        @user = the_url.user
        if the_url.password
          options[:password] = the_url.password
        end
        if the_url.port
          options[:port] = the_url.port
        end
        @client = ::Net::SFTP.start(the_url.hostname, the_url.user, options)
        @client.connect!
        if @client.closed?
          @client = nil
          raise Exception, "Failed to open a connection."
        end
        self
      end
      #
      def login(the_url=nil, options={})
        result = false
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI"
          end
          @user = the_url.user
          if the_url.password
            options[:password] = the_url.password
          end
          if the_url.port
            options[:port] = the_url.port
          end
          @client = ::Net::SFTP.start(the_url.hostname, the_url.user, options)
          @client.connect!
          if @client.closed?
            @client = nil
            raise Exception, "Failed to open a connection."
          else
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def closed?()
        if @client
          @client.closed?
        else
          true
        end
      end
      #
      def logout()
        if @client
          @client.close_channel
          @client = nil
          true
        end
      end
      #
      def async_upload(the_local_source=nil, the_destination=nil, options={}, &progress_block)
        # options:
        #:progress - either a block or an object to act as a progress callback. See the discussion of "progress monitoring"
        # below.
        #
        #:requests - the number of pending SFTP requests to allow at any given time. When uploading an entire directory
        # tree recursively, this will default to 16, otherwise it will default to 2. Setting this higher might improve
        # throughput. Reducing it will reduce throughput.
        #
        #:read_size - the maximum number of bytes to read at a time from the source. Increasing this value might
        # improve throughput. It defaults to 32,000 bytes.
        #
        #:name - the filename to report to the progress monitor when an IO object is given as local. This defaults
        # to "<memory>".
        result = false
        begin
          if @client
            unless the_local_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            unless options[:name]
              options[:name] = File.basename(the_local_source)
            end
            if progress_block.respond_to?(:call)
              channel = @client.upload(the_local_source, the_destination, options, &progress_block)
            else
              channel = @client.upload(the_local_source, the_destination, options)
            end
            channel.wait
            # True result means the request was sent, not that it completed.
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:local_path => the_local_source, :remote_path => the_destination, :options => options}})
        end
        result
      end
      #
      def upload(the_local_source=nil, the_destination=nil, options={}, &progress_block)
        # options:
        #:progress - either a block or an object to act as a progress callback. See the discussion of "progress monitoring"
        # below.
        #
        #:requests - the number of pending SFTP requests to allow at any given time. When uploading an entire directory
        # tree recursively, this will default to 16, otherwise it will default to 2. Setting this higher might improve
        # throughput. Reducing it will reduce throughput.
        #
        #:read_size - the maximum number of bytes to read at a time from the source. Increasing this value might
        # improve throughput. It defaults to 32,000 bytes.
        #
        #:name - the filename to report to the progress monitor when an IO object is given as local. This defaults
        # to "<memory>".
        result = false
        begin
          if @client
            unless the_local_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            unless options[:name]
              options[:name] = File.basename(the_local_source)
            end
            if progress_block.respond_to?(:call)
              result = @client.upload!(the_local_source, the_destination, options, &progress_block)
            else
              result = @client.upload!(the_local_source, the_destination, options)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:local_path => the_local_source, :remote_path => the_destination, :options => options}})
        end
        result
      end
      #
      def async_download(the_remote_source=nil, the_destination=nil, options={}, &progress_block)
        # progress - either a block or an object to act as a progress callback. See the discussion of "progress monitoring"
        # at http://net-ssh.github.io/net-sftp/classes/Net/SFTP/Operations/Download.html.
        #
        # :requests - the number of pending SFTP requests to allow at any given time. When downloading an
        #  entire directory tree recursively, this will default to 16. Setting this higher might improve throughput.
        #  Reducing it will reduce throughput.
        #
        # :read_size - the maximum number of bytes to read at a time from the source. Increasing this value might
        # improve throughput. It defaults to 32,000 bytes.
        #
        result = false
        begin
          if @client
            unless the_remote_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            if progress_block.respond_to?(:call)
              channel = @client.download(the_remote_source, the_destination, options, &progress_block)
            else
              channel = @client.download(the_remote_source, the_destination, options)
            end
            channel.wait
            # True result means the request was sent, not that it completed.
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:remote_path => the_remote_source, :local_path => the_destination, :options => options}})
        end
        result
      end
      #
      def download(the_remote_source=nil, the_destination=nil, options={}, &progress_block)
        # progress - either a block or an object to act as a progress callback. See the discussion of "progress monitoring"
        # at http://net-ssh.github.io/net-sftp/classes/Net/SFTP/Operations/Download.html.
        #
        # :requests - the number of pending SFTP requests to allow at any given time. When downloading an
        #  entire directory tree recursively, this will default to 16. Setting this higher might improve throughput.
        #  Reducing it will reduce throughput.
        #
        # :read_size - the maximum number of bytes to read at a time from the source. Increasing this value might
        # improve throughput. It defaults to 32,000 bytes.
        #
        result = false
        begin
          if @client
            unless the_remote_source.is_a?(::String)
              raise ArgumentError, "You MUST provide a remote path as a String."
            end
            unless the_destination.is_a?(::String)
              raise ArgumentError, "You MUST provide a local path (or file name) as a String."
            end
            if progress_block.respond_to?(:call)
              result = @client.download!(the_remote_source, the_destination, options, &progress_block)
            else
              result = @client.download!(the_remote_source, the_destination, options)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:remote_path => the_remote_source, :local_path => the_destination, :options => options}})
        end
        result
      end
      # Remote File System Operations and Objects
      def entries(the_path=nil, pattern=nil, flags=0, &block)
        # List entries in a given remote path.
        # If block is provided, resultant list is iterated over the block - (each_entry).
        result = []
        begin
          if @client
            # Validate the_path: /.*(?:\\|\/)(.+)$/ from: https://www.experts-exchange.com/questions/22088316/Extract-Filename-from-PATH-using-REGEX.html
            unless (/.*(?:\\|\/)(.+)$/.match(the_path.to_s) || the_path.to_s.split("/").size > 0 || the_path == "/")
              raise ArgumentError, "You MUST provide a valid remote file system path."
            end
            if pattern.is_a?(::String)
              # use glob
              unless flags.is_a?(::Numeric)
                flags = 0
              end
              raw_list = @client.dir.glob(the_path, pattern, flags)
            else
              # use entries
              raw_list = @client.dir.entries(the_path)
            end
            list = []
            raw_permission = { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }
            blank_permissions = {:effective => nil, :owner => raw_permission.clone, :group => raw_permission.clone, :other => raw_permission.clone}
            #
            raw_list.each do |details|
              #
              unless details.name == "." || details.name == ".."
                #
                record = {:title => (details.name), :type => :virtual_directory, :owner_type => :virtual_directory, :on_device => nil, :on_device_major => nil, :on_device_minor => nil, :is_device => nil, :is_device_major => nil, :is_device_minor => nil, :inode => nil, :flags => [], :hardlinks_to => 0, :user_id => nil, :group_id => nil, :size => 0, :block_size => 0, :blocks => 0, :accessed => nil, :modified => nil, :status_modified => nil, :permissions => nil, :mode=>nil}
                permission_record = blank_permissions.clone
                #
                record = record.merge({:size => (details.attributes.size), :accessed => (Time.at(details.attributes.atime)).to_datetime, :modified => (Time.at(details.attributes.mtime)).to_datetime, :state_modified => (Time.at(details.attributes.mtime)).to_datetime, :user_id => (details.attributes.uid), :group_id => (details.attributes.gid)})
                if details.directory?()
                  record[:type] = :directory
                  record[:owner_type] = :directory
                end
                if details.file?()
                  record[:type] = :file
                  record[:owner_type] = :file
                end
                if details.symlink?()
                  record[:type] = :symlink
                  record[:owner_type] = :symlink
                end
                # puts "Got: #{details.attributes.permissions.inspect}"
                record[:permissions] = ::File.mode_permission_to_gxg(details.attributes.permissions.to_i)
                current_groups = @client.session.exec!("groups").gsub("\n","").split(" ")
                if current_groups.size > 0
                  effective_permissions = raw_permission.clone
                  if @user == details.attributes.owner
                    include_owner = true
                  else
                    include_owner = false
                  end
                  if current_groups.include?(details.attributes.group)
                    include_group = true
                  else
                    include_group = false
                  end
                  #
                  permissions_stack = []
                  if include_owner
                    permissions_stack << record[:permissions][:owner]
                  end
                  if include_group
                    permissions_stack << record[:permissions][:group]
                  end
                  permissions_stack << record[:permissions][:other]
                  permissions_stack.each do |entry|
                    entry.keys do |the_key|
                      if entry[(the_key)] == true
                        effective_permissions[(the_key)] = true
                      end
                    end
                  end
                  record[:permissions][:effective] = effective_permissions
                  if record[:permissions][:effective][:read]
                    record[:flags] << :read
                  end
                  if record[:permissions][:effective][:write]
                    record[:flags] << :write
                  end
                end
                list << record
              end
              #
            end
            #
            if block.respond_to?(:call)
              list.each do |entry|
                block.call(entry)
              end
            end
            result = list
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:remote_path => the_path}})
        end
        result
      end
      #
      def open_remote_file(the_path=nil, permissions={})
        result = nil
        begin
          if @client
            filename = ::File.basename(the_path)
            entries = this().entries(::File.dirname(the_path))
            open_only = false
            flags = []
            entries.each do |item|
              if item[:title] == filename
                open_only = true
                flags = item[:flags]
                break
              end
            end
            if open_only
              if flags.include?(:read)
                if flags.include?(:write)
                  open_mode = "w+"
                else
                  open_mode = "r"
                end
              else
                if flags.include?(:write) 
                  open_mode = "w"
                else                
                  open_mode = "r"
                end
              end
              #open
              result = @client.file.open(the_path.to_s, open_mode)
            else
              #create
              if permissions.is_a?(::Hash)
                if permissions[:owner].is_a?(::Hash) && permissions[:group].is_a?(::Hash) && permissions[:other].is_a?(::Hash)
                  permissions = ::File.gxg_permissions_to_mode(permissions)
                end
              end
              if permissions.is_a?(::Numeric)
                unless permissions > 0
                  permissions = 0644.to_i
                end
              else
                permissions = 0644.to_i
              end
              result = @client.file.open(the_path.to_s, "w+", permissions)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:remote_path => the_path, :permissions => permissions}})
        end
        result
      end
      #
      def change_ownership(the_path=nil, new_owners=nil, &block)
        result = false
        begin
          unless the_path.is_a?(::String)
            raise ArgumentError, "You MUST supply a remote path. (/path/to/something)."
          end
          unless new_owners.is_a?(::Hash)
            raise ArgumentError, "You MUST supply a Hash with :user, and optionally :group, defined with a String."
          end
          unless new_owners[:user].is_a?(::String)
            raise ArgumentError, "You MUST supply a Hash with :user, and optionally :group, defined with a String."
          end
          response = @client.setstat!(the_path, new_owners)
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:path => the_path, :new_owners => new_owners}})
        end
        result
      end
      #
      def change_permissions(the_path=nil, new_permissions=nil, &block)
        result = false
        begin
          unless the_path.is_a?(::String)
            raise ArgumentError, "You MUST supply a remote path. (/path/to/something)."
          end
          unless new_permissions
            raise ArgumentError, "You MUST supply a new permission value. (GxG permission or Integer/Octal)."
          end
          if new_permissions.is_a?(::Hash)
            new_permissions = ::File.gxg_permissions_to_mode(new_permissions)
          end
          response = @client.setstat!(the_path, {:permissions => new_permissions})
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:path => the_path, :new_permissions => new_permissions}})
        end
        result
      end
      # 
      def remove_remote_file(the_path=nil, &block)
        result = false
        begin
          unless the_path.is_a?(::String)
            raise ArgumentError, "You MUST supply a remote file path. (/path/to/file)."
          end
          response = @client.remove!(the_path)
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:path => the_path}})
        end
        result
      end
      #
      def make_link(new_link_path=nil, existing_path=nil, symlink=true, &block)
        result = false
        begin
          unless new_link_path.is_a?(::String)
            raise ArgumentError, "You MUST supply a new link path. (/path/to/new_link)."
          end
          unless existing_path.is_a?(::String)
            raise ArgumentError, "You MUST supply an existing file path. (/path/to/file)."
          end
          unless symlink
            symlink = true
          end
          response = @client.link!(new_link_path,existing_path,symlink)
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:new_link_path => new_link_path, :existing_path => existing_path, :symlink => symlink}})
        end
        result
      end
      #
      def rename(name=nil, new_name=nil,&block)
        result = false
        begin
          unless name.is_a?(::String)
            raise ArgumentError, "You MUST supply a remote file path. (/path/to/old_name)."
          end
          unless new_name.is_a?(::String)
            raise ArgumentError, "You MUST supply a new file name path. (/path/to/new_name)."
          end
          response = @client.rename!(name,new_name,0x0004)
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:original_name => name, :new_name => new_name}})
        end
        result
      end
      #
      def make_directory(the_path=nil, &block)
        result = false
        begin
          unless the_path.is_a?(::String)
            raise ArgumentError, "You MUST supply a new directory path. (/path/to/new_dir)."
          end
          response = @client.mkdir!(the_path)
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:original_name => name, :new_name => new_name}})
        end
        result
      end
      #
      def remove_directory(the_path=nil, &block)
        result = false
        begin
          unless the_path.is_a?(::String)
            raise ArgumentError, "You MUST supply a directory path to remove. (/path/to/dir)."
          end
          response = @client.rmdir!(the_path)
          if block.respond_to?(:call)
            block.call(response)
          end
          result = response.ok?
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:original_name => name, :new_name => new_name}})
        end
        result
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("sftp-ssh", ::GxG::Networking::SftpClient)
    ::GxG::Networking::DISPATCHER.register_client("ftp-ssh", ::GxG::Networking::SftpClient)
    #
    class FtpClient
      # Review : make BufferedSegments compatible
      def initialize(the_url=nil, options={})
        unless the_url.is_a?(::URI::Generic)
          raise ArgumentError, "You MUST provide a valid URI"
        end
        # The available options are:
        #
        # port::      Port number (default value is 21)
        if options[:port].is_a?(::Numeric)
          login_options[:port] = options[:port].to_i
        end
        # ssl::       If options[:ssl] is true, then an attempt will be made
        #             to use SSL (now TLS) to connect to the server.  For this
        #             to work OpenSSL [OSSL] and the Ruby OpenSSL [RSSL]
        #             extensions need to be installed.  If options[:ssl] is a
        #             hash, it's passed to OpenSSL::SSL::SSLContext#set_params
        #             as parameters.
        if options[:use_ssl] == true
          login_options[:ssl] = true
        end
        # private_data_connection::  If true, TLS is used for data connections.
        #                            Default: +true+ when options[:ssl] is true.
        # username::  Username for login.  If options[:username] is the string
        #             "anonymous" and the options[:password] is +nil+,
        #             "anonymous@" is used as a password.
        login_options[:username] = the_url.user
        # password::  Password for login.
        login_options[:password] = the_url.password
        # account::   Account information for ACCT.
        if options[:account_info]
          login_options[:account] = options[:account_info]
        end
        # passive::   When +true+, the connection is in passive mode. Default:
        #             +true+.
        if options[:passive] == false
          login_options[:passive] = false
        end
        # open_timeout::  Number of seconds to wait for the connection to open.
        #                 See Net::FTP#open_timeout for details.  Default: +nil+.
        if options[:open_timeout].is_a?(::Numeric)
          login_options[:open_timeout] = options[:open_timeout]
        end
        # read_timeout::  Number of seconds to wait for one block to be read.
        #                 See Net::FTP#read_timeout for details.  Default: +60+.
        if options[:read_timeout].is_a?(::Numeric)
          login_options[:read_timeout] = options[:read_timeout]
        end
        # ssl_handshake_timeout::  Number of seconds to wait for the TLS
        #                          handshake.
        #                          See Net::FTP#ssl_handshake_timeout for
        #                          details.  Default: +nil+.
        if options[:ssl_handshake_timeout].is_a?(::Numeric)
          login_options[:ssl_handshake_timeout] = options[:ssl_handshake_timeout]
        end
        #
        @client = Net::FTP.new(the_url.hostname, login_options)
        if @client.is_a?(Net::FTP)
          @client.login
          if @client.closed?
            raise Exception, "Failed to log into FTP session"
          end
        else
          raise Exception, "Failed to create FTP session"
        end
        self
      end
      #
      def login(the_url=nil, options={})
        result = false
        login_options = {}
        begin
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI"
          end
          # The available options are:
          #
          # port::      Port number (default value is 21)
          if options[:port].is_a?(::Numeric)
            login_options[:port] = options[:port].to_i
          end
          # ssl::       If options[:ssl] is true, then an attempt will be made
          #             to use SSL (now TLS) to connect to the server.  For this
          #             to work OpenSSL [OSSL] and the Ruby OpenSSL [RSSL]
          #             extensions need to be installed.  If options[:ssl] is a
          #             hash, it's passed to OpenSSL::SSL::SSLContext#set_params
          #             as parameters.
          if options[:use_ssl] == true
            login_options[:ssl] = true
          end
          # private_data_connection::  If true, TLS is used for data connections.
          #                            Default: +true+ when options[:ssl] is true.
          # username::  Username for login.  If options[:username] is the string
          #             "anonymous" and the options[:password] is +nil+,
          #             "anonymous@" is used as a password.
          login_options[:username] = the_url.user
          # password::  Password for login.
          login_options[:password] = the_url.password
          # account::   Account information for ACCT.
          if options[:account_info]
            login_options[:account] = options[:account_info]
          end
          # passive::   When +true+, the connection is in passive mode. Default:
          #             +true+.
          if options[:passive] == false
            login_options[:passive] = false
          end
          # open_timeout::  Number of seconds to wait for the connection to open.
          #                 See Net::FTP#open_timeout for details.  Default: +nil+.
          if options[:open_timeout].is_a?(::Numeric)
            login_options[:open_timeout] = options[:open_timeout]
          end
          # read_timeout::  Number of seconds to wait for one block to be read.
          #                 See Net::FTP#read_timeout for details.  Default: +60+.
          if options[:read_timeout].is_a?(::Numeric)
            login_options[:read_timeout] = options[:read_timeout]
          end
          # ssl_handshake_timeout::  Number of seconds to wait for the TLS
          #                          handshake.
          #                          See Net::FTP#ssl_handshake_timeout for
          #                          details.  Default: +nil+.
          if options[:ssl_handshake_timeout].is_a?(::Numeric)
            login_options[:ssl_handshake_timeout] = options[:ssl_handshake_timeout]
          end
          #
          @client = Net::FTP.new(the_url.hostname, login_options)
          if @client.is_a?(Net::FTP)
            @client.login
            if @client.closed?
              raise Exception, "Failed to log into FTP session"
            else
              result = true
            end
          else
            raise Exception, "Failed to create FTP session"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def logout()
        if @client
          @client.close
          if @client.closed?
            true
          else
            false
          end
        end
      end
      #
      def closed?()
        if @client
          @client.closed?
        else
          true
        end
      end
      #
      def status()
        result = nil
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed connection."
            else
              result = @client.status()
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def system_info()
        result = nil
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed connection."
            else
              result = @client.system()
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def help()
        result = nil
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed connection."
            else
              result = @client.help()
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def send_account_info(acct_info=nil)
        result = false
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed connection."
            else
              unless acct_info.is_a?(::String)
                raise ArgumentError, "You MUST provide account information (as a String)."
              end
              result = @client.acct(acct_info)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:account_info => acct_info}})
        end
        result
      end
      #
      def send_command(command=nil)
        result = nil
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed connection."
            else
              unless command.is_a?(::String)
                raise ArgumentError, "You must provide a String to issue FTP commands."
              end
              result = @client.sendcmd(command)
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:command => command}})
        end
        result
      end
      #
      def reopen()
        result = false
        begin
          if @client
            if @client.closed?
              @client.connect()
              if @client.closed?
                raise Exception, "Failed to re-open connection."
              end
            else
              result = true
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def get_file(file_name=nil, save_path=nil)
        result = nil
        begin
          if @client
            if save_path
              result = @client.getbinaryfile(file_name, save_path, 1024)
            else
              result = ::GxG::ByteArray.new
              @client.getbinaryfile(file_name, save_path) do |data_chunk|
                result << data_chunk
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_name => file_name, :save_path => save_path}})
        end
        result
      end
      #
      def put_file(local_path=nil, remote_file=nil)
        result = false
        begin
          if @client
            result = @client.putbinaryfile(local_path, remote_file, 1024)
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:local_path => local_path, :remote_file => remote_file}})
        end
        result
      end
      #
      def rename_file(file_name=nil, new_file_name=nil)
        result = false
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed session"
            else
              unless file_name
                raise ArgumentError, "You MUST provide a current file name to rename."
              end
              unless new_file_name
                raise ArgumentError, "You MUST provide a new name to rename the file."
              end
              result = @client.rename(file_name, new_file_name)
              unless result
                raise Exception, "Failed to rename file."
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_name => file_name, :new_file_name => new_file_name}})
        end
        result
      end
      #
      def remove_file(file_name=nil)
        result = false
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed session"
            else
              unless file_name
                raise ArgumentError, "You MUST provide a file name to remove."
              end
              result = @client.delete(file_name)
              unless result
                raise Exception, "Failed to remove file."
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_name => file_name}})
        end
        result
      end
      #
      def entries(dir_name=nil, filter=nil)
        result = []
        unless dir_name
          dir_name = @client.pwd()
        end
        begin
          if @client
            present_dir = @client.pwd()
            @client.chdir(dir_name)
            if filter
              list = @client.list(filter)
            else
              list = @client.list()
            end
            list.each do |entry|
              # TODO: process entry text
              data = entry.split(" ")
              record = {:title => "", :type => :virtual_directory, :owner_type => :virtual_directory, :on_device => nil, :on_device_major => nil, :on_device_minor => nil, :is_device => nil, :is_device_major => nil, :is_device_minor => nil, :inode => nil, :flags => [:read], :hardlinks_to => 0, :user_id => nil, :group_id => nil, :size => 0, :block_size => 0, :blocks => 0, :accessed => nil, :modified => nil, :status_modified => nil, :permissions => nil, :mode=>nil}
              #
              record[:permissions] = ::File.unix_permissions_to_gxg(data[0].to_s)
              if record[:permissions][:other][:write]
                record[:flags] << :write
              end
              #              record[:owner] = data[2]
              #              record[:group] = data[3]
              record[:size] = data[4].to_i
              record[:modified] = ::DateTime::parse(data[5..7].join(" "))
              record[:title] = data[8]
              result << record
            end
            @client.chdir(present_dir)
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:dir_name => dir_name, :filter => filter}})
        end
        result
      end
      #
      def present_directory()
        result = nil
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed session"
            else
              result = @client.pwd()
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def change_directory(dir_name=nil)
        result = false
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed session"
            else
              unless dir_name
                raise ArgumentError, "You MUST provide a directory path to change to."
              end
              @client.chdir(dir_name)
              if @client.pwd() != dir_name
                raise Exception, "Failed to change directory."
              else
                result = true
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:dir_name => dir_name}})
        end
        result
      end
      #
      def make_directory(dir_name=nil)
        result = false
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed session"
            else
              unless dir_name
                raise ArgumentError, "You MUST provide a directory path to create."
              end
              result = @client.mkdir(dir_name)
              unless result
                raise Exception, "Failed to change directory."
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:dir_name => dir_name}})
        end
        result
      end
      #
      def remove_directory(dir_name=nil)
        result = false
        begin
          if @client
            if @client.closed?
              raise Exception, "Attempted to access a closed session"
            else
              unless dir_name
                raise ArgumentError, "You MUST provide a directory name to remove."
              end
              result = @client.rmdir(dir_name)
              unless result
                raise Exception, "Failed to remove directory."
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:dir_name => dir_name}})
        end
        result
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("ftp", ::GxG::Networking::FtpClient)
    #
    class HttpClient
      #
      def initialize(the_url=nil, options={})
        @cookie = nil
        if the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
          @url = the_url.clone
          if options[:query].is_a?(::Hash)
            @url.query = ::URI.encode_www_form(options[:query])
          end
          unless options[:follow_redirects] == false
            options.merge({:follow_redirects => true})
          end
          #
          if @url.scheme.downcase == "https"
            options[:use_ssl] = true
          end
          # sets following values by its accessor.
          # The keys are ca_file, ca_path, cert, cert_store, ciphers,
          # close_on_empty_response, key, open_timeout, read_timeout, ssl_timeout,
          # ssl_version, use_ssl, verify_callback, verify_depth and verify_mode.
          # If you set :use_ssl as true, you can use https and default value of
          # verify_mode is set as OpenSSL::SSL::VERIFY_PEER.
          client_parameters = [(the_url.hostname), (the_url.port)]
          if options[:proxy].is_a?(::URI::Generic)
            client_parameters << options[:proxy].host
            client_parameters << options[:proxy].port
            if options[:proxy].user && options[:proxy].password
              client_parameters << options[:proxy].user
              client_parameters << options[:proxy].password
            else
              client_parameters << nil
              client_parameters << nil
            end
          else
            client_parameters << nil
            client_parameters << nil
            client_parameters << nil
            client_parameters << nil
          end
          if options.keys.size > 0
            client_parameters << options
          end
          @options = options
          @client = Net::HTTP.start(*client_parameters)
          if options[:pem_source].is_any?(::File, ::GxG::Database::PersistedArray)
            pem_data = nil
            if options[:pem_source].is_a?(::File)
              options[:pem_source].rewind
              pem_data = options[:pem_source].read()
            else
              buffer = ::GxG::ByteArray.new
              options[:pem_source].each_index do |segment|
                buffer << options[:pem_source][(segment)].to_s
                options[:pem_source].unload(segment)
              end
              pem_data = buffer.to_s
            end
            if pem_data
              @client.use_ssl = true
              @client.cert = OpenSSL::X509::Certificate.new(pem_data)
              @client.key = OpenSSL::PKey::RSA.new(pem_data, options[:pem_password])
              @client.verify_mode = OpenSSL::SSL::VERIFY_PEER
            end
          end
        else
          raise ArgumentError, "You MUST use HTTP or HTTPS as a protcol here."
        end
        self
      end
      #
      def clear_cache()
        @cookie = nil
        true
      end
      #
      def cookies()
        @cookie.clone
      end
      #
      def get(the_url=nil, options=nil)
        result = nil
        begin
          unless the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            the_url = @url
          end
          if options.is_a?(::Hash)
            if options[:query].is_a?(::Hash)
              the_url.query = ::URI.encode_www_form(options[:query])
            end
            options = @options.merge(options)
          else
            options = @options
          end
          if the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            if @cookie
              if options[:header].is_a?(::Hash)
                request = Net::HTTP::Get.new(the_url.request_uri, {'Cookie' => @cookie}.merge(options[:header]))
              else
                request = Net::HTTP::Get.new(the_url.request_uri, {'Cookie' => @cookie})
              end
            else
              if options[:header].is_a?(::Hash)
                request = Net::HTTP::Get.new(the_url.request_uri, options[:header])
              else
                request = Net::HTTP::Get.new(the_url.request_uri)
              end
            end
            if (the_url.user && the_url.password)
              # basic auth
              request.basic_auth(the_url.user, the_url.password)
            end
            response = @client.request(request)
            @cookie = response.response['set-cookie']
            response_code = response.code.to_i
            if options[:follow_redirects]
              if response_code >= 300 && response_code < 400
                # Process Redirect
                redirect_count = 1
                redirect_limit = (options[:redirect_limit] || 9).to_i
                location = response['location']
                while location do
                  #
                  if @cookie
                    redirect_request = Net::HTTP::Get.new(location, {'Cookie' => @cookie})
                  else
                    redirect_request = Net::HTTP::Get.new(location)
                  end
                  redirect_response = @client.request(redirect_request)
                  if redirect_response.code.to_i == 200
                    response = redirect_response
                    response_code = 200
                    @cookie = response.response['set-cookie']
                    break
                  else
                    if redirect_response['location']
                      @cookie = redirect_response.response['set-cookie']
                      redirect_count += 1
                      # Review : allow option to set this limit higher :redirect_limit
                      if redirect_count > redirect_limit
                        raise Exception, "Circular redirect chain suspected (#{redirect_limit} or more redirects)"
                      end
                      response_code = redirect_response.code.to_i
                      location = redirect_response['location']
                    else
                      break
                    end
                  end
                  #
                end
              end
            end
            if options[:save_to].is_any?(::File, ::GxG::Database::PersistedArray)
              if options[:save_to].is_a?(::File)
                options[:save_to].rewind
                response.read_body do |data_chunk|
                  options[:save_to].write(data_chunk)
                end
                options[:save_to].rewind
              else
                response.read_body do |data_chunk|
                  options[:save_to] << ::GxG::ByteArray.new(data_chunk)
                  options[:save_to].save
                  options[:save_to].unload(options[:save_to].size - 1)
                end
              end
            end
            if response_code == 200 && options[:save_to] == nil
              # Return raw response
              result = response
            else
              if options[:save_to]
                result = true
              else
                raise Exception, "Error occured: Code #{response.code}, Data: #{response.to_s}"
              end
            end
          else
            raise Exception, "You MUST provide a valid HTTP or HTTP URI"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
      #
      def put(the_url=nil, data=nil, options={})
        #
        result = false
        begin
          unless the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            the_url = @url
          end
          if options.is_a?(::Hash)
            if options[:query].is_a?(::Hash)
              the_url.query = ::URI.encode_www_form(options[:query])
            end
            options = @options.merge(options)
          else
            options = @options
          end
          if the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            if @cookie
              request = Net::HTTP::Put.new(the_url.request_uri, {'Cookie' => @cookie})
            else
              request = Net::HTTP::Put.new(the_url.request_uri)
            end
            request.body = data
            if (the_url.user && the_url.password)
              # basic auth
              request.basic_auth(the_url.user, the_url.password)
            end
            response = @client.request(request)
            @cookie = response.response['set-cookie']
            response_code = response.code.to_i
            #
            if options[:follow_redirects]
              if response_code >= 300 && response_code < 400
                # Process Redirect
                redirect_count = 1
                redirect_limit = (options[:redirect_limit] || 9).to_i
                location = response['location']
                while location do
                  #
                  if @cookie
                    redirect_request = Net::HTTP::Put.new(location, {'Cookie' => @cookie})
                  else
                    redirect_request = Net::HTTP::Put.new(location)
                  end
                  redirect_response = @client.request(redirect_request)
                  if redirect_response.code.to_i == 200
                    response = redirect_response
                    response_code = 200
                    break
                  else
                    if redirect_response['location']
                      redirect_count += 1
                      if redirect_count > redirect_limit
                        raise Exception, "Circular redirect chain suspected (#{redirect_limit} or more redirects)"
                      end
                      response_code = redirect_response.code.to_i
                      location = redirect_response['location']
                    else
                      break
                    end
                  end
                  #
                end
              end
            end
            if response.code.to_i == 200
              result = true
            else
              raise Exception, "Error occured: Code #{response.code}, Data: #{response.to_s}"
            end
          else
            raise Exception, "You MUST provide a valid HTTP URI"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :form_data => data, :options => options}})
        end
        result
      end
      #
      def post(the_url=nil, form_data=nil, options={})
        result = false
        begin
          unless the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            the_url = @url
          end
          if options.is_a?(::Hash)
            if options[:query].is_a?(::Hash)
              the_url.query = ::URI.encode_www_form(options[:query])
            end
            options = @options.merge(options)
          else
            options = @options
          end
          # Review : figure a way to use VFS objects in multipart Posts (file uploads)
          if the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            if @cookie
              request = Net::HTTP::Post.new(the_url.request_uri, {'Cookie' => @cookie})
            else
              request = Net::HTTP::Post.new(the_url.request_uri)
            end
            if (the_url.user && the_url.password)
              # basic auth
              request.basic_auth(the_url.user, the_url.password)
            end
            request.set_form_data(form_data)
            response = @client.request(request)
            @cookie = response.response['set-cookie']
            response_code = response.code.to_i
            if options[:follow_redirects]
              if response_code >= 300 && response_code < 400
                # Process Redirect
                redirect_count = 1
                redirect_limit = (options[:redirect_limit] || 9).to_i
                location = response['location']
                while location do
                  #
                  if @cookie
                    redirect_request = Net::HTTP::Post.new(location, {'Cookie' => @cookie})
                  else
                    redirect_request = Net::HTTP::Post.new(location)
                  end
                  redirect_request.set_form_data(form_data)
                  redirect_response = @client.request(redirect_request)
                  if redirect_response.code.to_i == 200
                    response = redirect_response
                    response_code = 200
                    break
                  else
                    if redirect_response['location']
                      redirect_count += 1
                      if redirect_count > redirect_limit
                        raise Exception, "Circular redirect chain suspected (#{redirect_limit} or more redirects)"
                      end
                      response_code = redirect_response.code.to_i
                      location = redirect_response['location']
                    else
                      break
                    end
                  end
                  #
                end
              end
            end
            if response.code.to_i == 200
              result = true
            else
              raise Exception, "Error occured: Code #{response.code}"
            end
          else
            raise Exception, "You MUST provide a valid HTTP URI"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :form_data => form_data, :options => options}})
        end
        result
      end
      #
      def delete(the_url=nil, options={})
        result = false
        begin
          unless the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            the_url = @url
          end
          if options.is_a?(::Hash)
            if options[:query].is_a?(::Hash)
              the_url.query = ::URI.encode_www_form(options[:query])
            end
            options = @options.merge(options)
          else
            options = @options
          end
          if the_url.is_any?(::URI::HTTP, ::URI::HTTPS)
            if @cookie
              request = Net::HTTP::Delete.new(the_url.request_uri, {'Cookie' => @cookie})
            else
              request = Net::HTTP::Delete.new(the_url.request_uri)
            end
            if (the_url.user && the_url.password)
              # basic auth
              request.basic_auth(the_url.user, the_url.password)
            end
            response = @client.request(request)
            @cookie = response.response['set-cookie']
            response_code = response.code.to_i
            if options[:follow_redirects]
              if response_code >= 300 && response_code < 400
                # Process Redirect
                redirect_count = 1
                redirect_limit = (options[:redirect_limit] || 9).to_i
                location = response['location']
                while location do
                  #
                  if @cookie
                    redirect_request = Net::HTTP::Delete.new(location, {'Cookie' => @cookie})
                  else
                    redirect_request = Net::HTTP::Delete.new(location)
                  end
                  redirect_response = @client.request(redirect_request)
                  if redirect_response.code.to_i == 200
                    response = redirect_response
                    response_code = 200
                    break
                  else
                    if redirect_response['location']
                      redirect_count += 1
                      if redirect_count > redirect_limit
                        raise Exception, "Circular redirect chain suspected (#{redirect_limit} or more redirects)"
                      end
                      response_code = redirect_response.code.to_i
                      location = redirect_response['location']
                    else
                      break
                    end
                  end
                  #
                end
              end
            end
            if response.code.to_i == 200
              result = true
            else
              raise Exception, "Error occured: Code #{response.code}"
            end
          else
            raise Exception, "You MUST provide a valid HTTP URI"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:url => the_url, :options => options}})
        end
        result
      end
    end
    ::GxG::Networking::DISPATCHER.register_client("http",::GxG::Networking::HttpClient)
    #
    class HttpsClient
      def initialize(the_url=nil, options={:follow_redirects => true, :use_ssl => true})
        @client = ::GxG::Networking::HttpClient.new(the_url, options)
        self
      end
      #
      def cookies()
        @client.cookies()
      end
      #
      def clear_cache()
        @client.clear_cache()
      end
      #
      def get(the_url=nil, options={:follow_redirects => true, :use_ssl => true})
        @client.get(the_url,options)
      end
      def put(the_url=nil, data=nil, options={})
        @client.put(the_url,data,options)
      end
      def post(the_url=nil, form_data=nil, options={})
        @client.post(the_url,form_data,options)
      end
      def delete(the_url=nil, options={})
        @client.post(the_url,options)
      end
    end
    ::GxG::Networking::DISPATCHER.register_client("https",::GxG::Networking::HttpsClient)
    #
    class GxGApi
      private
      #
      def sendable_hash(data={})
        result = {}
        processing_db = [{original => data, target => result}]
        while processing_db.size > 0
          entry = processing_db.shift
          if entry
            if entry[:original].is_a?(::Hash)
              entry[:original].each_pair do |the_selector, the_value|
                if the_value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::DetachedHash)
                  entry[:target][(the_selector)] = the_value.export_package()
                else
                  if the_value.is_a?(::Hash)
                    entry[:target][(the_selector)] = {}
                    processing_db << {:original => entry[:original][(the_selector)], :target => entry[:target][(the_selector)]}
                  else
                    if the_value.is_a?(::Array)
                      entry[:target][(the_selector)] = []
                      processing_db << {:original => entry[:original][(the_selector)], :target => entry[:target][(the_selector)]}
                    else
                      entry[:target][(the_selector)] = the_value
                    end
                  end
                end
              end
            end
            #
            if entry[:original].is_a?(::Array)
              entry[:original].each_with_index do |the_value, the_selector|
                if the_value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::DetachedHash)
                  entry[:target][(the_selector)] = the_value.export_package()
                else
                  if the_value.is_a?(::Hash)
                    entry[:target][(the_selector)] = {}
                    processing_db << {:original => entry[:original][(the_selector)], :target => entry[:target][(the_selector)]}
                  else
                    if the_value.is_a?(::Array)
                      entry[:target][(the_selector)] = []
                      processing_db << {:original => entry[:original][(the_selector)], :target => entry[:target][(the_selector)]}
                    else
                      entry[:target][(the_selector)] = the_value
                    end
                  end
                end
              end
            end
            #
          end
        end
        result
      end
      #
      def pull(details={})
        result = nil
        begin
          response = @connector.get(::URI::parse("#{@scheme}://#{@hostname}#{@endpoint}?details=#{sendable_hash(details).gxg_export.to_json.encrypt(@csrf).encode64}"))
          # response.body.rewind
          if response.code.to_i == 200
            raw_result = ::Hash::gxg_import(JSON::parse(response.body.decode64.decrypt(@csrf), :symbolize_names => true))
            if raw_result.is_a?(::Hash)
              raw_result.search do |the_value, the_selector, the_container|
                if the_value.is_a?(::Hash)
                    if the_value[:formats].is_a?(::Hash) && the_value[:records].is_a?(::Array)
                        imported_list = ::GxG::Database::Database::detached_package_import(the_value)
                        if imported_list.size > 1
                            the_container[(the_selector)] = imported_list
                        else
                            the_container[(the_selector)] = imported_list[0]
                        end
                    end
                end
              end
              result = raw_result[:result]
            end
          else
            raise Exception.new(response.body.read())
          end
        rescue Exception => the_error
          log_error({:error => the_error})
        end
        result
      end
      #
      def push(data={})
        result = false
        begin
          result = @connector.put(::URI::parse("#{@scheme}://#{@hostname}#{@endpoint}"), sendable_hash(data).gxg_export.to_json.encrypt(@csrf).encode64)
        rescue Exception => the_error
          log_error({:error => the_error})
        end
        result
      end
      #
      public
      #
      def initialize(the_url=nil, options={})
        the_uri = ::URI::parse(the_url.to_s)
        response = nil
        @scheme = "https"
        @hostname = the_uri.hostname
        @endpoint = the_uri.path
        @connector = nil
        @csrf = nil
        @interface = {}
        begin
          the_uri = ::URI::parse("https://#{@hostname}#{@endpoint}?details=eyJpbnRyb2R1Y3Rpb24iOnRydWV9")
          the_connector = ::GxG::Networking::HttpsClient.new(the_uri)
          response = the_connector.get(the_uri)
        rescue Exception => the_error
          begin
            @scheme = "http"
            the_uri = ::URI::parse("http://#{@hostname}#{@endpoint}?details=eyJpbnRyb2R1Y3Rpb24iOnRydWV9")
            the_connector = ::GxG::Networking::HttpClient.new(the_uri)
            response = the_connector.get(the_uri)
          rescue Exception => the_error
            raise Exception.new("Failed to establish session link at #{the_url.to_s}.")
          end
        end
        if response
          if response.code.to_i == 200
            @connector = the_connector
            # response.body.rewind()
            the_csrf = ::Hash::gxg_import(JSON::parse(response.body.decode64, :symbolize_names => true))
            @csrf = the_csrf[:csrf]
          end
        end
        self
      end
      #
      def interface()
        @interface
      end
      #
      def login(username=nil, password=nil)
        if push({:upgrade_credential => {:username => username.to_s, :password => password.to_s}})
          @interface = pull({:interface => nil})
          true
        else
          false
        end
      end
      #
      def logout()
        pull({:downgrade_credential => nil})
        @interface = pull({:interface => nil})
        true
      end
      #
      def get(details={})
        if details.is_a?(::Hash)
          pull(details)
        else
          log_error("You MUST provide a Hash")
          nil
        end
      end
      #
      def put(data={})
        if data.is_a?(::Hash)
          push(data)
        else
          log_error("You MUST provide a Hash")
          nil
        end
      end
      #
    end
    ::GxG::Networking::DISPATCHER.register_client("gxg",::GxG::Networking::GxGApi)
    #
    class GxGRemoteServer
      def refresh_services
        response = nil
        begin
          the_uri = ::URI::parse("https://#{@hostname}#{@endpoint}")
          the_connector = ::GxG::Networking::HttpsClient.new(the_uri)
          response = the_connector.get(the_uri)
        rescue Exception => the_error
          begin
            @scheme = "http"
            the_uri = ::URI::parse("http://#{@hostname}#{@endpoint}")
            the_connector = ::GxG::Networking::HttpClient.new(the_uri)
            response = the_connector.get(the_uri)
          rescue Exception => the_error
            raise Exception.new("Failed to establish session link at #{the_url.to_s}.")
          end
        end
        if response
          if response.code.to_i == 200
            provisions = JSON::parse(response.body.decode64, :symbolize_names => true)[:result]
            if provisions
              @services = {}
              provisions.each do |the_record|
                @services[(the_record[:provides].to_s.downcase.to_sym)] = the_record[:path]
              end
            end
          end
        end
      end
      #
      def initialize(the_url=nil, options={})
        # URI Note: user:password@hostname/path/to/endpoint
        @uri = ::URI::parse(the_url.to_s)
        if ::GxG::valid_uuid?(options[:use_uuid].to_s.to_sym)
          @uuid = options[:use_uuid].to_s.to_sym
        else
          @uuid = ::GxG::uuid_generate.to_s.to_sym
        end
        @scheme = "https"
        @hostname = @uri.hostname
        @services = {}
        self.refresh_services
        @clients = {}
        @credential = :"00000000-0000-4000-0000-000000000000"
        @bridge_challenge = ::GxG::uuid_generate.to_s.to_sym
        @status = :unavailable
        @services.each_pair do |service,endpoint|
          @clients[(service)] = ::GxG::Networking::GxGApi.new("gxg://#{@hostname}#{endpoint}")
          @clients[(service)].login(@uri.username, @uri.password)
          #
        end
        @status = :connected
        self
      end
      #
      def uuid
        @uuid
      end
      #
      def title
        @title
      end
      #
      def credential()
        @credential
      end
      #
      def status()
        @status
      end
      # ### Bridging tools:
      def connect_bridge(parmameters={})
        localuuid = nil
        localtitle = "Untitled"
        localaccess = nil
        ::GxG::GXG_FEDERATION_SAFETY.synchronize do
          localuuid = ::GxG::GXG_FEDERATION[:uuid]
          localtitle = ::GxG::GXG_FEDERATION[:title]
          localaccess = ::GxG::GXG_FEDERATION[:access_url]
        end
        # @bridge_challenge
        # {:uuid => localuuid, :title => localtitle, :access_url => localaccess, :bridge_challenge => @bridge_challenge}
        header = @clients[:federation].get({:connect => {:uuid => localuuid, :title => localtitle, :access_url => localaccess, :bridge_challenge => @bridge_challenge}})
        # xxx
        if service == :federation
          # :access_url
          if @clients[(service)].respond_to_event?(:connect)
            # {:uuid => (uuid), :username => String, :password => String}
            header = @clients[(service)].get({:connect => {:uuid => @uuid, :username => "", :password => ""}})
            # {} 
            if header.is_a?(::Hash)
              @title = header[:title]
            else
              raise Exception.new("Could not connect")
            end
          end
        end
        #
      end
      #
      def disconnect_bridge(parmameters={})
        # @bridge_challenge
        # 
      end
      #
      def complete_bridge(parmameters={})
        #@bridge_challenge
      end
      #
      def interface
        result = {}
        #
        @services.keys.each do |service|
          result[(service)] = @clients[(service)].interface
        end
        #
        result
      end
      #
      def respond_to_event?(service, operation)
        @clients[(service)].respond_to_event?(operation)
      end
      #
      def call_event(service, operation_frame)
        @clients[(service)].get(operation_frame)
      end
      #
      def login(username=nil, password=nil)
        #
        @services.keys.each do |service|
          @clients[(service)].login(username, password)
        end
        #
        true
      end
      #
      def logout
        #
        @services.keys.each do |service|
          @clients[(service)].logout
        end
        #
        true
      end
      #
      def keys
        @services.keys
      end
      #
      def [](selector=:unspecified)
        @clients[(selector)]
      end
      #
      def send_message(the_message)
        @clients[:federation].put({:send_message => {:uuid => @uuid, :message => the_message}})[:result]
      end
      #
      def next_message()
        @clients[:federation].get({:next_message => @uuid})[:result]
      end
    end
    ::GxG::Networking::DISPATCHER.register_client("federation",::GxG::Networking::GxGRemoteServer)
    #
    class NextcloudClient
      # TODO: complete class code
      def initialize(the_url=nil, options={})
        self
      end
    end
    ::GxG::Networking::DISPATCHER.register_client("nextcloud",::GxG::Networking::NextcloudClient)
    #
    class MatrixID
      def initialize(the_id=nil)
        if the_id.is_a?(::MatrixSdk::MXID)
          @id = the_id
        else
          if the_id.is_any?(::String, ::Symbol)
            @id = ::MatrixSdk::MXID.new(the_id.to_s)
          end
        end
        self
      end
      #
      def base_object()
        @id
      end
      #
      def domain()
        @id.domain()
      end
      #
      def localport()
        @id.localport()
      end
      #
      def port()
        @id.port()
      end
      #
      def sigil()
        @id.sigil()
      end
      #
      def event?()
        @id.event?
      end
      #
      def group?()
        @id.group?
      end
      #
      def homeserver()
        @id.homeserver
      end
      #
      def homeserver_suffix()
        @id.homeserver_suffix
      end
      #
      def room?()
        @id.room?
      end
      #
      def room_alias()
        @id.room_alias
      end
      #
      def room_id()
        @id.room_id
      end
      #
      def to_s()
        @id.to_s
      end
      #
      def type()
        @id.type
      end
      #
      def user?()
        @id.user?
      end
      #
      def valid?()
        @id.valid?
      end
    end
    #
    class MatrixUser
      def initialize(client=nil, id=nil, options={})
        if client.is_a?(::MatrixSdk::Client)
          unless id.is_a?(::String)
            raise ArgumentError, "You MUST provide a user_id as a String."
          end
          @user = ::MatrixSdk::User.new(client, id, options)
        else
          if client.is_a?(::MatrixSdk::User)
            @user = client
          else
            raise ArgumentError, "You MUST provide a MatrixSdk::Client or MatrixSdk::User as client parameter."
          end
        end
        self
      end
      #
      def base_object()
        @user
      end
      #
      def active?
        @user.active?
      end
      #
      def avatar_url()
        @user.avatar_url()
      end
      #
      def avatar_url=(the_url_string=nil)
        if the_url_string.is_any?(::String, ::URI::Generic)
          @user.avatar_url = the_url_string.to_s
        else
          nil
        end
      end
      #
      def device_keys()
        @user.device_keys()
      end
      #
      def display_name()
        @user.display_name()
      end
      #
      def friendly_name()
        @user.friendly_name()
      end
      #
      def inspect()
        "<MatrixUser: #{@user.client.mxid()}>"
      end
      #
      def last_active()
        @user.last_active.to_datetime()
      end
      #
      def presence()
        @user.presence()
      end
      #
      def presence=(the_status=nil)
        if the_status.is_any?(::String, ::Symbol)
          if [:online, :offline, :unavailable].include?(the_status.to_sym)
            @user.presence = the_status.to_sym
          end
        end
      end
      #
      def status_message()
        @user.status_msg()
      end
      #
      def status_message=(the_message=nil)
        @user.status_msg = the_message.to_s
      end
      #
      def events(symbol_array=[])
        @user.events(*symbol_array)
      end
      #
      def ignore_inspect(symbol_array=[])
        @user.ignore_inspect(*symbol_array)
      end
      #
    end
    #
    class MatrixRoom
      def initialize(client=nil, room_id=nil, options={})
        if client.is_a?(::GxG::Networking::MatrixClient)
          if room_id.is_any?(::MatrixSdk::MXID, ::GxG::Networking::MatrixID, ::String, ::Symbol)
            room_id = ::MatrixSdk::MXID.new(room_id.to_s)
          else
            raise ArgumentError, "You MUST provide a GxG::Networking::MatrixID as room_id parameter."
          end
          @room = ::MatrixSdk::Room.new(client.base_object(), room_id, options)
        else
          if client.is_a?(::GxG::Networking::MatrixRoom)
            @room = client.base_object()
          else
            if client.is_a?(::MatrixSdk::Room)
              @room = client
            else
              raise ArgumentError, "You MUST provide a MatrixSdk::Client or MatrixSdk::Room as client parameter."
            end
          end
        end
        # Parameters:
        #     client (Client) —
        #     The underlying connection
        #     room_id (MXID) —
        #     The room ID
        #     data (Hash) (defaults to: {}) —
        #     Additional data to assign to the room
        # Options Hash (data):
        #     :name (String) —
        #     The current name of the room
        #     :topic (String) —
        #     The current topic of the room
        #     :canonical_alias (String, MXID) —
        #     The canonical alias of the room
        #     :aliases (Array(String, MXID)) —
        #     All non-canonical aliases of the room
        #     :join_rule (:invite, :public) —
        #     The join rule for the room
        #     :guest_access (:can_join, :forbidden) —
        #     The guest access setting for the room
        #     :world_readable (Boolean) —
        #     If the room is readable by the entire world
        #     :members (Array(User)) —
        #     The list of joined members
        #     :events (Array(Object)) —
        #     The list of current events in the room
        #     :members_loaded (Boolean) —
        #     If the list of members is already loaded
        #     :event_history_limit (Integer) — default: 10 —
        #     The limit of events to store for the room
        #     :avatar_url (String, URI) —
        #     The avatar URL for the room
        #     :prev_batch (String) —
        #     The previous batch token for backfill
        @thread_safety = ::Mutex.new
        @listening = nil
        @invitations = []
        @file_transfers = []
        @inbox = []
        self
      end
      #
      def listening?()
        if @thread_safety.synchronize { @listening }
          true
        else
          false
        end
      end
      #
      def start_listening(options={})
        listener = @room.on_event.add_handler { |the_event| on_message(the_event) }
        @thread_safety.synchronize { @listening = listener }
        true
      end
      #
      def stop_listening()
        if self.listening?
          the_id = 0
          @thread_safety.synchronize { the_id = @listening[:id] }
          @room.on_event.remove_handler(the_id)
          @thread_safety.synchronize { @listening = nil }
          true
        else
          false
        end
      end
      #
      def on_message(the_event=nil)
        if the_event
          # ### Event Types:
          # See : https://matrix.org/docs/spec/client_server/latest#room-events
          # See : https://matrix.org/docs/spec/client_server/latest#modules
          # if ['m.room.message', 'm.room.member'].include?(the_event.type) && @room.client.mxid != the_event.sender.to_s
          #   the_message = new_message({:sender => self, :ufs => ("org.matrix." << the_event.type.to_s).to_sym, :body => the_event})
          #   @thread_safety.synchronize { @inbox << the_message }
          # end
          # Note: invitation = event.type 'm.room.member' (with the membership value set to "invite")
          # Note: ?? = event.type 'm.room.membership' (??)
          # Note: room-message = event.type 'm.room.message'
          # Note: enrypted-message = event.type 'm.room.encrypted'
          # Note: room-topic = event.type 'm.room.topic'
          # Note: call invitation = event.type 'm.call.invite'
          # Note: call answer = event.type 'm.call.answer'
          put "Room Got: #{the_event.inspect}"
          if @room.client.mxid != the_event.sender.to_s
            the_message = new_message({:sender => self, :ufs => ("org.matrix." << the_event.type.to_s).to_sym, :body => the_event})
            # ### Event Routing:
            case the_event.type.to_s
            when 'm.room.message', 'm.room.encrypted'
              @thread_safety.synchronize { @inbox << the_message }
            when 'm.room.member'
              # Invitation?
              if the_event.msgtype.to_s.include?('call.invite')
                @thread_safety.synchronize { @invitations << the_message }
              end
            end
            #
          end
        end
      end
      #
      def invitations()
        result = []
        @thread_safety.synchronize { @invitations.each {|the_invitation| result << the_invitation} }
        result
      end
      #
      def next_message()
        @thread_safety.synchronize { @inbox.shift }
      end
      #
      def base_object()
        @room
      end
      #
      def room_id()
        ::GxG::Networking::MatrixID.new(@room.id)
      end
      #
      def add_alias(room_alias)
        @room.add_alias(room_alias)
      end
      #
      def add_tag(tag, data={})
        @room.add_tag(tag, **data)
      end
      #
      def all_members(**parameters)
        @room.all_members(**parameters).map {|item| ::GxG::Networking::MatrixUser.new(item)}
      end
      #
      def allow_guests=(enable=false)
        @room.allow_guests = enable
      end
      #
      def avatar_url()
        @room.avatar_url()
      end
      #
      def avatar_url=(the_url=nil)
        unless the_url.is_a?(::URI::MATRIX)
          if the_url.is_a?(::String)
            the_url = ::URI.parse(the_url)
          else
            raise ArgumentError, "You MUST provide a String or URI::MATRIX as the url."
          end
        end
        @room.avatar_url = the_url
      end
      #
      def  backfill_messages(reverse=false, limit=10)
        @room.backfill_messages(reverse, limit)
      end
      #
      def ban_user(user_id=nil, reason="")
        if user_id.is_any?(::String, ::GxG::Networking::MatrixUser)
          if user_id.is_a?(::GxG::Networking::MatrixUser)
            user_id = user_id.base_object
          end
          @room.ban_user(user_id, reason)
        else
          false
        end
      end
      #
      def display_name()
        @room.display_name()
      end
      #
      def get_account_data(type=nil)
        if type
          @room.get_account_data(type)
        else
          {}
        end
      end
      #
      def guest_access?()
        @room.guest_access?()
      end
      #
      def inspect()
        "<MatrixRoom: #{@room.display_name()}>"
      end
      #
      def invite_only=(enable=false)
        if enable == true
          @room.invite_only = true
        else
          @room.invite_only = false
        end
      end
      #
      def invite_only?()
        @room.invite_only?()
      end
      #
      def invite_user(user_id=nil)
        if user_id.is_any?(::String, ::GxG::Networking::MatrixUser)
          if user_id.is_a?(::GxG::Networking::MatrixUser)
            user_id = user_id.base_object
          end
          @room.invite_user(user_id)
        else
          false
        end
      end
      #
      def joined_members()
        @room.joined_members().map {|item| ::GxG::Networking::MatrixUser.new(item)}
      end
      #
      def kick_user(user_id=nil, reason="")
        if user_id.is_any?(::String, ::GxG::Networking::MatrixUser)
          if user_id.is_a?(::GxG::Networking::MatrixUser)
            user_id = user_id.base_object
          end
          @room.kick_user(user_id, reason)
        else
          false
        end
      end
      #
      def leave()
        @room.leave()
      end
      #
      def modify_required_power_levels(events = nil, params = {})
        @room.modify_required_power_levels(events, params)
      end
      #
      def modify_user_power_levels(users = nil, users_default = nil)
        @room.modify_user_power_levels(users, users_default)
      end
      #
      def redact_message(event_id, reason = nil)
        @room.redact_message(event_id, reason)
      end
      #
      def reload!()
        @room.reload!()
      end
      #
      def reload_aliases!()
        @room.reload_aliases!()
      end
      #
      def reload_name!()
        @room.reload_name!()
      end
      #
      def reload_topic!()
        @room.reload_topic!()
      end
      #
      def remove_tag(tag=nil)
        if tag
          @room.remove_tag(tag)
        else
          false
        end
      end
      #
      def report_message(event_id, reason="", score = -100)
        if event_id.is_any?(::String, ::GxG::Networking::MatrixID)
          if event_id.is_a?(::GxG::Networking::MatrixID)
            event_id = event_id.base_object()
          end
          @room.report_message(event_id, reason, score)
        else
          false
        end
      end
      #
      def send_audio(url, name, audio_info={})
        if url.is_any?(::String, ::URI::Generic)
          @room.send_audio(url, name, audio_info)
        else
          false
        end
      end
      #
      def send_emote(text=nil)
        if text
          @room.send_emote(text)
        end
      end
      #
      def send_file(url, name, file_info={})
        if url.is_any?(::String, ::URI::Generic)
          @room.send_file(url, name, file_info)
        else
          false
        end
      end
      #
      def send_html(html, body=nil, msgtype=nil, format=nil)
        @room.send_html(html, body, msgtype, format)
      end
      #
      def send_image(url, name, image_info={})
        if url.is_any?(::String, ::URI::Generic)
          @room.send_image(url, name, image_info)
        else
          false
        end
      end
      #
      def send_location(geo_uri, name, thumbnail_url=nil, thumbnail_info={})
        if geo_uri.is_any?(::String, ::URI::Generic) && thumbnail_url.is_any?(::String, ::URI::Generic)
          @room.send_location(geo_uri, name, thumbnail_url, thumbnail_info)
        else
          false
        end
      end
      #
      def send_notice(text=nil)
        if text
          @room.send_notice(text)
        end
      end
      #
      def send_text(text=nil)
        # Review : waiting for bug fix --> https://github.com/jruby/jruby/issues/6453
        if text
          @room.send_text(text)
        end
      end
      #
      def send_video(url, name, video_info={})
        if url.is_any?(::String, ::URI::Generic)
          @room.send_video(url, name, video_info)
        else
          false
        end
      end
      #
      def set_account_data(type, account_data)
        if type.is_a?(::String) && account_data.is_a?(::Hash)
          @room.set_account_data(type, account_data)
        else
          false
        end
      end
      #
      def set_user_profile(display_name=nil, avatar_url=nil, reason=nil)
        if avatar_url.is_any?(::String, ::URI::Generic)
          @room.set_user_profile(display_name, avatar_url, reason)
        else
          false
        end
      end
      #
      def tags()
        @room.tags()
      end
      #
      def unban_user(user_id)
        if user_id.is_any?(::String, ::GxG::Networking::MatrixUser)
          if user_id.is_a?(::GxG::Networking::MatrixUser)
            user_id = user_id.base_object()
          end
          @room.unban_user(user_id)
        else
          false
        end
      end
    end
    #
    class MatrixClient
      # Review : ensure module supports are provided
      # See : https://matrix.org/docs/spec/client_server/latest#modules
      #
      # Federation Notes:
      # you need to make sure other servers can reach your server, and that can be done in one of three ways:
      #
      # have the server running directly at port 8448 on the server_name you've configured in homeserver.yaml
      #
      # have a webserver running at that server_name serving a file at /.well-known/matrix/server that tells other servers where the actual server is running
      # mkdir -p /var/www/<YourServerName.tld>/.well-known/matrix
      # echo '{ "m.server": "<YourServerName.tld>:443" }' > /var/www/<YourServerName.tld>/.well-known/matrix/server (or /var/www/html/.well-known/matrix/server)
      #
      # have an SRV record in your DNS at _matrix._tcp.server_name.tld. that points to where your server is.
      #
      # Once you have one of these working (the federation tester can verify if it is working), you're ready to talk to other servers
      # See : https://matrix.org/blog/2020/04/06/running-your-own-secure-communication-service-with-matrix-and-jitsi#synapse
      # Note: you do NOT have to enable registration (you can keep closed registration) to federate a room.
      #
      def initialize(the_url=nil, options={})
        if the_url.is_a?(::MatrixSdk::Client)
          @client = the_url
        else
          unless the_url.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI."
          end
          # See: https://aleol57.gitlab-pages.liu.se/ruby-matrix-sdk/MatrixSdk/Client.html#initialize-instance_method
          @url = the_url
          the_url = the_url.clone
          @user_id = the_url.user
          the_url.user = nil
          @password = the_url.password
          the_url.password = nil
          unless @user_id && @password
            raise ArgumentError, "You MUST provide a user_id and password in the URI."
          end
          @options = options.clone
          @options[:user_id] = @user_id
          unless [:all, :some, :none].include?(@options[:client_cache])
            @options[:client_cache] = :all
          end
          if @options[:proxy]
            if @options[:proxy].is_a?(::URI::Generic)
              @options[:proxy_uri] = @options.delete(:proxy)
            else
              if @options[:proxy].is_a?(::String)
                @options[:proxy_uri] = ::URI.parse(@options.delete(:proxy).to_s)
              end
            end
          end
          @client = ::MatrixSdk::Client.new(the_url, **@options)
        end
        @mxid = ::GxG::Networking::MatrixID.new("@#{@user_id}:#{the_url.hostname}")
        @api = @client.api()
        @session = nil
        @thread_safety = ::Mutex.new
        @invitations = []
        @rooms = []
        @watcher = nil
        @listening = nil
        #
        self
      end
      #
      def base_object()
        @client
      end
      #
      def inspect()
        "<MatrixClient: @#{@user_id}:#{@url.hostname}>"
      end
      #
      def api()
        @api
      end
      #
      def listening?()
        if @thread_safety.synchronize { @listening }
          true
        else
          false
        end
      end
      #
      def start_listening(options={})
        listener = @client.on_event.add_handler { |the_event| on_message(the_event) }
        @thread_safety.synchronize { @listening = listener }
        true
      end
      #
      def stop_listening()
        if self.listening?
          the_id = 0
          @thread_safety.synchronize { the_id = @listening[:id] }
          @client.on_event.remove_handler(the_id)
          @thread_safety.synchronize { @listening = nil }
          true
        else
          false
        end
      end
      #
      def on_message(the_event=nil)
        if the_event
          # ### Event Types:
          # See : https://matrix.org/docs/spec/client_server/latest#room-events
          # See : https://matrix.org/docs/spec/client_server/latest#modules
          # if ['m.room.message', 'm.room.member'].include?(the_event.type) && @room.client.mxid != the_event.sender.to_s
          #   the_message = new_message({:sender => self, :ufs => ("org.matrix." << the_event.type.to_s).to_sym, :body => the_event})
          #   @thread_safety.synchronize { @inbox << the_message }
          # end
          # Note: invitation = event.type 'm.room.member' (with the membership value set to "invite")
          # Note: ?? = event.type 'm.room.membership' (??)
          # Note: room-message = event.type 'm.room.message'
          # Note: enrypted-message = event.type 'm.room.encrypted'
          # Note: room-topic = event.type 'm.room.topic'
          # Note: call invitation = event.type 'm.call.invite'
          # Note: call answer = event.type 'm.call.answer'
          put "Got: #{the_event.inspect}"
          if @room.client.mxid != the_event.sender.to_s
            the_message = new_message({:sender => self, :ufs => ("org.matrix." << the_event.type.to_s).to_sym, :body => the_event})
            # ### Event Routing:
            case the_event.type.to_s
            when 'm.room.member'
              # Invitation?
              if the_event.state_key.to_s.include?('invite')
                @thread_safety.synchronize { @invitations << the_message }
              end
            end
            #
          end
        end
      end
      #
      def invitations()
        result = []
        @thread_safety.synchronize { @invitations.each {|the_invitation| result << the_invitation} }
        result
      end
      #
      def add_listener(room)
        # Review : deprecated (I don't think I need this.)
        if room.is_a?(::GxG::Networking::MatrixRoom)
          room.start_listening
          true
        else
          false
        end
      end
      #
      def login(user_id=nil, password=nil, options={})
        if @client.logged_in?
          false
        else
          unless user_id.is_a?(::String)
            user_id = @user_id
          end
          unless password.is_a?(::String)
            password = @password
          end
          unless options.is_a?(::Hash)
            options = {}
          end
          options = options.clone
          #
          unless options[:sync_timeout].is_a?(::Integer)
            options[:sync_timeout] = 15
          end
          unless options[:full_state] ==  true
            options[:full_state] = false
          end
          @client.login(user_id, password, **options)
          ::GxG::Engine::reserve_event_descriptor()
          @client.start_listener_thread({})
          @watcher = $Dispatcher.every("5 seconds") do
            if self.logged_in? && (! self.listening?)
              self.start_listener_thread({})
            end
          end
          self.start_listening
          self.rooms.each do |the_room|
            the_room.start_listening
          end
          true
        end
      end
      #
      def login_with_token(user_id=nil, token=nil, options={})
        if @client.logged_in?()
          false
        else
          if user_id.is_a?(::String) && token == nil
            token = user_id
            user_id = nil
          end
          unless user_id.is_a?(::String)
            user_id = @user_id
          end
          unless password.is_a?(::String)
            password = @password
          end
          unless options.is_a?(::Hash)
            options = {}
          end
          options = options.clone
          #
          unless options[:sync_timeout].is_a?(::Integer)
            options[:sync_timeout] = 15
          end
          unless options[:full_state] ==  true
            options[:full_state] = false
          end
          @client.login_with_token(user_id, token, **options)
          ::GxG::Engine::reserve_event_descriptor()
          @client.start_listener_thread({})
          @watcher = $Dispatcher.every("5 seconds") do
            if self.logged_in? && (! self.listening?)
              self.start_listener_thread({})
            end
          end
          self.start_listening
          self.rooms.each do |the_room|
            the_room.start_listening
          end
          true
        end
      end
      #
      def session()
        @session
      end
      #
      def logout()
        $Dispatcher.cancel_timer(@watcher)
        @watcher = nil
        self.stop_listening
        @client.stop_listener_thread()
        ::GxG::Engine::release_event_descriptor()
        @client.logout()
        true
      end
      #
      def mxid()
        @mxid
      end
      #
      def access_token()
        @api.access_token()
      end
      #
      def device_id()
        @api.device_id()
      end
      #
      def proxy()
        @api.proxy_uri()
      end
      #
      def protocols()
        @api.protocols()
      end
      #
      def transaction_id()
        @api.transaction_id()
      end
      #
      def upload_file(the_file=nil, cdn_server_url=nil)
        # Review : add CDN upload to chosen server.
        result = nil
        if the_file.is_any?(::File, ::GxG::Storage::BufferedSegments)
          mime_type = ::MimeMagic.by_magic(the_file)
          if mime_type
            content_type = mime_type.type
          else
            content_type = "application/octet-stream"
          end
          if @api
            options = {:body_stream => the_file, :headers => {"content-type" => content_type}}
            result = @api.request(:post, :media_r0, "/upload", **options)
          end
        end
        result
        # data = Net::HTTP.get_response(URI(url))
        # mxc_url = client.api.media_upload(data.body, data.content_type)[:content_uri] if data.is_a? Net::HTTPOK
        # api.request(:post,
        #     :media_r0,
        #     '/upload',
        #     body_stream: open('./file'),
        #     headers: { 'content-type' => 'image/png' })
        # => { :content_uri => "mxc://example.com/AQwafuaFswefuhsfAFAgsw" }
        # Parameters:{
        #     method (Symbol) —
        #     The method to use, can be any of the ones under Net::HTTP
        #     api (Symbol) —
        #     The API symbol to use, :client_r0 is the current CS one
        #     path (String) —
        #     The API path to call, this is the part that comes after the API definition in the spec
        #     options (Hash) —
        #     Additional options to pass along to the request
        # Options Hash (**options):
        #     :query (Hash) —
        #     Query parameters to set on the URL
        #     :body (Hash, String) —
        #     The body to attach to the request, will be JSON-encoded if sent as a hash
        #     :body_stream (IO) —
        #     A body stream to attach to the request
        #     :headers (Hash) —
        #     Additional headers to set on the request
        #     :skip_auth (Boolean) — default: false —
        #     Skip authentication}
      end
      #
      def create_room(room_alias=nil, options={})
        if room_alias.is_a?(::String)
          room = @client.create_room(room_alias, **options)
          if room
            room = ::GxG::Networking::MatrixRoom.new(room)
            @thread_safety.synchronize { @rooms << room }
            room.start_listening
            true
          else
            false
          end
        else
          false
        end
      end
      #
      def ensure_room(room_id=nil)
        if room_id.is_any?(::String, ::GxG::Networking::MatrixID)
          if room_id.is_a?(::String)
            room_id = ::GxG::Networking::MatrixID.new(room_id.to_s)
          end
          room = @client.ensure_room(room_id.base_object())
          if room
            id_list = self.rooms.map {|the_room| the_room.base_object.mxid.to_s }
            if id_list.include?(room.mxid.to_s)
              self.rooms.each do |the_room|
                if the_room.base_object.mxid.to_s == room.mxid.to_s
                  room = the_room
                  break
                end
              end
              if room.is_a?(::GxG::Networking::MatrixRoom)
                room
              else
                nil
              end
            else
              room = ::GxG::Networking::MatrixRoom.new(room)
              @thread_safety.synchronize { @rooms << room }
              room.start_listening
              room
            end
          else
            nil
          end
        else
          nil
        end
      end
      #
      def find_room(room_id=nil, only_canonical=false)
        if room_id.is_any?(::String, ::GxG::Networking::MatrixID)
          if room_id.is_a?(::String)
            room_id = ::GxG::Networking::MatrixID.new(room_id.to_s)
          end
          room = @client.find_room(room_id.base_object(), only_canonical)
          if room
            self.rooms.each do |the_room|
              if the_room.base_object.mxid.to_s == room.mxid.to_s
                room = the_room
                break
              end
            end
            if room.is_a?(::GxG::Networking::MatrixRoom)
              room
            else
              ::GxG::Networking::MatrixRoom.new(room)
            end
          else
            nil
          end
        else
          nil
        end
      end
      #
      def get_user(user_id)
        if user_id.is_any?(::String, ::GxG::Networking::MatrixID)
          if user_id.is_a?(::String)
            user_id = ::GxG::Networking::MatrixID.new(user_id.to_s)
          end
          user = @client.get_user(user_id.base_object())
          if user
            ::GxG::Networking::MatrixUser.new(user)
          else
            nil
          end
        else
          nil
        end
      end
      #
      def join_room(room=nil, options={:server_name => []})
        if room.is_a?(::GxG::Networking::MatrixRoom)
          room = room.room_id.to_s
        end
        if room.is_any?(::GxG::Networking::MatrixID, ::MatrixSdk::MXID)
          room = room.to_s
        end
        if room.is_a?(::String)
          room = @client.join_room(room, **options)
          if room
            new_room = ::GxG::Networking::MatrixRoom.new(room)
            @thread_safety.synchronize { @rooms << new_room }
            new_room.start_listening
            true
          else
            false
          end
        else
          false
        end
      end
      #
      def listen_forever(timeout=30, bad_sync_timeout=5, sync_interval=0, options={})
        @client.listen_forever(timeout, bad_sync_timeout, sync_interval, **options)
      end
      #
      def listening?()
        @client.listening?()
      end
      #
      def logged_in?()
        @client.logged_in?()
      end
      #
      def user()
        ::GxG::Networking::MatrixUser.new(@client.mxid)
      end
      #
      def presence()
        @client.presence()
      end
      #
      def public_rooms()
        @client.public_rooms.map {|item| ::GxG::Networking::MatrixRoom.new(item)}
      end
      #
      def register_as_guest()
        @client.register_as_guest()
      end
      #
      def register_with_password(username=nil, password=nil, options={})
        if username.is_a?(::String) && password.is_a?(::String)
          begin
            @client.register_with_password(username, password, **options)
            true
          rescue Exception => exception
            false
          end
        else
          false
        end
      end
      #
      def registered_3pids()
        @client.registered_3pids()
      end
      #
      def reload_rooms!()
        @client.reload_rooms!()
      end
      #
      def remove_room_alias(room_id=nil)
        if room_id.is_any?(::GxG::Networking::MatrixID, ::MatrixSdk::MXID)
          room_id = room_id.to_s
        end
        if room_id.is_a?(::String)
          room = @client.remove_room_alias(room_id)
          if room
            true
          else
            false
          end
        else
          false
        end
      end
      #
      def rooms()
        result = []
        id_list = []
        @thread_safety.synchronize {
          @rooms.each do |the_room|
            id_list << the_room.room_id.base_object.to_s
            result << the_room
          end
        }
        # Review : find a way to include direct rooms in @room :
        # direct = client.api.get_account_data(client.mxid, 'm.direct')
        # room_id = direct.fetch mxid.to_s.to_sym
        # room = client.ensure_room room_id
        @client.rooms.each do |item|
          unless id_list.include?(item.room_id.to_s)
            new_entry = ::GxG::Networking::MatrixRoom.new(item)
            @thread_safety.synchronize { @rooms << new_entry }
            result << new_entry
          end
        end
        result
      end
      #
      def set_presence(status, message=nil)
        if [:online, :offline, :unavailable].include?(status)
          @client.set_presence(status, message)
          true
        else
          false
        end
      end
      #
      def start_listener_thread(options)
        @client.start_listener_thread(**options)
      end
      #
      def stop_listener_thread()
        @client.stop_listener_thread()
      end
      #
      def listen_for_events(skip_store_batch=false, options={})
        # See : https://aleol57.gitlab-pages.liu.se/ruby-matrix-sdk/MatrixSdk/Client.html#create_room-instance_method
        unless self.listening?
          unless options[:skip_store_batch] == true
            options[:skip_store_batch] = false
          end
          @client.sync(**options)
        end
      end
      #
    end
    MatrixSdk.logger = ::GxG::LOG
    ::GxG::Networking::DISPATCHER.register_client("matrix-https",::GxG::Networking::MatrixClient)
    ::GxG::Networking::DISPATCHER.register_client("matrix-http",::GxG::Networking::MatrixClient)
  end
  #
  CLIENTS = GxG::Networking::DISPATCHER
  #
end
#
class Object
  private
  def remote_server(specifier=nil)
    result = nil
    if specifier or ::GxG::valid_uuid?(specifier)
      ::GxG::GXG_FEDERATION_SAFETY.synchronize {
        ::GxG::GXG_FEDERATION[:available].each_pair do |server_uuid, server|
          if specifier.is_a?(::String)
            if specifier == server.title
              result = server
              break
            end
          else
            if specifier == server_uuid
              result = server
              break
            end
          end
        end
      }
    end
    result
  end
end
