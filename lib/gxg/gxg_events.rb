#
module GxG
  #
  GXG_FEDERATION = {:title => "Untitled", :uuid => nil, :available => {}, :connections => {}}
  GXG_FEDERATION_SAFETY = Mutex.new
  #
  module Messages
    class Channel
      #
      def initialize(the_uuid)
        @uuid = the_uuid
        @inbox = []
        @inbox_safety = ::Mutex.new
        @outbox = []
        @outbox_safety = ::Mutex.new
        @socket = nil
        @remote = nil
        @channel_secret = nil
        self
      end
      #
      def uuid()
        @uuid
      end
      #
      def socket()
        @socket
      end
      #
      def socket=(the_socket=nil)
        @socket = the_socket
      end
      #
      def remote()
        @remote
      end
      #
      def remote=(the_remote=nil)
        @remote = the_remote
      end
      #
      def secret()
        @channel_secret
      end
      #
      def secret=(the_secret=nil)
        @channel_secret = the_secret
      end
      #
      def inbox_size()
        @inbox_safety.synchronize { @inbox.size }
      end
      #
      def next_message()
        @inbox_safety.synchronize { @inbox.unshift }
      end
      #
      def outbox_size()
        @outbox_safety.synchronize { @outbox.size }
      end
      #
      def send_message(the_message)
        @outbox_safety.synchronize { @outbox << the_message }
      end
      #
      def read()
        @outbox_safety.synchronize { @outbox.unshift }
      end
      #
      def write(the_message)
        @inbox_safety.synchronize { @inbox << the_message }
      end
      #
    end
    #
    class ChannelManager
      #
      def update_channels
        result = false
        channels = []
        GXG_FEDERATION_SAFETY.synchronize {
          GXG_FEDERATION[:connections].values.each do |the_channel|
            channels << the_channel
          end
        }
        channels.each do |the_channel|
          the_message = the_channel.read()
          while the_message do
            self.dispatch_message(the_message)
            the_message = the_channel.read()
          end
        end
        if channels.size > 0
          # indicates that yes there were messages and yes they were sent.
          result = true
        end
        result
      end
      #
      def dispatch_message(the_message=nil)
        result = false
        if the_message.is_a?(::GxG::Events::Message)
          destination = the_message[:to]
          # uuid
          if ::GxG::valud_uuid?(destination.to_s)
            channel = self.fetch_channel(destination.to_s.to_sym)
            if channel
              if channel.socket
                # Send format: channel.socket.send({ :payload => the_message.export.to_s.encrypt(channel.secret).encode64 }.to_json.encode64, :text)
                channel.socket.send({ :payload => the_message.export.to_s.encrypt(channel.secret.to_s).encode64 }.to_json.encode64, :text)
              else
                channel.write(the_message)
              end
              result = true
            end
          end
          # email address -- TODO: integrate sendmail functionality in pure ruby. ::GxG::Networking::SmtpClient.new(::URI::parse("smtp://username:password@hostname.org:587"), {:use_ssl => true, :ignore_ssl_errors => true})
          #
        end
        result
      end
      #
      def fetch_channel(the_uuid)
        GXG_FEDERATION_SAFETY.synchronize { GXG_FEDERATION[:connections][(the_uuid)] }
      end
      #
      def create_channel(the_uuid)
        GXG_FEDERATION_SAFETY.synchronize { GXG_FEDERATION[:connections][(the_uuid)] = ::GxG::Messages::Channel.new(the_uuid)}
      end
      #
      def destroy_channel(the_uuid)
        channel = self.fetch_channel(the_uuid)
        if channel
          channel.outbox_size.times do |indexer|
            the_message = channel.read()
            if the_message
              self.dispatch_message(the_message)
            end
          end
        end
        GXG_FEDERATION_SAFETY.synchronize { GXG_FEDERATION[:connections].delete(the_uuid) }
      end
      #
      def next_message(the_uuid)
        result = nil
        channel = self.fetch_channel(the_uuid)
        if channel
          result = channel.next_message()
        end
        result
      end
      #
      def send_message(the_uuid, the_message)
        channel = self.fetch_channel(the_uuid)
        if channel
          channel.send_message(the_message)
        end
      end
      #
      def initialize
        self
      end
      #
    end
  end
   
  module Events
    #
    class Message
      def self.import(the_data=nil)
        the_message = new_message {}
        the_message.import(the_data)
        the_message
      end
      #
      def initialize(*args)
        # MUST provide a hash with at least :sender message field set
        # {:sender => <some-object>, :body => <some-object>, :on_success => <some-proc>, :on_fail => <some-proc> }
        unless args[0].is_a?(::Hash)
          raise ArgumentError, "you must pass a Hash to create the message"
        end
        @data = {:sender => nil, :id => (::GxG::uuid_generate().to_s.to_sym), :ufs => :"org.gxg.message", :subject => args[1], :body => nil, :on_success => nil, :on_fail => nil}.merge(args[0])
        unless @data[:sender]
          raise ArgumentError, "you must set the :sender key in the argument Hash"
        end
        self
      end
      #
      def inspect()
        @data.inspect
      end
      #
      def id()
        @data[:id]
      end
      #
      def sender()
        @data[:sender]
      end
      #
      def subject()
        @data[:subject]
      end
      # ### Universal Format Specifier of the body attribute.
      def ufs()
        @data[:ufs]
      end
      #
      def ufs=(the_format=nil)
        if the_format.is_any(::String, ::Symbol)
          @data[:ufs] = the_format.to_s.to_sym
        end
      end
      #
      def body()
        @data[:body]
      end
      #
      def compose_reply(&block)
        if block.respond_to?(:call)
          # Review : consider just cloning the @data variable and swapping sender/to.
          reply_message = ::GxG::Events::Message.new({:sender => self[:to], :to => self[:sender], :ufs => self.ufs(), :context => self[:context], :subject => self[:subject], :body => self[:body]})
          block.call(reply_message)
        else
          nil
        end
      end
      #
      def succeed(input=nil)
        if @data[:on_success].respond_to?(:call)
          @data[:on_success].call(input)
        end
      end
      #
      def fail(input=nil)
        if @data[:on_fail].respond_to?(:call)
          @data[:on_fail].call(input)
        end
      end
      #
      def on(event_type=nil,&block)
        if [:success, :fail].include?(event_type)
          if block.respond_to?(:call)
            case event_type
            when :success
              @data[:on_success] = block
            when :fail
              @data[:on_fail] = block
            end
          else
            raise ArgumentError, "You MUST provide a callable block."
          end
        else
          # Custom Events:
          @data[(("on_" + event_type.to_s.downcase).to_sym)] = block
        end
      end
      #
      def respond_to_event?(event_type=nil)
        result = false
        if event_type.is_any(::String, ::Symbol)
          if @data[(("on_" + event_type.to_s.downcase).to_sym)]
            result = true
          end
        end
        result
      end
      #
      def call_event(operation_envelope=nil)
        result = nil
        if operation_envelope.is_a?(::Hash)
          the_event = operation_envelope.keys[0]
          if self.respond_to?(the_event)
            data = operation_envelope[(the_event)]
            result = {:result => @data[(("on_" + event_type.to_s.downcase).to_sym)].call(data)}
          else
            result = {:result => nil, :error => "Command #{the_event.inspect} Not Found"}
          end
        end
        result
      end
      # Hash-like support methods:
      def keys()
        @data.keys()
      end
      def [](the_key)
        @data[(the_key)]
      end
      def []=(the_key, the_value)
        @data[(the_key)] = the_value
      end
      def process(&block)
        @data.process(&block)
      end
      def process!(&block)
        @data.process!(&block)
      end
      def search(&block)
        @data.search(&block)
      end
      def paths_to(*args)
        @data.paths_to(*args)
      end
      def get_at_path(*args)
        @data.get_at_path(*args)
      end
      def set_at_path(*args)
        @data.set_at_path(*args)
      end
      #
      def import(the_data=nil)
        # Requires gxg_export+JSON String or gxg_export Hash
        unless the_data.is_any?(::String, ::Hash)
          raise Exception.new("You MUST supply a JSON string or a Hash, you supplied: #{the_data.class.inspect}")
        end
        result = false
        if the_data.is_a?(::String)
          the_data = JSON.parse(the_data, {:symbolize_names => true})
        end
        if the_data.is(::Hash)
          @data.merge(::Hash::gxg_import(the_data))
          result = true
        end
        result
      end
      #
      def export()
        @data.gxg_export.to_json.to_s
      end
      def to_s()
        self.export.to_s
      end
      def to_json
        self.to_s
      end
      #
    end
    #
    class LoggerDB
      #
    end
    class LogRing < ::Logger
      #
      def initialize(*args)
        super(::STDOUT)
        @thread_safety = ::Mutex.new
        @busy = false
        @messages = []
        @outlets = {}
        self
      end
      #
      def keys()
        @thread_safety.synchronize { @outlets.keys() }
      end
      def [](the_key)
        @thread_safety.synchronize { @outlets[(the_key)] }
      end
      def []=(the_key,the_logger)
        if the_logger.is_any?(::Logger, ::GxG::Events::LoggerDB)
          @thread_safety.synchronize { @outlets[(the_key)] = the_logger }
          the_logger
        else
          raise ArgumentError, "You must supply a Logger or GxG::Events::LoggerDB instance, you provided a #{the_logger.class}"
        end
      end
      # ### Message handlers
      def post(the_message=nil)
        if the_message.is_a?(::GxG::Events::Message)
          @thread_safety.synchronize { @messages << the_message }
          true
        else
          false
        end
      end
      #
      def next_message()
        @thread_safety.synchronize { @messages.shift }
      end
      #
      def process_messages()
        unless @thread_safety.synchronize { @busy == true }
          @thread_safety.synchronize { @busy = true }
          #
          the_message = self.next_message()
          if the_message.is_a?(::GxG::Events::Message)
            begin
              if the_message[:subject] == :notification
                if the_message[:body].is_a?(::Hash)
                  outlets = this.keys()
                  outlets.to_enum(:each).each do |the_outlet_key|
                    the_outlet = this()[(the_outlet_key)]
                    if (the_message[:body][:severity] || ::Logger::UNKNOWN) >= the_outlet.level()
                      # output
                      if the_outlet.is_a?(::GxG::Events::LoggerDB)
                        # TODO: GxG::Events::LogRing : build out object-based event logging:
                      else
                        # conventional string based:
                        if (the_message[:body][:message].is_a?(::String) || the_message[:body][:message].is_a?(::Exception))
                          the_outlet.add(the_message[:body][:severity], the_message[:body][:message], the_message[:body][:progname])
                        else
                          if the_message[:body][:message].is_a?(::Hash)
                            #
                            if the_message[:body][:message][:error].is_a?(::Exception)
                              if the_message[:body][:message][:error].backtrace.is_a?(::Array)
                                if the_message[:body][:message][:parameters]
                                  the_outlet.add(the_message[:body][:severity], ("\n #{the_message[:body][:message][:error].exception.class.to_s}: " + the_message[:body][:message][:error].to_s + "\n Parameters: " + the_message[:body][:message][:parameters].inspect + "\n Trace: " + the_message[:body][:message][:error].backtrace.join("\n") + "\n"), the_message[:body][:progname])
                                else
                                  the_outlet.add(the_message[:body][:severity], ("\n #{the_message[:body][:message][:error].exception.class.to_s}: " + the_message[:body][:message][:error].to_s + "\n Trace: " + the_message[:body][:message][:error].backtrace.join("\n") + "\n"), the_message[:body][:progname])
                                end
                              else
                                if the_message[:body][:message][:parameters]
                                  the_outlet.add(the_message[:body][:severity], ("\n #{the_message[:body][:message][:error].exception.class.to_s}: " + the_message[:body][:message][:error].to_s + "\n Parameters: " + the_message[:body][:message][:parameters].inspect + "\n"), the_message[:body][:progname])
                                else
                                  the_outlet.add(the_message[:body][:severity], ("\n #{the_message[:body][:message][:error].exception.class.to_s}: " + the_message[:body][:message][:error].to_s + "\n"), the_message[:body][:progname])
                                end
                              end
                            else
                              the_outlet.add(the_message[:body][:severity], the_message[:body][:message].inspect, the_message[:body][:progname])
                            end
                          else
                            the_outlet.add(the_message[:body][:severity], the_message[:body][:message].inspect, the_message[:body][:progname])
                          end
                        end
                      end
                    end
                    #
                  end
                end
              end
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:message => the_message}})
            end
          end
          #
          @thread_safety.synchronize { @busy = false }
        end
        true
      end
      #
      def add(severity = nil, message = nil, progname = nil, origin = nil, &block)
        #
        unless [::Logger::DEBUG, ::Logger::INFO, ::Logger::WARN, ::Logger::ERROR, ::Logger::FATAL, ::Logger::UNKNOWN].include?(severity)
          severity = ::Logger::UNKNOWN
        end
        if progname
          unless message
            message = progname
            progname = nil
          end
        end
        begin
          unless message
            if block.respond_to?(:call)
              message = block.call()
            end
          end
          # this.mailbox << ::GxG::Events::Message.new({:sender => (origin || this), :severity => severity, :message => message, :progname => progname})
          the_message = new_message({:sender => (origin || self), :ufs => :"org.gxg.message.notification", :severity => severity, :message => message, :progname => progname}, :notification)
          self.post(the_message)
          true
        rescue => the_error
          log_error({:error => the_error, :parameters => {:severity => severity, :message => message, :progname => progname, :block => block}})
          false
        end
      end
      def unknown?()
        true
      end
      alias :trace? :unknown?
      def unknown(message = nil, progname = nil, origin = nil, &block)
        if self.alive?()
          self.add(::Logger::UNKNOWN, message, progname, (origin || self), &block)
        end
      end
      alias :trace :unknown
      def fatal?()
        true
      end
      def fatal(message = nil, progname = nil, origin = nil, &block)
        if self.alive?()
          self.add(::Logger::FATAL, message, progname, (origin || self), &block)
        end
      end
      def error?()
        true
      end
      def error(message = nil, progname = nil, origin = nil, &block)
        if self.alive?()
          self.add(::Logger::ERROR, message, progname, (origin || self), &block)
        end
      end
      def warn?()
        true
      end
      alias :warning? :warn?
      def warn(message = nil, progname = nil, origin = nil, &block)
        if self.alive?()
          self.add(::Logger::WARN, message, progname, (origin || self), &block)
        end
      end
      alias :warning :warn
      def info?()
        true
      end
      def info(message = nil, progname = nil, origin = nil, &block)
        if self.alive?()
          self.add(::Logger::INFO, message, progname, (origin || self), &block)
        end
      end
      def debug?()
        true
      end
      def debug(message = nil, progname = nil, origin = nil, &block)
        if self.alive?()
          self.add(::Logger::DEBUG, message, progname, (origin || self), &block)
        end
      end
    end
    #
    # Provide a Cooperative Processing facility for sessions
    class EventDispatcher
      def initialize(interval=0.333, thread_reservation=100)
        super()
        @reserved_threads = (thread_reservation.to_i || 100)
        @uuid = ::GxG::uuid_generate().to_sym
        @event_queues = {:root => {:events => [], :settings => {:active => true, :portion => 100.0}}}
        @running = false
        @ticking = false
        # Timer format: {:when => Time_Object.to_f, :what => event_frame, :interval => float, :id => uuid.sym}
        @timers = []
        @scheduler = Rufus::Scheduler.new(:max_work_threads => @reserved_threads)
        def @scheduler.on_error(job, error)
          log_error({:error => error, :parameters => {:job => job}})
        end
        @scheduler.pause
        @tick_timer = nil
        @tick_interval = interval
        #
        self
      end
      #
      def running?()
        @running
      end
      #
      def startup()
        @running = true
        if @scheduler.paused?
          @scheduler.resume
        end
        unless @tick_timer
          @tick_timer = @scheduler.every(@tick_interval) do
            tick
          end
        end
        @reserved_threads.times do
          begin
            ::GxG::Engine::reserve_event_descriptor()
          rescue Exception => the_error
            log_error({:error => the_error})
            break
          end
        end
        @running
      end
      #
      def shutdown()
        @running = false
        if @tick_timer
          self.cancel_timer(@tick_timer)
          @tick_timer = nil
          @scheduler.pause
          @reserved_threads.times do
            ::GxG::Engine::release_event_descriptor()
          end
        end
        true
      end
      #
      def tick()
        if @running
          unless @ticking
            @ticking = true
            events = []
            envelope = ::GxG::Engine::event_allocation_envelope()
            if envelope.last >= envelope.first
              prefetch = {}
              @event_queues.keys.each do |the_queue|
                if (@event_queues[(the_queue)][:settings][:active] && @event_queues[(the_queue)][:events].size > 0)
                  ((@event_queues[(the_queue)][:settings][:portion].to_f / 100.0) * envelope.last.to_f).to_i.times do
                    op = @event_queues[(the_queue)][:events].shift
                    if op.respond_to?(:call)
                      (prefetch[(the_queue)] ||= []) << op
                    end
                  end
                end
              end
              #
              prefetch_count = 0
              prefetch.keys.each do |the_queue|
                prefetch_count += prefetch[(the_queue)].size
              end
              #
              while prefetch_count > 0 do
                prefetch.keys.each do |the_queue|
                  op = prefetch[(the_queue)].shift
                  if op
                    events << op
                  end
                  prefetch_count -= 1
                end
              end
              #
            end
            # xxx old version:
            # queues = {}
            # load_size = 0
            # @event_queues.keys.each do |the_queue|
            #   if (@event_queues[(the_queue)][:settings][:active] && @event_queues[(the_queue)][:events].size > 0)
            #     queues[(the_queue)] = {:portion => ((@event_queues[(the_queue)][:settings][:portion].to_f / 100.0) * total_slots.to_f).to_i}
            #     if queues[(the_queue)][:portion] == 0
            #       # Fudging a little here in case of real heavy loads and/or too many queues.
            #       queues[(the_queue)][:portion] = 1
            #     end
            #     queues[(the_queue)][:size] = @event_queues[(the_queue)][:events].size
            #     load_size += queues[(the_queue)][:size]
            #   end
            # end
            # queues.keys.each do |the_queue|
            #   # TODO: devise apportioned event dispatch
            #   queues[(the_queue)][:portion].times do 
            #     op = @event_queues[(the_queue)][:events].shift
            #     if op.respond_to?(:call)
            #       events << op
            #     else
            #       break
            #     end
            #   end
            # end
            #
            events.each do |the_event|
              if the_event
                Thread.new do
                  ::GxG::Engine::reserve_event_descriptor()
                  begin
                    the_event.call()
                  rescue Exception => the_error
                    log_error({:error => the_error})
                  end
                  ::GxG::Engine::release_event_descriptor()
                end
              end
            end
            #
            @ticking = false
          end
        end
      end
      #
      def inspect_timers()
        @scheduler.jobs()
      end
      def inspect_queue(queue=:root)
        @event_queues[(queue)]
      end
      #
      def adjust_event_queue(queue=:root,settings={})
        # RESEARCH: GxG::Events::EventDispatcher.adjust_event_queue : refactor :portion of each queue algo needed.
        unless queue.to_s.to_sym == :root
          if @event_queues[(queue.to_sym)]
            # LATER: Eventually add :portion as valid setting to accept.
            [:active].each do |the_setting|
              if settings[(the_setting.to_sym)]
                new_setting = {}
                # portion adjustment algo here
                new_setting[(the_setting.to_sym)] = settings[(the_setting.to_sym)]
                #
                @event_queues[(queue.to_sym)][:settings].merge!(new_setting)
              end
            end
          else
            puts "Warning: queue #{queue.inspect} does not exist"
            # For Now: just ignore references to non-existent queues. (reconsider later)
            # raise ArgumentError, "Event Queue :#{queue} does not exist to alter"
          end
        end
      end
      #
      def create_event_queue(settings={})
        unless settings.is_a?(Hash)
          raise ArgumentError, "you must provide a Hash as a parameter set"
        end
        queue_name = settings.delete(:name).to_s.to_sym
        if queue_name.to_s.size > 0
          if @event_queues[(queue_name)]
            raise ArgumentError, "Event Queue #{queue_name.inspect} already exists"
          else
            @event_queues[(queue_name)] = {:events => [], :settings => {:active => false, :portion => 0.0}}
            # For Now: simply evenly divide the portions equally, only :root can be 100%.
            even_portion = (100.0 / @event_queues.keys.size.to_f)
            @event_queues.keys.each do |the_queue|
              @event_queues[(the_queue)][:settings][:portion] = (even_portion)
            end
            self.adjust_event_queue(queue_name, settings.merge({:active => true}))
            true
          end
        else
          raise ArgumentError, ":name must be provided for Event Queue"
        end
      end
      #
      def delete_event_queue(queue=nil)
        if queue.to_s.to_sym == :root
          false
        else
          @event_queues.delete(queue)
          # For Now: simply evenly divide the portions equally, only :root can be 100%.
          even_portion = (@event_queues.keys.size.to_f / 100.0)
          @event_queues.keys.each do |the_queue|
            @event_queues[(the_queue)][:settings][:portion] = (even_portion)
          end
          true
        end
      end
      #
      def pause_event_queue(queue=nil)
        unless queue.to_s.to_sym == :root
          self.adjust_event_queue(queue,{:active => true})
        end
      end
      #
      def unpause_event_queue(queue=nil)
        unless queue.to_s.to_sym == :root
          self.adjust_event_queue(queue,{:active => false})
        end
      end
      #
      def post_to_event_queue(queue=:root,the_event=nil)
        if the_event.respond_to?(:call)
          if @event_queues[(queue)]
            @event_queues[(queue)][:events] << the_event
          else
            # issue a warning, and post to :root queue anyways (for now). (link to logger, and output)
            @event_queues[:root][:events] << the_event
          end
        end
      end
      #
      def post_event(queue_name=:root,&block)
        unless @event_queues[(queue_name.to_sym)]
          self.create_event_queue({:name => queue_name.to_sym})
        end
        self.post_to_event_queue(queue_name.to_sym,block)
        true
      end
      # Adding Timers
      # See: https://stackoverflow.com/questions/235504/validating-crontab-entries-with-php
      # Cron REGEX: /^((?:[1-9]?\d|\*)\s*(?:(?:[\/-][1-9]?\d)|(?:,[1-9]?\d)+)?\s*){5}$/
      # Rufus Duration REGEX: /^(-?)([\d\.smhdwy]+)$/
      # at, in, every, cron
      #
      def cancel_timer(timer_reference=nil)
        @scheduler.jobs().each do |the_task|
          if the_task.job_id == timer_reference
            the_task.unschedule
            break
          end
        end
        true
      end
      #
      def at(expression="",&block)
        the_time = nil
        case expression.class
        when ::DateTime
          the_time = expression.to_time()
        when ::Time
          the_time = expression
        when ::String
          the_time = ::Chronic::parse(expression)
          unless the_time
            raise ArgumentError, "Invalid time expression: #{expression.inspect}"
          end
        else
          raise ArgumentError, "Invalid time expression: #{expression.inspect}"
        end
        if the_time
          if block.respond_to?(:call)
            event_frame = Proc.new {
              GxG::Engine.reserve_event_descriptor()
              block.call()
              GxG::Engine.release_event_descriptor()
            }
            @scheduler.at(the_time.iso8601,&event_frame)
          else
            nil
          end
        else
          nil
        end
      end
      #
      def in(expression="", &block)
        if expression.is_a?(::Numeric)
          interval = expression
        else
          if expression.include?(" ")
            # parse to Rufus duration
            duration_type = nil
            interval = nil
            expression.split(" ").each do |entry|
              if duration_type && interval
                break
              else
                if ["s","second", "seconds"].include?(entry)
                  duration_type = "s"
                end
                if ["m","minute", "minutes"].include?(entry)
                  duration_type = "m"
                end
                if ["h","hour", "hours"].include?(entry)
                  duration_type = "h"
                end
                if ["d","day", "days"].include?(entry)
                  duration_type = "d"
                end
                if ["w","week", "weeks"].include?(entry)
                  duration_type = "w"
                end
                if /[-+0-9.,]*/.match(entry).to_s.size > 0
                  if entry.include?(".")
                    interval = entry.to_f
                  else
                    interval = entry.to_i
                  end
                end
              end
            end
            interval = (interval.to_s + duration_type.to_s)
          else
            # Verify standard Rufus expression
            duration_type = expression.split(/[-+0-9.,]*/)[1].to_s
            if ["s","m","h","d","w"].include?(duration_type.downcase)
              interval = /[-+0-9.,]*/.match(expression).to_s.to_i
              if interval > 0
                interval = (interval.to_s + duration_type.to_s)
              else
                raise ArgumentError, "Invalid interval expression: #{expression.inspect}"
              end
            else
              raise ArgumentError, "Invalid interval expression: #{expression.inspect}"
            end
          end
        end
        if block.respond_to?(:call)
          event_frame = Proc.new {
            GxG::Engine.reserve_event_descriptor()
            block.call()
            GxG::Engine.release_event_descriptor()
          }
          @scheduler.in(interval,&event_frame)
        else
          nil
        end
      end
      #
      def every(expression="", &block)
        if expression.is_a?(::Numeric)
          interval = expression
        else
          if expression.include?(" ")
            # parse to Rufus duration
            duration_type = nil
            interval = nil
            expression.split(" ").each do |entry|
              if duration_type && interval
                break
              else
                if ["s","second", "seconds"].include?(entry)
                  duration_type = "s"
                end
                if ["m","minute", "minutes"].include?(entry)
                  duration_type = "m"
                end
                if ["h","hour", "hours"].include?(entry)
                  duration_type = "h"
                end
                if ["d","day", "days"].include?(entry)
                  duration_type = "d"
                end
                if ["w","week", "weeks"].include?(entry)
                  duration_type = "w"
                end
                if /[-+0-9.,]*/.match(entry).to_s.size > 0
                  if entry.include?(".")
                    interval = entry.to_f
                  else
                    interval = entry.to_i
                  end
                end
              end
            end
            the_interval = (interval.to_s + duration_type.to_s)
          else
            # Verify standard Rufus expression
            duration_type = expression.split(/[-+0-9.,]*/)[1].to_s
            if ["s","m","h","d","w"].include?(duration_type.downcase)
              interval = /[-+0-9.,]*/.match(expression).to_s.to_i
              if interval > 0
                the_interval = (interval.to_s + duration_type.to_s)
              else
                raise ArgumentError, "Invalid interval expression: #{expression.inspect}"
              end
            else
              raise ArgumentError, "Invalid interval expression: #{expression.inspect}"
            end
          end
        end
        if block.respond_to?(:call)
          event_frame = Proc.new {
            GxG::Engine.reserve_event_descriptor()
            block.call()
            GxG::Engine.release_event_descriptor()
          }
          @scheduler.every(the_interval,&event_frame)
        else
          nil
        end
      end
      #
      def cron(expression="",&block)
        if /^((?:[1-9]?\d|\*)\s*(?:(?:[\/-][1-9]?\d)|(?:,[1-9]?\d)+)?\s*){5}$/.match(expression)
          if block.respond_to?(:call)
            event_frame = Proc.new {
              GxG::Engine.reserve_event_descriptor()
              block.call()
              GxG::Engine.release_event_descriptor()
            }
            @scheduler.cron(expression,&event_frame)
          else
            nil
          end
        else
          raise ArgumentError, "Invalid CRON expression: #{expression.inspect}"
        end
      end
      #
    end
    #
  end
  #
  module EventManager
    #
    def self.manager_running?()
      result = false
      if $Dispatcher
        result = $Dispatcher.running?
      end
      result
    end
  end
  # ### Re-define the LOG Constant
  if const_defined?(:LOG)
    remove_const(:LOG)
  end
  LOG = ::GxG::Events::LogRing.new()
end
#
module GxG
  CHANNELS = ::GxG::Messages::ChannelManager.new
end
class Object
  #
  def send_message(the_message)
    unless @uuid
      @uuid = ::GxG::uuid_generate.to_s.to_sym
      ::GxG::CHANNELS.create_channel(@uuid)
    end
    ::GxG::CHANNELS.send_message(@uuid, the_message)
    true
  end
  #
  def next_message()
    unless @uuid
      @uuid = ::GxG::uuid_generate.to_s.to_sym
      ::GxG::CHANNELS.create_channel(@uuid)
    end
    ::GxG::CHANNELS.next_message(@uuid)
  end
  #
  def post(the_message)
    unless @uuid
      @uuid = ::GxG::uuid_generate.to_s.to_sym
      ::GxG::CHANNELS.create_channel(@uuid)
    end
    channel = ::GxG::CHANNELS.fetch_channel(@uuid)
    if channel 
      channel.write(the_message)
    end
    true
  end
end