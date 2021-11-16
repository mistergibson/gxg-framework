#!/usr/bin/env ruby
require 'ffi-rzmq'
require 'ezmq'
# Patches to EZMQ:
module EZMQ
  class Publisher
    def send(message="", topic='', **options)
      message = "#{ topic } #{ (options[:encode] || @encode).call message }"
      @socket.send_string message
    end
  end
end
# gxg_ipc is there to pick the bones, but will be discarded : use this file.
module GxG
  module Networking
    #
    module ZMQ
      #
      class ZmqContext < ::EZMQ::Context
        #
      end
      #
      @@details = {}
      @@details[:zmq_context] = ::GxG::Networking::ZMQ::ZmqContext.new
      def self.zmq_default_context()
        @@details[:zmq_context]
      end
      #
      def self.zmq_supported_protocols()
        if ::GxG::SYSTEM.platform()[:platform] == :windows
          ["inproc", "tcp", "tcp4", "tcp6", "pgm", "epgm"]
        else
          ["inproc", "ipc", "tcp", "tcp4", "tcp6", "pgm", "epgm"]
        end
      end
      #
      class ZmqAdapter
        # Proposed: {:bind/connect => <URI>, :context => <Context>, :encode => <Proc>, :decode => <Proc>}
        # mode (:bind, :connect) — a mode for the socket.
        # Options Hash:
        #context (ZMQ::Context) — a context to use for this socket (one will be created if not provided).
        #encode (lambda) — how to encode messages.
        #decode (lambda) — how to decode messages.
        #transport (Symbol) — default: :tcp — transport for transport.
        #address (String) — default: '127.0.0.1' — address for endpoint.
        #port (Fixnum) — default: 5555 — port for endpoint.
        def vetted_parameters(params={})
          unless params.is_a?(::Hash)
            raise ArgumentError, "You MUST provide a Hash as parameters."
          end
          if params[:bind]
            # bind
            mode = :bind
          else
            # connect
            mode = :connect
          end
          options = {}
          if params[:context].is_a?(::ZMQ::Context)
            options[:context] = params[:context]
          end
          uri = params[(mode)].clone
          unless uri.port
            uri.port = 5555
          end
          options[:port] = uri.port
          unless uri.is_a?(::URI::Generic)
            raise ArgumentError, "You MUST provide a valid URI to bind or connect to."
          end
          if ::GxG::Networking::ZMQ::zmq_supported_protocols().include?(uri.scheme())
            if mode == :bind
              if ["tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"].include?(uri.scheme())
                uri.resolve_host()
                if ::GxG::SYSTEM.network_port_used?(::Addrinfo::parse(uri))
                  raise Errno::EADDRINUSE, "Address and port already in use: #{uri.to_s}"
                end
              end
            end
          else
            raise Exception, "Unsupported networking protocol: #{uri.scheme().inspect}"
          end
          options[:transport] = uri.scheme.to_s.to_sym
          options[:address] = uri.hostname
          if ["tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"].include?(uri.scheme())
            options[:port] = (uri.port || 5555)
          end
          options[:transport] = uri.scheme.to_s.to_sym
          if params[:encode].respond_to?(:call)
            options[:encode] = params[:encode]
          end
          if params[:decode].respond_to?(:call)
            options[:decode] = params[:decode]
          end
          {:mode => mode, :options => options}
        end
        #
        def open?()
          @open
        end
        #
        def close()
          if @open == true
            @connector.socket.close
            @open = false
            true
          else
            false
          end
        end
        #
        def context()
          if @open == true
            @connector.context()
          end
        end
        #
        def socket()
          if @open == true
            @connector.socket()
          end
        end
        #
        def identity()
          if @open == true
            @connector.socket.identity
          end
        end
        #
        def listen(&block)
          if @open == true
            @connector.listen(&block)
          end
        end
        #
        def receive(**options, &block)
          if @open == true
            @connector.receive(options, &block)
          end
        end
        #
        def send(message="", **options)
          if @open == true
            @connector.send(message.to_s,options)
          end
        end
        #
      end
      #
      class ZmqPair < ZmqAdapter
        #
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Pair.new(params[:mode], params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
      end
      #
      class ZmqPusher < ZmqAdapter
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Pusher.new(params[:mode], params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
      end
      #
      class ZmqPuller < ZmqAdapter
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Puller.new(params[:mode], params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
      end
      #
      class ZmqClient < ZmqAdapter
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Client.new(params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
        def request(message="", **options)
          @connector.request(message.to_s,options)
        end
      end
      #
      class ZmqServer < ZmqAdapter
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Server.new(params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
      end
      #
      class ZmqPublisher < ZmqAdapter
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Publisher.new(params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
        def send(message="", topic='', **options)
          if @open == true
            @connector.send(message.to_s, topic.to_s,options)
          end
        end
        #
      end
      #
      class ZmqSubscriber < ZmqAdapter
        def initialize(params={})
          params = self.vetted_parameters(params)
          @connector = ::EZMQ::Subscriber.new(params[:options])
          @connector.socket.identity = ::Celluloid::UUID::random_generate.to_s
          @open = true
          self
        end
        #
        def subscribe(topic="")
          if @open == true
            @connector.subscribe(topic)
          end
        end
        #
        def unsubscribe(topic="")
          if @open == true
            @connector.unsubscribe(topic)
          end
        end
      end
      #
    end
    #
    # xxx
#    class AbstractZMQSocket
#      # Abstract class, never instantiated
#      def self.supported_protocols()
#        if ::GxG::SYSTEM.platform()[:platform] == :windows
#          ["inproc", "tcp", "tcp4", "tcp6", "pgm", "epgm"]
#        else
#          ["inproc", "ipc", "tcp", "tcp4", "tcp6", "pgm", "epgm"]
#        end
#      end
#      #
#      def initialize(settings={})
#        # {:context => nil, :type => nil, :bind => {:thisone => "", :thatone => ""}, :connect => nil}
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        @thread_safety = ::Mutex.new
#        if settings[:context].is_a?(::ZMQ::Context)
#          @context = settings[:context]
#        else
#          @context = ::GxG::Networking::zmq_context()
#        end
#        if settings[:type].is_a?(::Numeric)
#          @socket = @context.socket(settings[:type])
#        else
#          raise ArgumentError, "you must supply a type for the socket"
#        end
#        @name = ::Celluloid::UUID.random_generate().to_sym
#        socket_id = (settings[:identity] || @name).to_s.dup
#        if socket_id.bytesize() > 255
#          socket_id.force_encoding(::Encoding::ASCII_8BIT)
#          socket_id = socket_id[(0..255)]
#        end
#        @socket.identity = socket_id
#        #
#        @recv_buffer_size = 1024
#        @send_buffer_size = 1024
#        #
#        @bindings = {}
#        if settings[:bind].is_a?(::Hash)
#          #
#          settings[:bind].keys.to_enum(:each).each do |binding_key|
#            if settings[:bind][(binding_key)].is_a?(::URI::Generic)
#              address = settings[:bind][(binding_key)]
#            else
#              address = ::URI::parse(settings[:bind][(binding_key)])
#            end
#            if ::GxG::Networking::AbstractZMQSocket::supported_protocols().include?(address.scheme())
#              address.resolve_host()
#              if ["tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"].include?(address.scheme())
#                if ::GxG::SYSTEM.network_port_used?(::Addrinfo::parse(address))
#                  raise Errno::EADDRINUSE, "Address and port already in use: #{address.to_s}"
#                end
#              end
#              begin
#                @socket.bind(address.to_s)
#                @bindings[(binding_key)] = address
#              rescue Exception
#                @socket.close
#                raise
#              end
#            else
#              raise ArgumentError, "#{address.scheme().to_s} is an unsupported protocol"
#            end
#          end
#          #
#        end
#        #
#        @connections = {}
#        if settings[:connect].is_a?(::Hash)
#          settings[:connect].keys.to_enum(:each).each do |connection_key|
#            if settings[:connect][(connection_key)].is_a?(::URI::Generic)
#              address = settings[:connect][(connection_key)]
#            else
#              address = ::URI::parse(settings[:connect][(connection_key)])
#            end
#            # address = ::URI::parse(settings[:connect][(connection_key)])
#            if ::GxG::Networking::AbstractZMQSocket::supported_protocols().include?(address.scheme())
#              address.resolve_host()
#              unless ::GxG::SYSTEM.network_port_used?(::Addrinfo::parse(address))
#                raise Errno::EADDRNOTAVAIL, "Address and port not bound: #{address.to_s}"
#              end
#              begin
#                @socket.connect(address.to_s)
#                @connections[(connection_key)] = address
#              rescue Exception
#                @socket.close
#                raise
#              end
#            else
#              raise ArgumentError, "#{address.scheme().to_s} is an unsupported protocol"
#            end
#          end
#        end
#        #
#        @recv_buffer_size = this.recv_buffer_size()
#        @send_buffer_size = this.send_buffer_size()
#        #
#        this
#      end
#      #
#      def context()
#        @thread_safety.synchronize { @context }
#      end
#      #
#      def socket()
#        @thread_safety.synchronize { @socket }
#      end
#      #
#      def identity()
#        @socket.identity()
#      end
#      #
#      def recv_buffer_size(*args)
#        #
#        if args.size > 0
#          if args[0].is_a?(::Numeric)
#            the_size = args.first.to_i
#            if the_size > 0
#              valid_min = [16384]
#              valid_max = [65536]
#              [@bindings, @connections].to_enum(:each).each do |the_set|
#                the_set.keys.to_enum(:each).each do |the_terminus|
#                  setting = ::GxG::Networking::buffer_limits(:in, (the_set[(the_terminus)].scheme).to_sym)[:valid]
#                  valid_min << (setting.min)
#                  valid_max << (setting.max)
#                end
#              end
#              if ((valid_min.min)..(valid_max.max)).include?(the_size)
#                @thread_safety.synchronize {
#                  @recv_buffer_size = the_size
#                  @socket.setsockopt(::ZMQ::RCVBUF,the_size)
#                }
#              else
#                raise Exception, "New buffer size #{the_size} is outside acceptable range: #{((valid_min.min)..(valid_max.max)).inspect}"
#              end
#            end
#          end
#        else
#          data = []
#          @thread_safety.synchronize { @socket.getsockopt(::ZMQ::RCVBUF,data) }
#          the_size = (data.first || 0).to_i
#          if the_size == 0
#            # find scheme of connection/binding : the_scheme
#            # buffer_size = (::GxG::Networking::buffer_limits(:out, the_scheme.to_sym)[:initial] || 65536)
#            buffer_sizes = [65536]
#            [@bindings, @connections].to_enum(:each).each do |the_set|
#              the_set.keys.to_enum(:each).each do |the_terminus|
#                buffer_sizes << (::GxG::Networking::buffer_limits(:in, (the_set[(the_terminus)].scheme).to_sym)[:valid].min)
#              end
#            end
#            # FORNOW: use the smallest buffer size found across all bindings and/or connections
#            @thread_safety.synchronize { @recv_buffer_size = buffer_sizes.min }
#          else
#            @thread_safety.synchronize { @recv_buffer_size = the_size }
#          end
#        end
#        @thread_safety.synchronize { @recv_buffer_size.dup }
#      end
#      #
#      def send_buffer_size(*args)
#        #
#        if args.size > 0
#          if args[0].is_a?(::Numeric)
#            the_size = args.first.to_i
#            if the_size > 0
#              valid_min = [16384]
#              valid_max = [65536]
#              [@bindings, @connections].to_enum(:each).each do |the_set|
#                the_set.keys.to_enum(:each).each do |the_terminus|
#                  setting = ::GxG::Networking::buffer_limits(:out, (the_set[(the_terminus)].scheme).to_sym)[:valid]
#                  valid_min << (setting.min)
#                  valid_max << (setting.max)
#                end
#              end
#              if ((valid_min.min)..(valid_max.max)).include?(the_size)
#                @thread_safety.synchronize {
#                  @send_buffer_size = the_size
#                  @socket.setsockopt(::ZMQ::SNDBUF,the_size)
#                }
#              else
#                raise Exception, "New buffer size #{the_size} is outside acceptable range: #{((valid_min.min)..(valid_max.max)).inspect}"
#              end
#            end
#          end
#        else
#          data = []
#          @thread_safety.synchronize { @socket.getsockopt(::ZMQ::SNDBUF,data) }
#          the_size = (data.first || 0).to_i
#          if the_size == 0
#            # find scheme of connection/binding : the_scheme
#            # buffer_size = (::GxG::Networking::buffer_limits(:out, the_scheme.to_sym)[:initial] || 65536)
#            buffer_sizes = [65536]
#            [@bindings, @connections].to_enum(:each).each do |the_set|
#              the_set.keys.to_enum(:each).each do |the_terminus|
#                buffer_sizes << (::GxG::Networking::buffer_limits(:out, (the_set[(the_terminus)].scheme).to_sym)[:valid].min)
#              end
#            end
#            # FORNOW: use the smallest buffer size found across all bindings and/or connections
#            @thread_safety.synchronize { @send_buffer_size = buffer_sizes.min }
#          else
#            @thread_safety.synchronize { @send_buffer_size = the_size }
#          end
#        end
#        @thread_safety.synchronize { @send_buffer_size.dup }
#      end
#      #
#      def binding(binding_key=nil)
#        if binding_key
#          @thread_safety.synchronize { @bindings[(binding_key)] }
#        else
#          @thread_safety.synchronize { @bindings }
#        end
#      end
#      #
#      def bind(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of keyed bind point(s) for the binding"
#        end
#        result = false
#        settings.keys.to_enum(:each).each do |binding_key|
#          if settings[(binding_key)].is_a?(::URI::Generic)
#            address = settings[(binding_key)]
#          else
#            address = ::URI::parse(settings[(binding_key)])
#          end
#          # address = ::URI::parse(settings[(binding_key)])
#          if ::GxG::Networking::AbstractZMQSocket::supported_protocols().include?(address.scheme())
#            address.resolve_host()
#            if ["tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"].include?(address.scheme())
#              if ::GxG::SYSTEM.network_port_used?(::Addrinfo::parse(address))
#                raise Errno::EADDRINUSE, "Address and port already in use: #{address.to_s}"
#              end
#            end
#            begin
#              @thread_safety.synchronize {
#                @socket.bind(address.to_s)
#                @bindings[(binding_key)] = address
#              }
#              result = true
#            rescue Exception
#              @thread_safety.synchronize { @socket.close }
#              raise
#            end
#          else
#            raise ArgumentError, "#{address.scheme().to_s} is an unsupported protocol"
#          end
#        end
#        @recv_buffer_size = this.recv_buffer_size()
#        @send_buffer_size = this.send_buffer_size()
#        #
#        result
#      end
#      #
#      def connection(connection_key=nil)
#        if connection_key
#          @thread_safety.synchronize { @connections[(connection_key)] }
#        else
#          @thread_safety.synchronize { @connections }
#        end
#      end
#      #
#      def connect(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of keyed address(es) for the connection"
#        end
#        result = false
#        settings.keys.to_enum(:each).each do |connection_key|
#          if settings[(connection_key)].is_a?(::URI::Generic)
#            address = settings[(connection_key)]
#          else
#            address = ::URI::parse(settings[(connection_key)])
#          end
#          # address = ::URI::parse(settings[(connection_key)])
#          if ::GxG::Networking::AbstractZMQSocket::supported_protocols().include?(address.scheme())
#            address.resolve_host()
#            if ["tcp", "tcp4", "tcp6"].include?(address.scheme())
#              unless ::GxG::SYSTEM.network_port_used?(::Addrinfo::parse(address))
#                raise Errno::EADDRNOTAVAIL, "Address and port not bound: #{address.to_s}"
#              end
#            end
#            begin
#              @thread_safety.synchronize {
#                @socket.connect(address.to_s)
#                @connections[(connection_key)] = address
#              }
#              result = true
#            rescue Exception
#              @thread_safety.synchronize { @socket.close() }
#              raise
#            end
#          else
#            raise ArgumentError, "#{address.scheme().to_s} is an unsupported protocol"
#          end
#        end
#        @recv_buffer_size = this.recv_buffer_size()
#        @send_buffer_size = this.send_buffer_size()
#        #
#        result
#      end
#      #
#      def close()
#        @thread_safety.synchronize { @socket.close() }
#      end
#      #
#      def triage_strings(data=[])
#        # takes raw output from @socket.recv_strings([]) and separates routing from content
#        result = {:route => [], :content => []}
#        prior_element = nil
#        data.to_enum(:each).each do |the_element|
#          # Empty strings terminate routes -- Do NOT use in payload as parse element
#          if the_element.to_s.size > 0
#            if prior_element.to_s.size > 0
#              result[:content] << prior_element
#            end
#            prior_element = the_element
#          else
#            if prior_element.to_s.size > 0
#              result[:route] << prior_element
#            end
#            prior_element = nil
#          end
#        end
#        if prior_element.to_s.size > 0
#          result[:content] << prior_element
#        end
#        result
#      end
#      #
#      def recv(options={:autojoin => true})
#        unless options.is_a?(::Hash)
#          options = {:autojoin => true}
#        end
#        payload = []
#        # @thread_safety.lock
#        status = @socket.recv_strings(payload,0)
#        if ::ZMQ::Util.resultcode_ok?(status)
#          data = this.triage_strings(payload)
#          if (data[:route].size > 0 || data[:content].size > 0)
#            if options[:autojoin]
#              ::GxG::Events::Message.new({:sender => this, :body => data[:content].join(), :route => data[:route]})
#            else
#              ::GxG::Events::Message.new({:sender => this, :body => data[:content], :route => data[:route]})
#            end
#          else
#            nil
#          end
#        else
#          begin
#            raise Exception, ("ZMQ - " + ::ZMQ::Util.error_string())
#          rescue => the_error
#            log_error({:error => the_error})
#          end
#          nil
#        end
#        # @thread_safety.unlock
#      end
#      #
#      def send(data=nil, route=[])
#        if data
#          # FORNOW: use the smallest buffer size found across all bindings and/or connections
#          buffer_size = @thread_safety.synchronize { @send_buffer_size }
#          payload = []
#          messages = []
#          unless route.is_a?(::Array)
#            route = [(route)]
#          end
#          #
#          if data.is_a?(::GxG::Events::Message)
#            if data.body().is_a?(::String)
#              data = [(data.body())]
#            else
#              data = [(data.body().serialize())]
#            end
#          end
#          if data.is_a?(::String)
#            data = [(data)]
#          end
#          #
#          if route.is_a?(::Array)
#            route.flatten.to_enum(:each).each do |the_route|
#              if the_route.is_a?(::String)
#                payload << the_route.slice_bytes(0..255)
#                payload << ""
#              end
#            end
#          end
#          payload << @socket.identity()
#          payload << ""
#          #
#          if data.is_a?(::Array)
#            data.flatten.to_enum(:each).each do |the_element|
#              if the_element.is_a?(::String)
#                if the_element.size > 0
#                  # Disallow parsing payload with empty strings : used to parse routes
#                  # Break into appropriate buffer size as needed : respect buffer sizes
#                  if the_element.bytesize > buffer_size
#                    length = the_element.bytesize()
#                    passes = ::GxG::Networking::passes_needed(length, buffer_size)
#                    total = (length - 1)
#                    starting = 0
#                    ending = ([length,buffer_size].min - 1)
#                    passes.times do
#                      messages << the_element.slice_bytes(starting..ending)
#                      #
#                      starting = ending + 1
#                      ending = (starting + (buffer_size - 1))
#                      if ending > total
#                        ending = ending - (ending - total)
#                      end
#                    end
#                    #
#                  else
#                    messages << the_element
#                  end
#                end
#              end
#            end
#            if messages.size > 0
#              payload << messages
#              payload.flatten!
#              status = @thread_safety.synchronize { @socket.send_strings(payload) }
#              if status == -1
#                begin
#                  raise Exception, "ZMQ - Message could not be enqueued."
#                rescue => the_error
#                  log_error({:error => the_error, :parameters => {:data => data, :route => route}})
#                end
#              end
#            end
#          end
#          #
#        end
#      end
#      #
#    end
    #
#    class ZMQRouter < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        unless settings[:context].is_a?(::ZMQ::Context)
#          settings[:context] = ::GxG::Networking::zmq_context()
#        end
#        settings[:type] = ::ZMQ::ROUTER
#        bindings = (settings.delete(:bind) || {})
#        super(settings)
#        unless bindings.keys.size > 0
#          bindings[:inproc] = ::URI::parse("inproc://#{@name}")
#        end
#        this.bind(bindings)
#        #
#        this
#      end
#      #
#    end
    #
#    class ZMQDealer < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::DEALER
#        super(settings)
#        #
#        this
#      end
#      #
#    end
    #
#    class ZMQRequest < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::REQ
#        super(settings)
#        #
#        this
#      end
#      #
#    end
    #
#    class ZMQReply < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::REP
#        super(settings)
#        #
#        this
#      end
#      #
#    end
    #
#    class ZMQPuller < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::PULL
#        super(settings)
#        #
#        this
#      end
#      #
#      def send(*args)
#        # no-op
#      end
#      #
#    end
    #
#    class ZMQPusher < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::PUSH
#        super(settings)
#        #
#        this
#      end
#      #
#      def recv()
#        nil
#      end
#      #
#    end
    #
#    class ZMQPair < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::PAIR
#        super(settings)
#        #
#        this
#      end
#      #
#    end
    #
#    class ZMQSubscriber < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::SUB
#        super(settings)
#        @topics = []
#        #
#        this
#      end
#      #
#      def topics()
#        @thread_safety.synchronize { @topics.dup }
#      end
#      #
#      def subscribe_topic(the_topic=nil)
#        the_topic = the_topic.to_s
#        if the_topic.bytesize > 255
#          the_topic = the_topic.slice_bytes(0..255).to_s
#        end
#        if the_topic.bytesize > 0
#          @thread_safety.synchronize {
#            unless @topics.include?(the_topic)
#              @topics << the_topic
#              @socket.setsockopt(::ZMQ::SUBSCRIBE,the_topic)
#            end
#          }
#        end
#      end
#      #
#      def unsubscribe_topic(the_topic=nil)
#        the_topic = the_topic.to_s
#        if the_topic.bytesize > 255
#          the_topic = the_topic.slice_bytes(0..255).to_s
#        end
#        if the_topic.bytesize > 0
#          @thread_safety.synchronize {
#            if @topics.include?(the_topic)
#              @topics.delete(the_topic)
#              @socket.setsockopt(::ZMQ::UNSUBSCRIBE,the_topic)
#            end
#          }
#        end
#      end
#      #
#      def send(*args)
#        # no-op
#      end
#      #
#    end
    #
#    class ZMQPublisher < ::GxG::Networking::AbstractZMQSocket
#      #
#      def initialize(settings={})
#        #
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "you must supply a hash of settings for the socket"
#        end
#        settings[:type] = ::ZMQ::PUB
#        bindings = (settings.delete(:bind) || {})
#        super(settings)
#        unless bindings.keys.size > 0
#          bindings[:inproc] = ::URI::parse("inproc://#{@name}")
#        end
#        this.bind(bindings)
#        #
#        this
#      end
#      #
#      def recv()
#        nil
#      end
#      #
#      def publish(the_data=nil,the_topic=nil)
#        if the_data
#          the_topic = the_topic.to_s
#          if the_topic.bytesize > 255
#            the_topic = the_topic.slice_bytes(0..255).to_s
#          end
#          if the_topic.bytesize > 0
#            this.send(the_data,[(the_topic)])
#          else
#            this.send(the_data)
#          end
#        end
#      end
#    end
    #
#    class ZMQ_RequestReplyBroker < ::GxG::Events::Actor
#      # class ZMQ_RequestReplyBroker is a derivative work based upon: http://zguide.zeromq.org/rb:rrbroker Copyright (c) 2013 iMatix Corporation
#      # accordingly, class ZMQ_RequestReplyBroker is licensed under this license: http://creativecommons.org/licenses/by-sa/3.0/legalcode
#      def initialize(settings={})
#        unless settings.is_a?(::Hash)
#          raise ArgumentError, "You must provide a hash of settings for the Broker."
#        end
#        unless settings[:frontend].is_a?(::URI::Generic)
#          raise ArgumentError, "You must provide a URI as :frontend."
#        end
#        unless settings[:backend].is_a?(::URI::Generic)
#          raise ArgumentError, "You must provide a URI as :backend."
#        end
#        super()
#        #
#        @context = ::GxG::Networking::zmq_context()
#        @frontend = ::GxG::Networking::ZMQRouter.new({:context => @context, :bind => {:frontend => settings[:frontend]}})
#        @backend = ::GxG::Networking::ZMQDealer.new({:context => @context, :bind => {:backend => settings[:backend]}})
#        # @queue = ::ZMQ::Device.new(::ZMQ::QUEUE, @frontend.socket(), @backend.socket())
#        @queue = ::ZMQ::Poller.new
#        @queue.register(@frontend.socket(), ::ZMQ::POLLIN)
#        @queue.register(@backend.socket(), ::ZMQ::POLLIN)
#        #
#        @circulating = false
#        @is_circulating = false
#        @circulate_safety = ::Mutex.new
#        #
#        this.resume_circulating()
#        ::Celluloid::current_actor()
#      end
#      #
#      def terminate()
#        this.halt_circulating()
#        @queue.deregister(@frontend.socket())
#        @queue.deregister(@backend.socket())
#        @frontend.close()
#        @backend.close()
#        #
#        super()
#      end
#      #
#      def circulating?()
#        @circulate_safety.synchronize { @circulating }
#      end
#      #
#      def halt_circulating()
#        @circulate_safety.synchronize { @circulating = false }
#      end
#      #
#      def resume_circulating()
#        unless this.circulating?()
#          @circulate_safety.synchronize { @circulating = true }
#          this.async.circulate
#        end
#      end
#      #
#      def circulate()
#        # Circulate Data as required
#        if this.alive?()
#          front_socket = @frontend.socket()
#          front_id = @frontend.identity()
#          back_socket = @backend.socket()
#          back_id = @frontend.identity()
#          busy = @circulate_safety.synchronize { @is_circulating }
#          while (this.circulating?() && !busy) do
#            #
#            @circulate_safety.synchronize { @is_circulating = true }
#            @circulate_safety.lock
#            #
#            @queue.poll(:blocking)
#            @queue.readables.each do |the_socket|
#              if the_socket === front_socket
#                data = @frontend.triage_strings(the_socket.recv_strings([]))
#                payload = []
#                if (data[:route].size > 0 || data[:content].size > 0)
#                  data[:route].to_enum(:each).each do |the_route|
#                    payload << the_route
#                    payload << ""
#                  end
#                  payload << back_id
#                  payload << ""
#                  payload << data[:content]
#                  payload.flatten!
#                  if payload.size > 0
#                    back_socket.send_strings(payload)
#                  end
#                end
#              end
#              if the_socket === back_socket
#                data = @backend.triage_strings(the_socket.recv_strings([]))
#                payload = []
#                if (data[:route].size > 0 || data[:content].size > 0)
#                  data[:route].to_enum(:each).each do |the_route|
#                    payload << the_route
#                    payload << ""
#                  end
#                  payload << front_id
#                  payload << ""
#                  payload << data[:content]
#                  payload.flatten!
#                  if payload.size > 0
#                    front_socket.send_strings(payload)
#                  end
#                end
#              end
#            end
#            #
#            @circulate_safety.unlock
#            @circulate_safety.synchronize { @is_circulating = false }
#            busy = @circulate_safety.synchronize { @is_circulating }
#            #
#            if this.alive?()
#              if this.circulating?()
#                sleep 0.033
#              end
#            end
#            #
#          end
#        end
#      end
#      #
#    end
    #
    # Deprecated: completely rethink this.
    class ZmqNode
      #
      def initialize(*args)
        #
        @zmq_thread_safety = ::Mutex.new
        @zmq_processing = false
        @zmq_is_processing = false
        @zmq_processing_handler = nil
        @zmq_processing_error_handler = nil
        @zmq_inputs = {}
        @zmq_outputs = {}
        #
        self
      end
      #
      def terminate()
        # Halt any zmq processing first
        this.halt_zmq_processing()
        # Remove any references to input and output sockets
        # Question: should I close all input/output sockets here???
        @zmq_thread_safety.synchronize {
          @zmq_inputs = {}
          @zmq_outputs = {}
        }
        super()
      end
      #
      def zmq_inputs()
        result = {}
        @zmq_thread_safety.synchronize {
          @zmq_inputs.keys.to_enum(:each).each do |the_key|
            result[(the_key)] = @zmq_inputs[(the_key)]
          end
          #
        }
        result
      end
      #
      def add_zmq_input(the_key=nil, the_socket=nil)
        valid = [::GxG::Networking::ZMQPair, ::GxG::Networking::ZMQPuller, ::GxG::Networking::ZMQSubscriber, ::GxG::Networking::ZMQReply, ::GxG::Networking::ZMQRequest]
        #
        unless the_key.is_a?(::Symbol)
          raise ArgumentError, "you need so supply a unique symbol key for the socket"
        end
        if (@zmq_thread_safety.synchronize { @zmq_inputs[(the_key)] })
          raise ArgumentError, "inputs already exists, you need so supply a unique symbol key for the socket"
        end
        unless the_socket.is_any?(valid)
          raise ArgumentError, "you supplied a #{the_socket.class.inspect}, you need so supply one of these as socket type: #{valid.inspect}"
        end
        @zmq_thread_safety.synchronize { @zmq_inputs[(the_key)] = the_socket }
        true
      end
      #
      def remove_zmq_input(the_key=nil)
        #
        result = false
        the_inputs = this.zmq_inputs()
        if the_inputs[(the_key)]
          @zmq_thread_safety.synchronize { @zmq_inputs.delete(the_key) }
          result = true
        end
        result
      end
      #
      def zmq_outputs()
        result = {}
        @zmq_thread_safety.synchronize {
          @zmq_outputs.keys.to_enum(:each).each do |the_key|
            result[(the_key)] = @zmq_outputs[(the_key)]
          end
          #
        }
        result
      end
      #
      def add_zmq_output(the_key=nil, the_socket=nil)
        valid = [::GxG::Networking::ZMQPair, ::GxG::Networking::ZMQPusher, ::GxG::Networking::ZMQPublisher, ::GxG::Networking::ZMQReply, ::GxG::Networking::ZMQRequest]
        #
        unless the_key.is_a?(::Symbol)
          raise ArgumentError, "you need so supply a unique symbol key for the socket"
        end
        if (@zmq_thread_safety.synchronize { @zmq_outputs[(the_key)] })
          raise ArgumentError, "inputs already exists, you need so supply a unique symbol key for the socket"
        end
        unless the_socket.is_any?(valid)
          raise ArgumentError, "you supplied a #{the_socket.class.inspect}, you need so supply one of these as socket type: #{valid.inspect}"
        end
        @zmq_thread_safety.synchronize { @zmq_outputs[(the_key)] = the_socket }
        true
      end
      #
      def remove_zmq_output(the_key=nil)
        #
        result = false
        the_outputs = this.zmq_outputs()
        if the_outputs[(the_key)]
          @zmq_thread_safety.synchronize { @zmq_outputs.delete(the_key) }
          result = true
        end
        result
      end
      #
      def zmq_handler(params={})
        result = {:result => false}
        begin
          unless params.is_a?(:Hash)
            raise ArgumentError, "you must provide a Hash as parameter container"
          end
          if params[:block].respond_to(:call)
            @zmq_thread_safety.synchronize { @zmq_processing_handler = params[:block] }
            result[:result] = true
          else
            raise ArgumentError, "you must provide something that responds to :call with the :block parameter"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => params})
        end
        result
      end
      #
      def zmq_error_handler(params={})
        result = {:result => false}
        begin
          unless params.is_a?(:Hash)
            raise ArgumentError, "you must provide a Hash as parameter container"
          end
          if params[:block].respond_to(:call)
            @zmq_thread_safety.synchronize { @zmq_processing_error_handler = params[:block] }
            result[:result] = true
          else
            raise ArgumentError, "you must provide something that responds to :call with the :block parameter"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => params})
        end
        result
      end
      #
      def zmq_processing?()
        @zmq_thread_safety.synchronize { @zmq_processing }
      end
      #
      def halt_zmq_processing()
        @zmq_thread_safety.synchronize { @zmq_processing = false;@zmq_is_processing = false }
      end
      #
      def resume_zmq_processing()
        unless this.processing?()
          @zmq_thread_safety.synchronize { @zmq_processing = true }
          this.async.zmq_process
        end
      end
      #
      def zmq_process()
        # Process items on the zmq inputs and potentially send things via outputs
        while (this.zmq_processing?() && !(@zmq_thread_safety.synchronize { @zmq_is_processing })) do
          #
          @zmq_thread_safety.synchronize { @zmq_is_processing = true }
          # Process event item
          begin
            my_handler = @zmq_thread_safety.synchronize { @zmq_processing_error_handler }
            begin
              processor = @zmq_thread_safety.synchronize { @zmq_processing_handler }
              if processor.respond_to?(:call)
                processor.call(this, this.zmq_inputs(), this.zmq_outputs())
              end
            rescue Exception => the_error
              # TODO: Revise logging/error-handling system generally, after display manager construction
              this.halt_zmq_processing()
              if my_handler.respond_to?(:call)
                # error handler provided
                my_handler.call({:error => the_error})
              else
                # log error and forget about it
                log_error({:error => the_error})
              end
            end
          rescue Exception => error_handling
            log_error({:error => error_handling})
          end
          #
          @zmq_thread_safety.synchronize { @zmq_is_processing = false }
          if this.alive?()
            if this.zmq_processing?()
              sleep 0.033
            end
          end
          #
        end
        #
      end
      #
    end
    #
  end
end