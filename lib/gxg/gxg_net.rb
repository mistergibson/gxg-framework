module GxG
  module Networking
    #
    def self.buffer_limits(direction=:in, whatfor=nil)
      limits = GxG::SYSTEM.memory_limits()[:buffers]
      result = {:initial=>0, :valid=>0..0}
#      unless whatfor.is_a?(::Symbol)
#        # :unknown will play it safe with :socket buffer limits
#        whatfor = :socket
#        #
#        if self.is_any?(::UNIXServer, ::UNIXSocket, ::Socket)
#          whatfor = :socket
#        else
#          if self.is_any?(::TCPServer, ::SOCKSocket, ::TCPSocket)
#            whatfor = :tcp
#          else
#            if self.is_any?(::UDPServer, ::UDPSource, ::UDPSocket)
#              whatfor = :udp
#            end
#          end
#        end
#      end
      case whatfor
      when :socket
        if direction == :in
          result = limits[:socket][:ipc][:read].clone
        else
          result = limits[:socket][:ipc][:write].clone
        end
      when :tcp
        if direction == :in
          result = limits[:ipv4][:tcp][:read].clone
        else
          result = limits[:ipv4][:tcp][:write].clone
        end
      when :udp
        if direction == :in
          result = limits[:ipv4][:udp][:read].clone
        else
          result = limits[:ipv4][:udp][:write].clone
        end
      end
      result
    end
  end
end
# WRONG Direction : there for pickings - eventually deleted.
## Tier 2 Augmentation:  networking classes
##
#class BasicSocket
#  #
#  protected
#  include ::GxG::Support::Library::Transcoding
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#  def self.open(*args,&block)
#    if block.respond_to?(:call)
#      block.call(new(*args))
#    else
#      new(*args)
#    end
#  end
#  #
#  # alias :original_method :method
#  #
#  def initialize(*args)
#    # 
#    super(*args)
#  end
#  #
#  def signature()
#    @signature.dup
#  end
#  #
#  def signature=(sig)
#    if sig.is_a?(::String)
#      sig = sig.hash
#    end
#    if sig.is_a?(::Numeric)
#      @signature = sig.to_i
#    else
#      @signature = sig.to_s.hash
#    end
#    @signature.dup
#  end
#  #
#  def unbind_reason()
#    @unbind_reason
#  end
#  #
#  def unbind_reason=(reason)
#    @unbind_reason = reason
#  end
#  #
#  def buffer_limits(direction=:in, whatfor=nil)
#    limits = GxG::SYSTEM.memory_limits()[:buffers]
#    result = {:initial=>0, :valid=>0..0}
#    unless whatfor.is_a?(::Symbol)
#      # :unknown will play it safe with :socket buffer limits
#      whatfor = :socket
#      #
#      if self.is_any?(::UNIXServer, ::UNIXSocket, ::Socket)
#        whatfor = :socket
#      else
#        if self.is_any?(::TCPServer, ::SOCKSocket, ::TCPSocket)
#          whatfor = :tcp
#        else
#          if self.is_any?(::UDPServer, ::UDPSource, ::UDPSocket)
#            whatfor = :udp
#          end
#        end
#      end
#    end
#    case whatfor
#    when :socket
#      if direction == :in
#        result = limits[:socket][:ipc][:read].dup
#      else
#        result = limits[:socket][:ipc][:write].dup
#      end
#    when :tcp
#      if direction == :in
#        result = limits[:ipv4][:tcp][:read].dup
#      else
#        result = limits[:ipv4][:tcp][:write].dup
#      end
#    when :udp
#      if direction == :in
#        result = limits[:ipv4][:udp][:read].dup
#      else
#        result = limits[:ipv4][:udp][:write].dup
#      end
#    end
#    result
#  end
#  #
#  def passes_needed(size_used=0, container_limit=0)
#    needed_raw = size_used.to_f / container_limit.to_f
#    overhang = needed_raw - needed_raw.to_i.to_f
#    needed_raw = needed_raw.to_i.to_f
#    if overhang > 0.0
#      needed_raw += 1.0
#    end
#    needed_raw.to_i
#  end
#  #
#  def receive_to_buffer(options={:propogate => false})
#    unless self.closed?()
#      unless options.is_a?(::Hash)
#        options={:propogate => false}
#      end
#      if @halt_receive_to_buffer == true
#        @halt_receive_to_buffer = false
#      else
#        data = self.recv().to_s
#        if data.bytesize() > 0
#          @in_buffer.string << data
#        end
#        while data.bytesize() > 0
#          data = self.recv().to_s
#          if data.bytesize() > 0
#            @in_buffer.string << data
#          end
#          pause
#        end
#        if GxG::EventManager::manager_running?()[:result]
#          if options[:propogate]
#            if options[:interval].is_a?(::Numeric)
#              ::GxG::EventManager::post_event(Proc.new { pause({:interval => options[:interval]});self.receive_to_buffer(options) })
#            else
#              ::GxG::EventManager::post_event(Proc.new { self.receive_to_buffer(options) })
#            end
#          end
#        end
#      end
#    end
#  end
#  #
#  def halt_receive_to_buffer()
#    @halt_receive_to_buffer = true
#  end
#  #
#end
##
#class UNIXSocket
#  #
#  alias :original_recvfrom :recvfrom
#  alias :original_recvfrom_nonblock :recvfrom
#  alias :recvfrom_nonblock :recvfrom
#  #
#  # alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  # alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketIORecvFrom
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class UNIXServer
#  #
#  alias :original_recvfrom :recvfrom
#  alias :original_recvfrom_nonblock :recvfrom
#  alias :recvfrom_nonblock :recvfrom
#  #
#  # alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  # alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketIORecvFrom
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class Socket
#  #
#  # alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  # alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class IPSocket
#  #
#  # alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  # alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class TCPSocket
#  #
#  alias :original_recvfrom :recvfrom
#  alias :original_recvfrom_nonblock :recvfrom
#  alias :recvfrom_nonblock :recvfrom
#  #
#  alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketIORecvFrom
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class TCPServer
#  #
#  alias :original_recvfrom :recvfrom
#  alias :original_recvfrom_nonblock :recvfrom
#  alias :recvfrom_nonblock :recvfrom
#  #
#  alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketIORecvFrom
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class UDPSocket
#  #
#  alias :original_recvfrom :recvfrom
#  alias :original_recvfrom_nonblock :recvfrom_nonblock
#  #
#  alias :original_recvmsg :recvmsg
#  alias :original_recv :recv
#  alias :original_sendmsg :sendmsg
#  alias :original_send :send
#  #
#  include ::GxG::Support::Library::SocketIO
#  # Since in binary mode, transcoding itself is useless, but other compatibility and object type-casting benefits if included.
#  include ::GxG::Support::Library::TranscodingIO
#  #
#  include ::GxG::Support::Library::SocketIORecvFrom
#  #
#  include ::GxG::Support::Library::SocketRW
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
#class UDPServer < ::UDPSocket
#  #
#  def initialize(the_host_ip, the_port)
#    #
#    @interface = Addrinfo.udp(the_host_ip, the_port)
#    if ::GxG::SYSTEM.network_port_used?(@interface.ip_address(),@interface.ip_port())
#      raise Errno::EADDRINUSE, "#{@interface.ip_address()}:#{@interface.ip_port()} is already in use"
#    end
#    #
#    if @interface.ipv6?()
#      super(::Socket::AF_INET6)
#    else
#      super(::Socket::AF_INET)
#    end
#    self.bind(@interface.ip_address(),@interface.ip_port())
#    #
#    unless ::GxG::SYSTEM.network_port_used?(@interface.ip_address(),@interface.ip_port())
#      raise Errno::EADDRNOTAVAIL, "#{@interface.ip_address()}:#{@interface.ip_port()} could not be bound properly"
#    end
#    #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#  end
#end
##
#class SOCKSocket
#  #
#  public
#  #
#  def self.new(*args)
#    #
#    allocate.instance_eval do
#      @signature = nil
#      # UUIDTools::UUID::random_create.to_s.hash
#      #
#      @in_buffer = ::StringIO.new("",::IO::RDWR)
#      @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
#      @out_buffer = ""
#      @out_buffer.force_encoding(::Encoding::ASCII_8BIT)
#      @unbind_reason = nil
#      @remote_closed = false
#      #
#      @before_receive_data = nil
#      @after_receive_data = nil
#      @before_send_data = nil
#      @after_send_data = nil
#      #
#      @halt_receive_to_buffer = false
#      #
#      initialize(*args)
#      #
#      # Socket IO *should* be set to non-blocking IO me thinks
#      self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
#      # post_init
#      #
#      unless @signature
#        # define signature based upon IO.fileno, then add, based upon class, to connection list or acceptor list for servers.
#        # ::EventMachine::gxg_add_connection / ::EventMachine::gxg_add_acceptor
#      end
#      self
#    end
#  end
#  #
#end
##
## ### Networking Section of GxG
#module GxG
#  #
#  module Networking
#    def self.buffer_limits(direction=:in, whatfor=nil)
#      limits = GxG::SYSTEM.memory_limits()[:buffers]
#      result = {:initial=>0, :valid=>0..0}
#      case whatfor
#      when :socket, :ipc
#        if direction == :in
#          result = limits[:socket][:ipc][:read].dup
#        else
#          result = limits[:socket][:ipc][:write].dup
#        end
#      when :inproc, :tcp, :tcp4, :pgm, :epgm
#        if direction == :in
#          result = limits[:ipv4][:tcp][:read].dup
#        else
#          result = limits[:ipv4][:tcp][:write].dup
#        end
#      when :tcp6
#        # TODO: @GxG::Networking::ZMQSocket.buffer_limits : GxG::SYSTEM.memory_limits : for now route to ipv4, need to expand system key set to include ipv6
#        if direction == :in
#          result = limits[:ipv4][:tcp][:read].dup
#        else
#          result = limits[:ipv4][:tcp][:write].dup
#        end
#      when :udp, :udp4, :udp6
#        if direction == :in
#          result = limits[:ipv4][:udp][:read].dup
#        else
#          result = limits[:ipv4][:udp][:write].dup
#        end
#      end
#      result
#    end
#    #
#    def self.passes_needed(size_used=0, container_limit=0)
#      needed_raw = size_used.to_f / container_limit.to_f
#      overhang = needed_raw - needed_raw.to_i.to_f
#      needed_raw = needed_raw.to_i.to_f
#      if overhang > 0.0
#        needed_raw += 1.0
#      end
#      needed_raw.to_i
#    end
#    #
#    # networking classes
#    class UNIXSocket < ::UNIXSocket
#      # when gem is pushed, subclass from Celluloid::IO::UNIXSocket
#    end
#    #
#    class BSDSocket < ::Socket
#      #
#    end
#    #
#    class UNIXServer < ::UNIXServer
#      # when gem is pushed, subclass from Celluloid::IO::UNIXServer
#      #
#      #      def accept()
#      #        ::GxG::Networking::UNIXSocket.new(self.path)
#      #      end
#      #      alias :accept_nonblock :accept
#      #
#    end
#    #
#    class TCPSocket < ::Celluloid::IO::TCPSocket
#      #
#    end
#    #
#    class TCPServer < ::Celluloid::IO::TCPServer
#      #
#    end
#    #
#    class UDPSocket < ::Celluloid::IO::UDPSocket
#      #
#    end
#    #
#    class UDPServer < ::UDPServer
#      #
#    end
#    #
#    class SOCKSocket < ::SOCKSocket
#      #
#    end
#    #
#    class DDPSocket
#      #
#    end
#    #
#    module Protocol
#      #
#      def register(*args)
#        # register(:proto, MyProtoClassPath)
#      end
#      #
#    end
#    #
#    # ### IPC Classes (via ZeroMQ)
#    # require(::File.expand_path(::File.dirname(__FILE__) << "/gxg_ipc.rb"))
#    #
#    #
#  end
#  #
#end
##