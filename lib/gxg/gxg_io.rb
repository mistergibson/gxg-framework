# IO Support Library Module & IO Classes ############################################
module GxG
  module Support
    module Library
      #
      module SocketIO
        #
        def sendmsg(data="", flags=0, destination_socket_address=nil, *controls)
          unless self.instance_variable_defined?(:@remote_closed)
            @remote_closed = nil
          end
          unless self.instance_variable_defined?(:@write_latency)
            @write_latency = {:low => nil, :last => nil, :high => nil}
          end
          unless self.instance_variable_defined?(:@before_send_data)
            @before_send_data = nil
          end
          unless self.instance_variable_defined?(:@after_send_data)
            @after_send_data = nil
          end
          if self.fcntl(::Fcntl::F_GETFL,::Fcntl::O_NONBLOCK) & ::Fcntl::O_NONBLOCK == ::Fcntl::O_NONBLOCK
            # on Winderz, just to a buffer sized spoon full until done ??
            if self.closed?()
              raise IOError, "attempting to sendmsg on a closed stream"
            else
              if @remote_closed
                raise Errno::EPIPE
              else
                data = data.to_s
                written_bytes = data.bytesize()
                # process controls:
                if controls.size > 0
                  if controls[0].is_a?(::Socket::AncillaryData)
                    controls = controls[0]
                  else
                    if controls[0].is_a?(::Hash)
                      controls = ::Socket::AncillaryData.new(::Socket::AF_UNIX, (controls[:level] || :SOCKET), (controls[:type] || ::Socket::SCM_RIGHTS), (controls[:data] || self.fileno))
                    else
                      controls.flatten!
                      controls = ::Socket::AncillaryData.new(::Socket::AF_UNIX, (controls[0] || :SOCKET), (controls[1] || ::Socket::SCM_RIGHTS), (controls[2] || self.fileno))
                    end
                  end
                else
                  raise ArgumentError, "you MUST supply ancillary data as a control"
                end
                #
                if self.is_any?(::UNIXServer, ::UNIXSocket, ::Socket)
                  whatfor = :socket
                else
                  if self.is_any?(::TCPServer, ::SOCKSocket, ::TCPSocket)
                    whatfor = :tcp
                  else
                    if self.is_any?(::UDPServer, ::UDPSource, ::UDPSocket)
                      whatfor = :udp
                    end
                  end
                end
                buffer_size = self.buffer_limits(:out,whatfor)[:initial]
                if written_bytes >= buffer_size
                  passes = self.passes_needed(written_bytes, buffer_size)
                else
                  passes = 1
                end
                #
                total = (written_bytes - 1)
                starting = 0
                ending = ([written_bytes,buffer_size].min - 1)
                #
                passes.times do
                  #
                  begin
                    # if remote end closes during write, raise error by setting @remote_closed and breaking loop.
                    reading = self.latency_reading(self.write_latency()) do
                      self.sendmsg_nonblock(data.slice_bytes(starting..ending),flags,destination_socket_address,controls)
                    end
                    @write_latency = reading[:reading]
                    #
                  rescue ::IO::WaitWritable, GxG::IO::IO::WaitWritable, ::Errno::EINTR, ::Errno::EWOULDBLOCK, ::Errno::EAGAIN
                    pause
                    begin
                      selected = ::IO::select(nil,[self],nil,0.010)
                      until selected
                        pause
                        selected = ::IO::select(nil,[self],nil,0.010)
                      end
                    rescue Exception
                      pause
                      retry
                    end
                    retry
                  rescue ::Errno::EPIPE
                    @remote_closed=true
                    break
                  end
                  #
                  starting = ending + 1
                  ending = (starting + (buffer_size - 1))
                  if ending > total
                    ending = ending - (ending - total)
                  end
                end
                if @remote_closed
                  raise Errno::EPIPE
                end
                written_bytes
              end
            end
          else
            if self.closed?()
              raise IOError, "attempting to sendmsg on a closed stream"
            else
              if @remote_closed
                raise Errno::EPIPE
              else
                data = self.transcode_to_external(data)
                written_bytes = data.bytesize()
                # process controls:
                if controls.size > 0
                  if controls[0].is_a?(::Socket::AncillaryData)
                    controls = controls[0]
                  else
                    if controls[0].is_a?(::Hash)
                      controls = ::Socket::AncillaryData.new(::Socket::AF_UNIX, (controls[:level] || :SOCKET), (controls[:type] || ::Socket::SCM_RIGHTS), (controls[:data] || self.fileno))
                    else
                      controls.flatten!
                      controls = ::Socket::AncillaryData.new(::Socket::AF_UNIX, (controls[0] || :SOCKET), (controls[1] || ::Socket::SCM_RIGHTS), (controls[2] || self.fileno))
                    end
                  end
                else
                  raise ArgumentError, "you MUST supply ancillary data as a control"
                end
                #
                if self.is_any?(::UNIXServer, ::UNIXSocket, ::Socket)
                  whatfor = :socket
                else
                  if self.is_any?(::TCPServer, ::SOCKSocket, ::TCPSocket)
                    whatfor = :tcp
                  else
                    if self.is_any?(::UDPServer, ::UDPSource, ::UDPSocket)
                      whatfor = :udp
                    end
                  end
                end
                buffer_size = self.buffer_limits(:out,whatfor)[:initial]
                if written_bytes >= buffer_size
                  passes = self.passes_needed(written_bytes, buffer_size)
                else
                  passes = 1
                end
                #
                total = (written_bytes - 1)
                starting = 0
                ending = ([written_bytes,buffer_size].min - 1)
                #
                passes.times do
                  # if remote end closes during write, raise error.
                  reading = self.latency_reading(self.write_latency()) do
                    self.original_sendmsg(data.slice_bytes(starting..ending),flags,destination_socket_address,controls) or @remote_closed=true
                  end
                  if @remote_closed
                    break
                  else
                    @write_latency = reading[:reading]
                  end
                  starting = ending + 1
                  ending = (starting + (buffer_size - 1))
                  if ending > total
                    ending = ending - (ending - total)
                  end
                end
                if @remote_closed
                  raise Errno::EPIPE
                end
                #
              end
              written_bytes
            end
          end
        end
        #
        def send(data="", flags=0, destination_socket_address=nil, *controls)
          # for now, flags ignored.  LATER: study Socket.send message flags in detail
          unless self.instance_variable_defined?(:@remote_closed)
            @remote_closed = nil
          end
          unless self.instance_variable_defined?(:@write_latency)
            @write_latency = {:low => nil, :last => nil, :high => nil}
          end
          unless self.instance_variable_defined?(:@before_send_data)
            @before_send_data = nil
          end
          unless self.instance_variable_defined?(:@after_send_data)
            @after_send_data = nil
          end
          if self.closed?()
            raise IOError, "attempting to send on a closed stream"
          else
            if @remote_closed
              raise Errno::EPIPE
            else
              data = data.to_s
              length = 0
              if data.bytesize() > 0
                length = data.bytesize()
                # process controls:
                if controls.size > 0
                  if controls[0].is_a?(::Socket::AncillaryData)
                    controls = controls[0]
                  else
                    if controls[0].is_a?(::Hash)
                      controls = ::Socket::AncillaryData.new(::Socket::AF_UNIX, (controls[:level] || :SOCKET), (controls[:type] || ::Socket::SCM_RIGHTS), (controls[:data] || self.fileno))
                    else
                      controls.flatten!
                      controls = ::Socket::AncillaryData.new(::Socket::AF_UNIX, (controls[0] || :SOCKET), (controls[1] || ::Socket::SCM_RIGHTS), (controls[2] || self.fileno))
                    end
                  end
                else
                  controls = nil
                end
                #
                if self.is_any?(::UNIXServer, ::UNIXSocket, ::Socket)
                  whatfor = :socket
                else
                  if self.is_any?(::TCPServer, ::SOCKSocket, ::TCPSocket)
                    whatfor = :tcp
                  else
                    if self.is_any?(::UDPServer, ::UDPSource, ::UDPSocket)
                      whatfor = :udp
                    end
                  end
                end
                buffer_size = self.buffer_limits(:out,whatfor)[:initial]
                if length >= buffer_size
                  passes = self.passes_needed(length, buffer_size)
                else
                  passes = 1
                end
                #
                total = (length - 1)
                starting = 0
                ending = ([length,buffer_size].min - 1)
                #
                passes.times do
                  # if remote end closes during write, raise error.
                  if controls
                    reading = self.latency_reading(self.write_latency()) do
                      self.sendmsg(data.slice_bytes(starting..ending),flags,destination_socket_address,controls) or @remote_closed=true
                    end
                  else
                    if destination_socket_address
                      reading = self.latency_reading(self.write_latency()) do
                        self.original_send(data.slice_bytes(starting..ending),flags,destination_socket_address) or @remote_closed=true
                      end
                    else
                      reading = self.latency_reading(self.write_latency()) do
                        self.original_send(data.slice_bytes(starting..ending),flags) or @remote_closed=true
                      end
                    end
                  end
                  if @remote_closed
                    break
                  else
                    @write_latency = reading[:reading]
                  end
                  starting = ending + 1
                  ending = (starting + (buffer_size - 1))
                  if ending > total
                    ending = ending - (ending - total)
                  end
                end
                #
                if @remote_closed
                  raise Errno::EPIPE
                end
              end
              length
            end
          end
        end
        #
        def recvmsg(max_mesg_length=nil, flags=0, max_control_length=nil, options={})
          # for now, flags ignored.  LATER: study Socket.recv message flags in detail
          if self.fcntl(::Fcntl::F_GETFL,::Fcntl::O_NONBLOCK) & ::Fcntl::O_NONBLOCK == ::Fcntl::O_NONBLOCK
            # on Winderz, just to a buffer sized spoon full until done ??
            if self.closed?()
              raise IOError, "attempting to recvmsg on a closed stream"
            else
              if @before_receive_data.respond_to?(:call)
                @before_receive_data.call()
              end
              begin
                result = self.recvmsg_nonblock(max_mesg_length, flags, max_control_length, options)
                # 
              rescue ::IO::WaitReadable, ::IO::WaitWritable, GxG::IO::IO::WaitReadable, GxG::IO::IO::WaitWritable
                pause
                begin
                  # about 10 ms
                  selected = GxG::IO::IO::select([self],nil,nil,0.010)
                  until selected
                    pause
                    selected = GxG::IO::IO::select([self],nil,nil,0.010)
                  end
                rescue Exception
                  pause
                  retry
                end
                retry
              end
              #
              if result.is_a?(::Array)
                if result[0].is_a?(::String)
                  result[0].force_encoding(::Encoding::ASCII_8BIT)
                end
              end
              if @after_receive_data.respond_to?(:call)
                @after_receive_data.call(result)
              end
            end
          else
            if self.closed?()
              raise IOError, "attempting to recvmsg on a closed stream"
            else
              if @before_receive_data.respond_to?(:call)
                @before_receive_data.call()
              end
              result = self.original_recvmsg(max_mesg_length, flags, max_control_length, options)
              if result.is_a?(::Array)
                if result[0].is_a?(::String)
                  result[0].force_encoding(::Encoding::ASCII_8BIT)
                end
              end
              if @after_receive_data.respond_to?(:call)
                @after_receive_data.call(result)
              end
            end
          end
          result
        end
        #
        def recv(bytecount=nil, flags=0)
          # for now, flags ignored.  LATER: study Socket.recv message flags in detail
          unless self.instance_variable_defined?(:@before_receive_data)
            @before_receive_data = nil
          end
          unless self.instance_variable_defined?(:@after_receive_data)
            @after_receive_data = nil
          end
          unless bytecount.is_a?(::Numeric)
            bytecount = self.buffer_limits(:in,:socket)[:initial]
          end
          unless flags.is_a?(::Numeric)
            flags = 0
          end
          if self.fcntl(::Fcntl::F_GETFL,::Fcntl::O_NONBLOCK) & ::Fcntl::O_NONBLOCK == ::Fcntl::O_NONBLOCK
            # on Winderz, just to a buffer sized spoon full until done ??
            #
            if self.closed?()
              raise IOError, "attempting to recv on a closed stream"
            else
              if @before_receive_data.respond_to?(:call)
                @before_receive_data.call()
              end
              if self.is_any?(::UNIXServer, ::UNIXSocket, ::Socket)
                whatfor = :socket
              else
                if self.is_any?(::TCPServer, ::SOCKSocket, ::TCPSocket)
                  whatfor = :tcp
                else
                  if self.is_any?(::UDPServer, ::UDPSource, ::UDPSocket)
                    whatfor = :udp
                  end
                end
              end
              buffer_size = self.buffer_limits(:in,whatfor)[:initial]
              unless bytecount.is_a?(::Numeric)
                bytecount = buffer_size
              end
              unless flags.is_a?(::Numeric)
                flags = 0
              end
              # millisecond: 1/1000th of a second (reminder)
              read_bytes = 0
              result = ""
              result.force_encoding(::Encoding::ASCII_8BIT)
              chunk = "abc"
              #
              until (read_bytes == bytecount || chunk.bytesize() == 0)
                begin
                  if ((bytecount - read_bytes) < buffer_size)
                    chunk = self.recv_nonblock((bytecount - read_bytes),flags).to_s
                  else
                    chunk = self.recv_nonblock(buffer_size,flags).to_s
                  end
                  read_bytes += chunk.bytesize()
                  if chunk.bytesize() > 0
                    result << chunk
                  end
                  # 
                rescue ::IO::WaitReadable, ::IO::WaitWritable, GxG::IO::IO::WaitReadable, GxG::IO::IO::WaitWritable
                  pause
                  begin
                    # about 10 ms
                    selected = GxG::IO::IO::select([self],nil,nil,0.010)
                    until selected
                      pause
                      selected = GxG::IO::IO::select([self],nil,nil,0.010)
                    end
                  rescue Exception
                    pause
                    retry
                  end
                  retry
                end
                #
                pause
              end
              #
              if @after_receive_data.respond_to?(:call)
                @after_receive_data.call([result,nil,0,nil])
              end
              result
            end
          else
            if self.closed?()
              raise IOError, "attempting to recv on a closed stream"
            else
              if @before_receive_data.respond_to?(:call)
                @before_receive_data.call()
              end
              result = self.original_recv(bytecount.to_i,flags).to_s
              result.force_encoding(::Encoding::ASCII_8BIT)
              if @after_receive_data.respond_to?(:call)
                @after_receive_data.call([result,nil,0,nil])
              end
            end
          end
          result
        end
        #
      end
      #
      module SocketIORecvFrom
        # Note: Allow aliases or existing recvfrom_nonblock to catch method references.
        # Do not define recvfrom_nonblock here.
        def recvfrom(max_mesg_length=nil, flags=0)
          # for now, flags ignored.  LATER: study Socket.recv message flags in detail
          if self.fcntl(::Fcntl::F_GETFL,::Fcntl::O_NONBLOCK) & ::Fcntl::O_NONBLOCK == ::Fcntl::O_NONBLOCK
            # on Winderz, just to a buffer sized spoon full until done ??
            if self.closed?()
              raise IOError, "attempting to recvmsg on a closed stream"
            else
              if @before_receive_data.respond_to?(:call)
                @before_receive_data.call()
              end
              begin
                result = self.recvfrom_nonblock(max_mesg_length, flags)
                # 
              rescue ::IO::WaitReadable, ::IO::WaitWritable, GxG::IO::IO::WaitReadable, GxG::IO::IO::WaitWritable
                pause
                begin
                  # about 10 ms
                  selected = GxG::IO::IO::select([self],nil,nil,0.010)
                  until selected
                    pause
                    selected = GxG::IO::IO::select([self],nil,nil,0.010)
                  end
                rescue Exception
                  pause
                  retry
                end
                retry
              end
              #
              if result.is_a?(::Array)
                if result[0].is_a?(::String)
                  result[0].force_encoding(::Encoding::ASCII_8BIT)
                end
              end
              if @after_receive_data.respond_to?(:call)
                @after_receive_data.call(result)
              end
            end
          else
            if self.closed?()
              raise IOError, "attempting to recvmsg on a closed stream"
            else
              if @before_receive_data.respond_to?(:call)
                @before_receive_data.call()
              end
              result = self.original_recvfrom(max_mesg_length, flags)
              if result.is_a?(::Array)
                if result[0].is_a?(::String)
                  result[0].force_encoding(::Encoding::ASCII_8BIT)
                end
              end
              if @after_receive_data.respond_to?(:call)
                @after_receive_data.call(result)
              end
            end
          end
          result
        end
        #
      end
      #
      module SocketRW
        #
        def eof?()
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          @in_buffer.eof?()
        end
        #
        def pos()
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          @in_buffer.pos()
        end
        #
        def pos=(*args)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          @in_buffer.pos = args[0]
        end
        #
        def lineno()
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          @in_buffer.lineno()
        end
        #
        def lineno=(*args)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          @in_buffer.lineno = args[0]
        end
        #
        def rewind()
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          @in_buffer.rewind()
        end
        #
        def getbyte()
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          result = @in_buffer.getbyte()
          if @in_buffer.eof?()
            @in_buffer.rewind
            @in_buffer.string.clear
          end
          result
        end
        #
        def getc(*args)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          result = @in_buffer.getc(*args)
          if @in_buffer.eof?()
            @in_buffer.rewind
            @in_buffer.string.clear
          end
          result
        end
        #
        def gets(*args)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          result = @in_buffer.gets(*args)
          if @in_buffer.eof?()
            @in_buffer.rewind
            @in_buffer.string.clear
          end
          result
        end
        #
        def each_char(&block)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          result = @in_buffer.each_char(&block)
          if @in_buffer.eof?()
            @in_buffer.rewind
            @in_buffer.string.clear
          end
          result
        end
        #
        def each_line(*args, &block)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          result = @in_buffer.each_line(*args, &block)
          if @in_buffer.eof?()
            @in_buffer.rewind
            @in_buffer.string.clear
          end
          result
        end
        #
        def read(*args)
          unless self.instance_variable_defined?(:@in_buffer)
            @in_buffer = ::StringIO.new("",::IO::RDWR)
            @in_buffer.set_encoding(::Encoding::ASCII_8BIT)
          end
          result = @in_buffer.read(*args)
          if @in_buffer.eof?()
            @in_buffer.rewind
            @in_buffer.string.clear
          end
          result
        end
        alias :read_nonblock :read
        alias :sysread :read
        #
        def readpartial(*args)
          #
          if self.closed_read?
            raise IOError, "not open for reading"
          else
            if self.eof?
              raise EOFError, "end of stream reached"
            else
              result = ""
              result.force_encoding(self.internal_encoding)
              data = self.read(*args)
              if data
                # non-nil
                if data.is_a?(::String)
                  # 'blocking' or not?
                  if (self.eof?() || (data && data.to_s.size > 0))
                    # no pseudo-blocking
                    result << data
                    data = nil
                  else
                    # pseudo-blocking
                    until (self.eof?() || (data && data.to_s.size > 0))
                      data = self.read(*args)
                      # string, buffer, or nil
                      if data
                        #
                        if data.is_a?(::String)
                          if (data && data.to_s.size > 0)
                            result << data
                            data = nil
                            break
                          else
                            if self.eof?()
                              raise EOFError, "end of stream reached"
                            end
                          end
                        else
                          # buffer
                          result = data
                          data = nil
                          break
                        end
                      else
                        if self.eof?()
                          raise EOFError, "end of stream reached"
                        end
                      end
                      #
                      pause
                      #
                    end
                  end
                else
                  # buffer
                  result = data
                end
              else
                if self.eof?()
                  raise EOFError, "end of stream reached"
                end
              end
              #
              if result
                if result.is_a?(::String)
                  if result.bytesize > 0
                    result
                  else
                    nil
                  end
                else
                  # buffer
                  result
                end
              else
                nil
              end
              # 
            end
          end
        end
        #
        def write(data="")
          data = self.transcode_to_external(data)
          written_bytes = data.bytesize()
          self.send(data,0)
          written_bytes
        end
        alias :write_nonblock :write
        alias :syswrite :write
        #
        def <<(*args)
          self.write(*args)
          self
        end
        #
        def ungetbyte()
          raise NotImplementedError, "unget operations not supported on this type of object"
        end
        alias :ungetbytes :ungetbyte
        alias :ungetc :ungetbyte
        alias :ungets :ungetbyte
        #
      end
      #
      module StringIOPrepare
        #
        def process_params_default_object(the_object)
          ""
        end
        def process_params_classes_valid()
          [::String]
        end
        def process_params_classes_error()
          "you MUST specify a String"
        end
      end
      #
      module IOPrepare
        #
        def process_params_default_object(the_object=nil)
          the_object
        end
        def process_params_classes_valid()
          [::IO, ::GxG::IO::IO, ::StringIO, ::GxG::IO::StringIO, ::Numeric]
        end
        def process_params_classes_error()
          "you MUST specify an IO :object or a :file_descriptor Fixnum"
        end
        #
      end
      #
      module CommonIOPrepare
        #
        def process_parameters(*args)
          default_object = nil
          if args[0].is_a?(Hash)
            # GxG style parameters
            raw_params = args[0]
            unless raw_params[:object].is_any?(self.process_params_classes_valid())
              unless raw_params[:file_descriptor].is_any?(self.process_params_classes_valid())
                default_object = self.process_params_default_object((raw_params[:object] || raw_params[:file_descriptor]))
                if default_object
                  raw_params[:object] = default_object
                else
                  raise ArgumentError, (self.class::process_params_classes_error())
                end
              end
            end
            unless raw_params[:mode].is_a?(Array)
              raise ArgumentError, "you MUST specify an Array of :mode flags (as symbols)"
            end
            raw_params[:mode].to_enum.each do |the_mode_flag|
              unless [:read, :write, :readwrite, :create, :overwrite, :truncate, :append, :text, :binary].include?(the_mode_flag)
                raw_params[:mode].delete(the_mode_flag)
              end
            end
            unless (raw_params[:mode].include?(:binary) || raw_params[:mode].include?(:text))
              raw_params[:mode] << :text
            end
          else
            # standard MRI style parameters
            raw_params = {:mode => []}
            if args[0].is_any?(self.process_params_classes_valid())
              if args[0].is_a?(::Numeric)
                raw_params[:file_descriptor] = args[0].to_i
              else
                raw_params[:object] = args[0]
              end
            else
              default_object = self.process_params_default_object(args[0])
              if default_object
                raw_params[:object] = default_object
              else
                raise ArgumentError, (self.class::process_params_classes_error())
              end
            end
            if args[2].is_a?(Hash)
              if args[2][:mode]
                raw_params[:raw_mode] = args[2][:mode]
              end
              if args[2][:binmode]
                raw_params[:mode] << :binary
              else
                unless raw_params[:mode].index(:text)
                  raw_params[:mode] << :text
                end
              end
              extern_encode = nil
              intern_encode = nil
              if args[2][:encoding]
                extern_encode = args[2][:encoding]
                intern_encode = args[2][:encoding]
              end
              if args[2][:external_encoding]
                unless extern_encode
                  extern_encode = args[2][:external_encoding]
                end
              end
              if args[2][:internal_encoding]
                unless intern_encode
                  intern_encode = args[2][:internal_encoding]
                end
              end
              if extern_encode
                raw_params[:external_encoding] = extern_encode
              end
              if intern_encode
                raw_params[:internal_encoding] = intern_encode
              end
              if args[2][:autoclose]
                raw_params[:autoclose] = args[2][:autoclose]
              end
            end
            if args[1].is_any?(String,Numeric)
              if raw_params[:raw_mode]
                raise ArgumentError, "you specify :mode as: 2nd parameter (String || Numeric) or an option in 3rd parameter Hash, but not in both"
              else
                raw_params[:raw_mode] = args[1]
              end
              if raw_params[:raw_mode].is_a?(String)
                mode_parse = raw_params[:raw_mode].split(":")
                mode_spec = mode_parse[0].numeric_values()
                if mode_spec.is_a?(Hash)
                  raw_params[:raw_mode] = mode_spec[:integer]
                else
                  raw_params[:raw_mode] = mode_parse[0]
                end
                #
                if mode_parse.size > 1
                  extern_encode = mode_parse[1]
                  if mode_parse.size > 2
                    intern_encode = mode_parse[2]
                  else
                    intern_encode = nil
                  end
                else
                  extern_encode = nil
                  intern_encode = nil
                end
                # if specified also in options, it is overwritten here by mode inclusion.
                if (extern_encode == intern_encode)
                  if extern_encode
                    # raw_params[:encoding] = extern_encode
                    raw_params[:external_encoding] = extern_encode
                    raw_params[:internal_encoding] = extern_encode
                  end
                else
                  if extern_encode
                    raw_params[:external_encoding] = extern_encode
                  end
                  if intern_encode
                    raw_params[:internal_encoding] = intern_encode
                  end
                end
                #
              else
                # numeric mode arg
                raw_params[:raw_mode] = args[1].to_i
              end
            end
            #
            unless (raw_params[:object] || raw_params[:file_descriptor])
              raise ArgumentError, "you MUST specify an IO :object or a :file_descriptor Fixnum"
            end
            #
            if raw_params[:raw_mode]
              # decipher :raw_mode
              if raw_params[:raw_mode].is_a?(Numeric)
                # Numeric
                if raw_params[:file_descriptor]
                  if (raw_params[:raw_mode] & ::File::RDWR) == ::File::RDWR
                    raw_params[:mode] << :read
                    raw_params[:mode] << :write
                  else
                    if (raw_params[:raw_mode] &  ::File::WRONLY) ==  ::File::WRONLY
                      raw_params[:mode] << :write
                    else
                      if (raw_params[:raw_mode] & ::File::RDONLY) == ::File::RDONLY
                        raw_params[:mode] << :read
                      end
                    end
                  end
                  if (raw_params[:raw_mode] & ::File::TRUNC) == ::File::TRUNC
                    raw_params[:mode] << :overwrite
                  end
                  if (raw_params[:raw_mode] & ::File::APPEND) == ::File::APPEND
                    raw_params[:mode] << :append
                  end
                  if (raw_params[:raw_mode] & ::File::CREAT) == ::File::CREAT
                    raw_params[:mode] << :append
                  end
                else
                  if (raw_params[:raw_mode] & ::IO::RDWR) == ::IO::RDWR
                    raw_params[:mode] << :read
                    raw_params[:mode] << :write
                  else
                    if (raw_params[:raw_mode] &  ::IO::WRONLY) ==  ::IO::WRONLY
                      raw_params[:mode] << :write
                    else
                      if (raw_params[:raw_mode] & ::IO::RDONLY) == ::IO::RDONLY
                        raw_params[:mode] << :read
                      end
                    end
                  end
                  if (raw_params[:raw_mode] & ::IO::TRUNC) == ::IO::TRUNC
                    raw_params[:mode] << :overwrite
                  end
                  if (raw_params[:raw_mode] & ::IO::APPEND) == ::IO::APPEND
                    raw_params[:mode] << :append
                  end
                  if (raw_params[:raw_mode] & ::IO::CREAT) == ::IO::CREAT
                    raw_params[:mode] << :create
                  end
                end
              else
                # String
                unless (raw_params[:mode].include?(:binary) || raw_params[:mode].include?(:text))
                  if raw_params[:raw_mode].to_s.include?("b")
                    raw_params[:mode] << :binary
                  else
                    raw_params[:mode] << :text
                  end
                end
                if raw_params[:raw_mode].to_s.include?("r")
                  raw_params[:mode] << :read
                  if raw_params[:raw_mode].to_s.include?("+")
                    raw_params[:mode] << :write
                  end
                else
                  if raw_params[:raw_mode].to_s.include?("w")
                    raw_params[:mode] << :write
                    raw_params[:mode] << :overwrite
                    if raw_params[:raw_mode].to_s.include?("+")
                      raw_params[:mode] << :read
                    end
                  else
                    if raw_params[:raw_mode].to_s.include?("a")
                      raw_params[:mode] << :write
                      raw_params[:mode] << :append
                      if raw_params[:raw_mode].to_s.include?("+")
                        raw_params[:mode] << :read
                      end
                    end
                  end
                end
              end
              raw_params.delete(:raw_mode)
            end
            #
          end
          #
          if raw_params[:external_encoding]
            unless ::Encoding::constants.include?(raw_params[:external_encoding].to_s.to_sym)
              raise ArgumentError, ":external_encoding :#{raw_params[:external_encoding].to_s} unsupported"
            end
          end
          if raw_params[:internal_encoding]
            unless ::Encoding::constants.include?(raw_params[:internal_encoding].to_s.to_sym)
              raise ArgumentError, ":internal_encoding :#{raw_params[:internal_encoding].to_s} unsupported"
            end
          end
          #
          raw_params
        end
        #
      end
      #
    end
  end
end
#
module GxG
  module IO
    # local input / output objects: Stream, Pipe, File, Device
    # replacement File/Pipe/Socket IO object and methods built upon EM/EM-Synchrony (uses std. IO obj. for low-level work but attempts actual non-blocking)
    # built-in 'non-blocking' does not appear to actually work (looking at you matz)
    # .fd: numeric file descriptor or IO object
    # mode: file mode. a string or an integer
    # opt: hash for specifying mode by name.
    #    :mode
    #
    #
    #Same as mode parameter
    #
    #:external_encoding
    #
    #
    #External encoding for the IO. “-” is a synonym for the default external encoding.
    #
    #:internal_encoding
    #
    #
    #Internal encoding for the IO. “-” is a synonym for the default internal encoding.
    #
    #If the value is nil no conversion occurs.
    #
    #:encoding
    #
    #
    #Specifies external and internal encodings as “extern:intern”.
    #
    #:textmode
    #
    #
    #If the value is truth value, same as “t” in argument mode.
    #
    #:binmode
    #
    #
    #If the value is truth value, same as “b” in argument mode.
    #
    #:autoclose
    #
    #
    #If the value is false, the fd will be kept open after this IO instance gets finalized.
    #
    class IO < ::IO
      # See : http://pleac.sourceforge.net/pleac_ruby/fileaccess.html
      # Also See : http://stackoverflow.com/questions/6701103/understanding-ruby-and-os-i-o-buffering
      # And See : http://ruby.runpaint.org/io
      # 
      # Valid mode values
      @@valid_modes = {:flags => {:io => {}, :tty => {}, :pipe => {}, :socket => {}, :file => {}}, :io =>{}, :tty => {}, :pipe => {}, :socket => {}, :file => {}}
      
      #
      @@valid_modes[:flags][:io][:read] = ::IO::RDONLY
      @@valid_modes[:flags][:io][:write] = ::IO::WRONLY
      @@valid_modes[:flags][:io][:readwrite] = ::IO::RDWR
      @@valid_modes[:flags][:io][:binary] = ::IO::BINARY
      # ### FIX : blows up on Windows -- not defined - FOR NOW SYNC = DSYNC
      @@valid_modes[:flags][:io][:sync] = ::IO::SYNC # no internal buffering -- The file will be opened for synchronous I/O. No write operation will complete until the data has been physically written to disk.
      @@valid_modes[:flags][:io][:dsync] = ::IO::DSYNC # only normal data be synchronized after each write operation, not metadata.
      @@valid_modes[:flags][:io][:rsync] = ::IO::RSYNC # the synchronization of read requests as well as write requests. It must be used with one of IO::SYNC or IO::DSYNC
      @@valid_modes[:flags][:io][:tty] = ::IO::TTY
      @@valid_modes[:flags][:io][:noctty] = ::IO::NOCTTY # If the named file is a terminal device, don’t make it the controlling terminal for the process.
      @@valid_modes[:flags][:io][:duplex] = ::IO::DUPLEX
      @@valid_modes[:flags][:io][:append] = ::IO::APPEND
      @@valid_modes[:flags][:io][:create] = ::IO::CREAT
      @@valid_modes[:flags][:io][:exclusive] = ::IO::EXCL
      @@valid_modes[:flags][:io][:wsplit] = ::IO::WSPLIT
      @@valid_modes[:flags][:io][:wsplit_initialized] = ::IO::WSPLIT_INITIALIZED
      @@valid_modes[:flags][:io][:trunc] = ::IO::TRUNC
      @@valid_modes[:flags][:io][:text] = ::IO::TEXT
      # Note: need to verify this int value before using:
      @@valid_modes[:flags][:io][:setenc_by_bom] = ::IO::SETENC_BY_BOM
      @@valid_modes[:flags][:io][:seek_set] = ::IO::SEEK_SET
      @@valid_modes[:flags][:io][:seek_current] = ::IO::SEEK_CUR
      @@valid_modes[:flags][:io][:seek_end] = ::IO::SEEK_END
      # ### file region locking:
      @@valid_modes[:flags][:io][:shared_lock] = ::IO::LOCK_SH # for reading
      @@valid_modes[:flags][:io][:exclusive_lock] = ::IO::LOCK_EX # for writing (implies blocking)
      @@valid_modes[:flags][:io][:nonblock_lock] = ::IO::LOCK_NB # combine with exclusive_lock for immediate non-blocking lock for writing.
      @@valid_modes[:flags][:io][:unlock] = ::IO::LOCK_UN
      #
      @@valid_modes[:flags][:io][:nonblocking] = ::IO::NONBLOCK # Neither the open() call, nor any other operation will cause the process to block (sleep) on the I/O. This behavior may be defined only for FIFOs.
      @@valid_modes[:flags][:io][:ndelay] = ::IO::NONBLOCK
      @@valid_modes[:flags][:io][:nofollow] = ::IO::NOFOLLOW # Do not follow symlinks.
      @@valid_modes[:flags][:io][:noaccesstime] = ::IO::NOATIME # Do not update the access time (atime) of the file.
      @@valid_modes[:flags][:io][:match_noescape] = ::IO::FNM_NOESCAPE #
      @@valid_modes[:flags][:io][:match_pathname] = ::IO::FNM_PATHNAME #
      @@valid_modes[:flags][:io][:match_dotmatch] = ::IO::FNM_DOTMATCH #
      @@valid_modes[:flags][:io][:match_casefold] = ::IO::FNM_CASEFOLD #
      @@valid_modes[:flags][:io][:match_systemcase] = ::IO::FNM_SYSCASE #
      # ### file modes
      @@valid_modes[:flags][:file][:read] = ::File::RDONLY
      @@valid_modes[:flags][:file][:write] = ::File::WRONLY
      @@valid_modes[:flags][:file][:readwrite] = ::File::RDWR
      @@valid_modes[:flags][:file][:binary] = ::File::BINARY
      @@valid_modes[:flags][:file][:sync] = ::File::SYNC # no internal buffering -- The file will be opened for synchronous I/O. No write operation will complete until the data has been physically written to disk.
      @@valid_modes[:flags][:file][:dsync] = ::File::DSYNC # only normal data be synchronized after each write operation, not metadata.
      @@valid_modes[:flags][:file][:rsync] = ::File::RSYNC # the synchronization of read requests as well as write requests. It must be used with one of IO::SYNC or IO::DSYNC
      @@valid_modes[:flags][:file][:tty] = ::File::TTY
      @@valid_modes[:flags][:file][:noctty] = ::File::NOCTTY
      @@valid_modes[:flags][:file][:duplex] = ::File::DUPLEX
      @@valid_modes[:flags][:file][:append] = ::File::APPEND
      @@valid_modes[:flags][:file][:create] = ::File::CREAT
      @@valid_modes[:flags][:file][:exclusive] = ::File::EXCL
      @@valid_modes[:flags][:file][:wsplit] = ::File::WSPLIT
      @@valid_modes[:flags][:file][:wsplit_initialized] = ::File::WSPLIT_INITIALIZED
      @@valid_modes[:flags][:file][:trunc] = ::File::TRUNC
      @@valid_modes[:flags][:file][:text] = ::File::TEXT
      @@valid_modes[:flags][:file][:setenc_by_bom] = ::File::SETENC_BY_BOM
      @@valid_modes[:flags][:file][:seek_set] = ::File::SEEK_SET
      @@valid_modes[:flags][:file][:seek_current] = ::File::SEEK_CUR
      @@valid_modes[:flags][:file][:seek_end] = ::File::SEEK_END
      # ### file region locking:
      @@valid_modes[:flags][:file][:shared_lock] = ::File::LOCK_SH # for reading
      @@valid_modes[:flags][:file][:exclusive_lock] = ::File::LOCK_EX # for writing (implies blocking)
      @@valid_modes[:flags][:file][:nonblock_lock] = ::File::LOCK_NB # combine with exclusive_lock for immediate non-blocking lock for writing.
      @@valid_modes[:flags][:file][:unlock] = ::File::LOCK_UN
      #
      @@valid_modes[:flags][:file][:nonblocking] = ::File::NONBLOCK
      @@valid_modes[:flags][:file][:ndelay] = ::File::NONBLOCK
      @@valid_modes[:flags][:file][:nofollow] = ::File::NOFOLLOW # Do not follow symlinks.
      @@valid_modes[:flags][:file][:noaccesstime] = ::File::NOATIME # Do not update the access time (atime) of the file.
      @@valid_modes[:flags][:file][:match_noescape] = ::File::FNM_NOESCAPE #
      @@valid_modes[:flags][:file][:match_pathname] = ::File::FNM_PATHNAME #
      @@valid_modes[:flags][:file][:match_dotmatch] = ::File::FNM_DOTMATCH #
      @@valid_modes[:flags][:file][:match_casefold] = ::File::FNM_CASEFOLD #
      @@valid_modes[:flags][:file][:match_systemcase] = ::File::FNM_SYSCASE #
      # Extended IO mode flags
      @@valid_modes[:flags][:io][:write_create] = (@@valid_modes[:flags][:io][:write] | @@valid_modes[:flags][:io][:create] | @@valid_modes[:flags][:io][:exclusive])
      @@valid_modes[:flags][:io][:write_trunc] = (@@valid_modes[:flags][:io][:write] | @@valid_modes[:flags][:io][:trunc])
      @@valid_modes[:flags][:io][:write_append] = (@@valid_modes[:flags][:io][:write] | @@valid_modes[:flags][:io][:append])
      @@valid_modes[:flags][:io][:readwrite_create] = (@@valid_modes[:flags][:io][:readwrite] | @@valid_modes[:flags][:io][:create] | @@valid_modes[:flags][:io][:exclusive])
      @@valid_modes[:flags][:io][:readwrite_trunc] = (@@valid_modes[:flags][:io][:readwrite] | @@valid_modes[:flags][:io][:trunc])
      @@valid_modes[:flags][:io][:readwrite_append] = (@@valid_modes[:flags][:io][:readwrite] | @@valid_modes[:flags][:io][:append])
      @@valid_modes[:flags][:io][:binary_read] = (@@valid_modes[:flags][:io][:read] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:binary_write] = (@@valid_modes[:flags][:io][:write] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:binary_write_create] = (@@valid_modes[:flags][:io][:write_create] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom] | @@valid_modes[:flags][:io][:exclusive])
      @@valid_modes[:flags][:io][:binary_write_trunc] = (@@valid_modes[:flags][:io][:write_trunc] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:binary_write_append] = (@@valid_modes[:flags][:io][:write_append] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:binary_readwrite] = (@@valid_modes[:flags][:io][:readwrite] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:binary_readwrite_create] = (@@valid_modes[:flags][:io][:readwrite_create] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom] | @@valid_modes[:flags][:io][:exclusive])
      @@valid_modes[:flags][:io][:binary_readwrite_trunc] = (@@valid_modes[:flags][:io][:readwrite_trunc] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:binary_readwrite_append] = (@@valid_modes[:flags][:io][:readwrite_append] | @@valid_modes[:flags][:io][:binary] | @@valid_modes[:flags][:io][:setenc_by_bom])
      @@valid_modes[:flags][:io][:text_read] = (@@valid_modes[:flags][:io][:read] | @@valid_modes[:flags][:io][:text])
      @@valid_modes[:flags][:io][:text_write] = (@@valid_modes[:flags][:io][:write] | @@valid_modes[:flags][:io][:text])
      @@valid_modes[:flags][:io][:text_write_create] = (@@valid_modes[:flags][:io][:write_create] | @@valid_modes[:flags][:io][:text] | @@valid_modes[:flags][:io][:exclusive])
      @@valid_modes[:flags][:io][:text_write_trunc] = (@@valid_modes[:flags][:io][:write_trunc] | @@valid_modes[:flags][:io][:text])
      @@valid_modes[:flags][:io][:text_write_append] = (@@valid_modes[:flags][:io][:write_append] | @@valid_modes[:flags][:io][:text])
      @@valid_modes[:flags][:io][:text_readwrite] = (@@valid_modes[:flags][:io][:readwrite] | @@valid_modes[:flags][:io][:text])
      @@valid_modes[:flags][:io][:text_readwrite_create] = (@@valid_modes[:flags][:io][:readwrite_create] | @@valid_modes[:flags][:io][:text] | @@valid_modes[:flags][:io][:exclusive])
      @@valid_modes[:flags][:io][:text_readwrite_trunc] = (@@valid_modes[:flags][:io][:readwrite_trunc] | @@valid_modes[:flags][:io][:text])
      @@valid_modes[:flags][:io][:text_readwrite_append] = (@@valid_modes[:flags][:io][:readwrite_append] | @@valid_modes[:flags][:io][:text])
      # File mode flags
      @@valid_modes[:flags][:file][:write_create] = (@@valid_modes[:flags][:file][:write] | @@valid_modes[:flags][:file][:create] | @@valid_modes[:flags][:file][:exclusive])
      @@valid_modes[:flags][:file][:write_trunc] = (@@valid_modes[:flags][:file][:write] | @@valid_modes[:flags][:file][:trunc])
      @@valid_modes[:flags][:file][:write_append] = (@@valid_modes[:flags][:file][:write] | @@valid_modes[:flags][:file][:append])
      @@valid_modes[:flags][:file][:readwrite_create] = (@@valid_modes[:flags][:file][:readwrite] | @@valid_modes[:flags][:file][:create] | @@valid_modes[:flags][:file][:exclusive])
      @@valid_modes[:flags][:file][:readwrite_trunc] = (@@valid_modes[:flags][:file][:readwrite] | @@valid_modes[:flags][:file][:trunc])
      @@valid_modes[:flags][:file][:readwrite_append] = (@@valid_modes[:flags][:file][:readwrite] | @@valid_modes[:flags][:file][:append])
      @@valid_modes[:flags][:file][:binary_read] = (@@valid_modes[:flags][:file][:read] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:binary_write] = (@@valid_modes[:flags][:file][:write] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:binary_write_create] = (@@valid_modes[:flags][:file][:write_create] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom] | @@valid_modes[:flags][:file][:exclusive])
      @@valid_modes[:flags][:file][:binary_write_trunc] = (@@valid_modes[:flags][:file][:write_trunc] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:binary_write_append] = (@@valid_modes[:flags][:file][:write_append] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:binary_readwrite] = (@@valid_modes[:flags][:file][:readwrite] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:binary_readwrite_create] = (@@valid_modes[:flags][:file][:readwrite_create] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom] | @@valid_modes[:flags][:file][:exclusive])
      @@valid_modes[:flags][:file][:binary_readwrite_trunc] = (@@valid_modes[:flags][:file][:readwrite_trunc] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:binary_readwrite_append] = (@@valid_modes[:flags][:file][:readwrite_append] | @@valid_modes[:flags][:file][:binary] | @@valid_modes[:flags][:file][:setenc_by_bom])
      @@valid_modes[:flags][:file][:text_read] = (@@valid_modes[:flags][:file][:read] | @@valid_modes[:flags][:file][:text])
      @@valid_modes[:flags][:file][:text_write] = (@@valid_modes[:flags][:file][:write] | @@valid_modes[:flags][:file][:text])
      @@valid_modes[:flags][:file][:text_write_create] = (@@valid_modes[:flags][:file][:write_create] | @@valid_modes[:flags][:file][:text] | @@valid_modes[:flags][:file][:exclusive])
      @@valid_modes[:flags][:file][:text_write_trunc] = (@@valid_modes[:flags][:file][:write_trunc] | @@valid_modes[:flags][:file][:text])
      @@valid_modes[:flags][:file][:text_write_append] = (@@valid_modes[:flags][:file][:write_append] | @@valid_modes[:flags][:file][:text])
      @@valid_modes[:flags][:file][:text_readwrite] = (@@valid_modes[:flags][:file][:readwrite] | @@valid_modes[:flags][:file][:text])
      @@valid_modes[:flags][:file][:text_readwrite_create] = (@@valid_modes[:flags][:file][:readwrite_create] | @@valid_modes[:flags][:file][:text] | @@valid_modes[:flags][:file][:exclusive])
      @@valid_modes[:flags][:file][:text_readwrite_trunc] = (@@valid_modes[:flags][:file][:readwrite_trunc] | @@valid_modes[:flags][:file][:text])
      @@valid_modes[:flags][:file][:text_readwrite_append] = (@@valid_modes[:flags][:file][:readwrite_append] | @@valid_modes[:flags][:file][:text])
      # IO modes
      #Mode |  Meaning
      #-----+--------------------------------------------------------
      #"r"  |  Read-only, starts at beginning of file  (default mode).
      #-----+--------------------------------------------------------
      #"r+" |  Read-write, starts at beginning of file.
      #-----+--------------------------------------------------------
      #"w"  |  Write-only, truncates existing file
      #     |  to zero length or creates a new file for writing.
      #-----+--------------------------------------------------------
      #"w+" |  Read-write, truncates existing file to zero length
      #     |  or creates a new file for reading and writing.
      #-----+--------------------------------------------------------
      #"a"  |  Write-only, starts at end of file if file exists,
      #     |  otherwise creates a new file for writing.
      #-----+--------------------------------------------------------
      #"a+" |  Read-write, starts at end of file if file exists,
      #     |  otherwise creates a new file for reading and
      #     |  writing.
      #-----+--------------------------------------------------------
      # "b" |  Binary file mode (may appear with
      #     |  any of the key letters listed above).
      #     |  Suppresses EOL <-> CRLF conversion on Windows. And
      #     |  sets external encoding to ASCII-8BIT unless explicitly
      #     |  specified.
      #-----+--------------------------------------------------------
      # "t" |  Text file mode (may appear with
      #     |  any of the key letters listed above except "b").
      # Valid IO modes
      # Things to remember:
      # tty operates over an fs pipe and appears to use the exact same file modes as a file therefore.
      # Unresolved Questions:
      # 1. :setenc_by_bom : set on io and tty also?  does tty have binary mode?
      # 2. :setenc_by_bom : only set on Windows? or *any* platform?
      # 3. :wsplit & :wsplit_initialize : under what conditions is this actually set to what (io, tty, file), and on what platforms?
      # 5. :sync : applied to io, tty, file?
      # 6. Are :tty, :pipe, and :socket able to use the *exact* same mode codes, or do they differ, and in what ways?
      # 
      # text io modes
      @@valid_modes[:io][:text_read] = {:synonyms => ["r", "rt", "tr", :text_read, @@valid_modes[:flags][:io][:text_read]], :if_exist => @@valid_modes[:flags][:io][:text_read]}
      @@valid_modes[:io][:text_readwrite] = {:synonyms => ["r+","r+t", "tr+", :text_readwrite, @@valid_modes[:flags][:io][:text_readwrite]], :if_exist => @@valid_modes[:flags][:io][:text_readwrite], :if_create => (@@valid_modes[:flags][:io][:text_readwrite] | @@valid_modes[:flags][:io][:readwrite_create])}
      @@valid_modes[:io][:text_write_overwrite] = {:synonyms => ["w","wt", "tw", :text_write, :text_write_overwrite, :text_write_truncate, @@valid_modes[:flags][:io][:text_write_trunc], @@valid_modes[:flags][:io][:text_write_create],(@@valid_modes[:flags][:io][:text_write_trunc] | @@valid_modes[:flags][:io][:text_write_create])], :if_exist => @@valid_modes[:flags][:io][:text_write_trunc], :if_create => @@valid_modes[:flags][:io][:text_write_create]}
      @@valid_modes[:io][:text_readwrite_overwrite] = {:synonyms => ["w+","w+t", "tw+", :text_readwrite_overwrite, :text_readwrite_truncate, @@valid_modes[:flags][:io][:text_readwrite_trunc], @@valid_modes[:flags][:io][:text_readwrite_create], (@@valid_modes[:flags][:io][:text_readwrite_trunc] | @@valid_modes[:flags][:io][:text_readwrite_create])], :if_exist => @@valid_modes[:flags][:io][:text_readwrite_trunc], :if_create => @@valid_modes[:flags][:io][:text_readwrite_create]}
      @@valid_modes[:io][:text_write_append] = {:synonyms => ["a","at", "ta", :text_write_append, @@valid_modes[:flags][:io][:text_write_append], (@@valid_modes[:flags][:io][:text_write_append] | @@valid_modes[:flags][:io][:text_write_create])], :if_exist => @@valid_modes[:flags][:io][:text_write_append], :if_create => @@valid_modes[:flags][:io][:text_write_create]}
      @@valid_modes[:io][:text_readwrite_append] = {:synonyms => ["a+","a+t", "ta+", :text_readwrite_append, @@valid_modes[:flags][:io][:text_readwrite_append], (@@valid_modes[:flags][:io][:text_readwrite_append] | @@valid_modes[:flags][:io][:text_readwrite_create])], :if_exist => @@valid_modes[:flags][:io][:text_readwrite_append], :if_create => @@valid_modes[:flags][:io][:text_readwrite_create]}
      #
      # binary io modes
      @@valid_modes[:io][:binary_read] = {:synonyms => ["rb", "br", :binary_read, @@valid_modes[:flags][:io][:binary_read]], :if_exist => @@valid_modes[:flags][:io][:binary_read]}
      @@valid_modes[:io][:binary_readwrite] = {:synonyms => ["r+b", "br+", :binary_readwrite, @@valid_modes[:flags][:io][:binary_readwrite]], :if_exist => @@valid_modes[:flags][:io][:binary_readwrite], :if_create => (@@valid_modes[:flags][:io][:binary_readwrite] | @@valid_modes[:flags][:io][:readwrite_create])}
      @@valid_modes[:io][:binary_write_overwrite] = {:synonyms => ["wb", "bw", :binary_write, :binary_write_overwrite, :binary_write_truncate, @@valid_modes[:flags][:io][:binary_write_trunc], @@valid_modes[:flags][:io][:binary_write_create], (@@valid_modes[:flags][:io][:binary_write_trunc] | @@valid_modes[:flags][:io][:binary_write_create])], :if_exist => @@valid_modes[:flags][:io][:binary_write_trunc], :if_create => @@valid_modes[:flags][:io][:binary_write_create]}
      @@valid_modes[:io][:binary_readwrite_overwrite] = {:synonyms => ["w+b", "bw+", :binary_readwrite_overwrite, :binary_readwrite_truncate, @@valid_modes[:flags][:io][:binary_readwrite_trunc], @@valid_modes[:flags][:io][:binary_readwrite_create], (@@valid_modes[:flags][:io][:binary_readwrite_trunc] | @@valid_modes[:flags][:io][:binary_readwrite_create])], :if_exist => @@valid_modes[:flags][:io][:binary_readwrite_trunc], :if_create => @@valid_modes[:flags][:io][:binary_readwrite_create]}
      @@valid_modes[:io][:binary_write_append] = {:synonyms => ["ab", "ba", :binary_write_append, @@valid_modes[:flags][:io][:binary_write_append], (@@valid_modes[:flags][:io][:binary_write_append] | @@valid_modes[:flags][:io][:binary_write_create])], :if_exist => @@valid_modes[:flags][:io][:binary_write_append], :if_create => @@valid_modes[:flags][:io][:binary_write_create]}
      @@valid_modes[:io][:binary_readwrite_append] = {:synonyms => ["a+b", "ba+", :binary_readwrite_append, @@valid_modes[:flags][:io][:binary_readwrite_append], (@@valid_modes[:flags][:io][:binary_readwrite_append] | @@valid_modes[:flags][:io][:binary_readwrite_create])], :if_exist => @@valid_modes[:flags][:io][:binary_readwrite_append], :if_create => @@valid_modes[:flags][:io][:binary_readwrite_create]}
      #
      # tty modes
      # is there a 'binary' mode for a tty? seems it would only be text - make sure.
      # @@valid_modes[:tty][:read]
      #
      # pipe modes
      #
      # io and file new valid modes : [:read, :write, :readwrite, :overwrite, :truncate:, :append, :text, :binary]
      #
      # text file modes
      @@valid_modes[:file][:text_read] = {:synonyms => ["r", "rt", "tr", :text_read, @@valid_modes[:flags][:file][:text_read]], :if_exist => @@valid_modes[:flags][:file][:text_read]}
      @@valid_modes[:file][:text_readwrite] = {:synonyms => ["r+","r+t", "tr+", :text_readwrite, @@valid_modes[:flags][:file][:text_readwrite]], :if_exist => @@valid_modes[:flags][:file][:text_readwrite], :if_create => @@valid_modes[:flags][:file][:text_readwrite_create]}
      @@valid_modes[:file][:text_write_overwrite] = {:synonyms => ["w","wt", "tw", :text_write, :text_write_overwrite, :text_write_truncate, @@valid_modes[:flags][:file][:text_write_trunc], @@valid_modes[:flags][:file][:text_write_create],(@@valid_modes[:flags][:file][:text_write_trunc] | @@valid_modes[:flags][:file][:text_write_create])], :if_exist => @@valid_modes[:flags][:file][:text_write_trunc], :if_create => @@valid_modes[:flags][:file][:text_write_create]}
      @@valid_modes[:file][:text_readwrite_overwrite] = {:synonyms => ["w+","w+t", "tw+", :text_readwrite_overwrite, :text_readwrite_truncate, @@valid_modes[:flags][:file][:text_readwrite_trunc], @@valid_modes[:flags][:file][:text_readwrite_create], (@@valid_modes[:flags][:file][:text_readwrite_trunc] | @@valid_modes[:flags][:file][:text_readwrite_create])], :if_exist => @@valid_modes[:flags][:file][:text_readwrite_trunc], :if_create => @@valid_modes[:flags][:file][:text_readwrite_create]}
      @@valid_modes[:file][:text_write_append] = {:synonyms => ["a","at", "ta", :text_write_append, @@valid_modes[:flags][:file][:text_write_append], (@@valid_modes[:flags][:file][:text_write_append] | @@valid_modes[:flags][:file][:text_write_create])], :if_exist => @@valid_modes[:flags][:file][:text_write_append], :if_create => @@valid_modes[:flags][:file][:text_write_create]}
      @@valid_modes[:file][:text_readwrite_append] = {:synonyms => ["a+","a+t", "ta+", :text_readwrite_append, @@valid_modes[:flags][:file][:text_readwrite_append], (@@valid_modes[:flags][:file][:text_readwrite_append] | @@valid_modes[:flags][:file][:text_readwrite_create])], :if_exist => @@valid_modes[:flags][:file][:text_readwrite_append], :if_create => @@valid_modes[:flags][:file][:text_readwrite_create]}
      #
      # binary file modes
      @@valid_modes[:file][:binary_read] = {:synonyms => ["rb", "br", :binary_read, @@valid_modes[:flags][:file][:binary_read]], :if_exist => @@valid_modes[:flags][:file][:binary_read]}
      @@valid_modes[:file][:binary_readwrite] = {:synonyms => ["r+b", "br+", :binary_readwrite, @@valid_modes[:flags][:file][:binary_readwrite]], :if_exist => @@valid_modes[:flags][:file][:binary_readwrite], :if_create => @@valid_modes[:flags][:file][:binary_readwrite_create]}
      @@valid_modes[:file][:binary_write_overwrite] = {:synonyms => ["wb", "bw", :binary_write, :binary_write_overwrite, :binary_write_truncate, @@valid_modes[:flags][:file][:binary_write_trunc], @@valid_modes[:flags][:file][:binary_write_create], (@@valid_modes[:flags][:file][:binary_write_trunc] | @@valid_modes[:flags][:file][:binary_write_create])], :if_exist => @@valid_modes[:flags][:file][:binary_write_trunc], :if_create => @@valid_modes[:flags][:file][:binary_write_create]}
      @@valid_modes[:file][:binary_readwrite_overwrite] = {:synonyms => ["w+b", "bw+", :binary_readwrite_overwrite, :binary_readwrite_truncate, @@valid_modes[:flags][:file][:binary_readwrite_trunc], @@valid_modes[:flags][:file][:binary_readwrite_create], (@@valid_modes[:flags][:file][:binary_readwrite_trunc] | @@valid_modes[:flags][:file][:binary_readwrite_create])], :if_exist => @@valid_modes[:flags][:file][:binary_readwrite_trunc], :if_create => @@valid_modes[:flags][:file][:binary_readwrite_create]}
      @@valid_modes[:file][:binary_write_append] = {:synonyms => ["ab", "ba", :binary_write_append, @@valid_modes[:flags][:file][:binary_write_append], (@@valid_modes[:flags][:file][:binary_write_append] | @@valid_modes[:flags][:file][:binary_write_create])], :if_exist => @@valid_modes[:flags][:file][:binary_write_append], :if_create => @@valid_modes[:flags][:file][:binary_write_create]}
      @@valid_modes[:file][:binary_readwrite_append] = {:synonyms => ["a+b", "ba+", :binary_readwrite_append, @@valid_modes[:flags][:file][:binary_readwrite_append], (@@valid_modes[:flags][:file][:binary_readwrite_append] | @@valid_modes[:flags][:file][:binary_readwrite_create])], :if_exist => @@valid_modes[:flags][:file][:binary_readwrite_append], :if_create => @@valid_modes[:flags][:file][:binary_readwrite_create]}
      #
      # ###
      @@valid_modes.freeze
      # ###
      protected
      #
      def self.valid_modes()
        @@valid_modes
      end
      def self.interpret_mode(params={})
        # [:read, :write, :binary, :sync, :tty, :duplex, :append, :create, :wsplit, :wsplit_initialized, :trunc, :text, :setenc_by_bom]
        #
      end
      def self.valid_mode_set(params={})
        # [:read, :write, :binary, :sync, :tty, :duplex, :append, :create, :wsplit, :wsplit_initialized, :trunc, :text, :setenc_by_bom]
        valid_modes = []
        valid_flags = []
        if params[:binary]
          if params[:read]
            if params[:write]
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:binary_read]
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:binary_readwrite]
            else
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:binary_read]
            end
          else
            if params[:write]
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:binary_write]
            end
          end
        else
          if params[:read]
            if params[:write]
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:text_read]
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:text_readwrite]
            else
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:text_read]
            end
          else
            if params[:write]
              valid_flags << @@valid_modes[:flags][(params[:type] || :io)][:text_write]
            end
          end
        end
        @@valid_modes[(params[:type] || :io)].keys.to_enum.each do |mode_key|
          @@valid_modes[(params[:type] || :io)][(mode_key)][:synonyms].to_enum.each do |synonym|
            if synonym.is_a?(Numeric)
              valid_flags.to_enum.each do |flag|
                if synonym & flag == flag
                  unless valid_modes.include?(@@valid_modes[(params[:type] || :io)][(mode_key)])
                    valid_modes << @@valid_modes[(params[:type] || :io)][(mode_key)]
                  end
                end
              end
            end
          end
        end
        #
        valid_modes
      end
      #
      #
      include ::GxG::Support::Library::IOPrepare
      include ::GxG::Support::Library::CommonIOPrepare
      include ::GxG::Support::Library::Transcoding
      #
      public
      #
      alias :closed_write? :closed?
      alias :closed_read?  :closed?
      #
      include ::GxG::Support::Library::TranscodingIO
      #
      def self.pipe(*args)
        # Goal: make IO.pipe available on ALL platforms a la false-pipe for code portability (via VFS??).  Duplex contains an @input and an @output IO channel
        # pipes are not 'select' able on Winderz, so a faux-pipe must be shimmed in.
        if [:kazoo_os].include?(GxG::SYSTEM.platform[:platform])
          # TODO: GxG::IO::IO::pipe : provide a ring buffer and return read and write endpoint ios for it where the platform does not support it
          # See: https://en.wikipedia.org/wiki/Circular_buffer
          # See also: http://comments.gmane.org/gmane.comp.lang.ruby.io-splice.general/11
          #
        else
          super(*args)
        end
      end
      # Public Instance Methods:
      def external_encoding=(*args)
        #
        unless self.binmode?()
          if args[0].is_any?(::Encoding, ::NilClass)
            #
            if args[0] == ::Encoding::ASCII_8BIT
              self.binmode()
            else
              #              old_data = self.string().dup
              #
              if args[0].is_a?(::Encoding)
                self.set_encoding(args[0])
                if @internal_encoding
                  if @internal_encoding != self.external_encoding
                    # preserve newline settings
                    nl_op = self.newline_option_used(:external)
                    options = {}
                    if nl_op
                      options[(nl_op)] = true
                    end
                    @conversion_options[:external] = ::String::transcoding_options(self.external_encoding,@internal_encoding,options)
                  end
                end
              else
                self.set_encoding(::Encoding.default_external())
              end
              # convert existing data???
              #              if self.external_encoding() != old_data.encoding()
              #                # preserve newline settings
              #                nl_op = self.newline_option_used(:external)
              #                options = {}
              #                if nl_op
              #                  options[(nl_op)] = true
              #                end
              #                old_data.transcode!(self.external_encoding(),options)
              #                #
              #                self.string.replace(old_data)
              #              end
              #
            end
            #
          else
            raise ArgumentError, "Expected an Encoding or NilClass, you provided #{args[0].class}"
          end
        end
        #
      end
      #
      def initialize(*args)
        # Sockets : http://www.tutorialspoint.com/ruby/ruby_socket_programming.htm
        # io.c : http://rxr.whitequark.org/mri/source/io.c?v=1.9.3#8028
        # File Permission Modes : http://www.tutorialspoint.com/ruby/ruby_input_output.htm
        params = self.process_parameters(*args)
        mode_string = ""
        mode_numeric = 0
        if params[:file_descriptor]
          mode_flags = {:binary => ::File::BINARY, :text => ::File::TEXT, :read => ::File::RDONLY, :write => ::File::WRONLY, :readwrite => ::File::RDWR, :create => ::File::CREAT, :overwrite => ::File::TRUNC, :append => ::File::APPEND}
          modes = GxG::IO::IO::valid_mode_set({:type => :file, :read => true, :write => true, :text => true, :binary => true})
        else
          mode_flags = {:binary => ::IO::BINARY, :text => ::IO::TEXT, :read => ::IO::RDONLY, :write => ::IO::WRONLY, :readwrite => ::IO::RDWR, :create => ::IO::CREAT, :overwrite => ::IO::TRUNC, :append => ::IO::APPEND}
          modes = GxG::IO::IO::valid_mode_set({:type => :io, :read => true, :write => true, :text => true, :binary => true})
        end
        the_mode_used = nil
        options = {}
        # :mode
        #Same as mode parameter
        if params[:mode]
          if params[:mode].index(:binary)
            if params[:mode].index(:read)
              if params[:mode].index(:write)
                mode_string = "binary_readwrite"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:readwrite])
              else
                mode_string = "binary_read"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:read])
              end
            else
              if params[:mode].index(:write)
                mode_string = "binary_write"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:write])
              end
            end
          else
            if params[:mode].index(:read)
              if params[:mode].index(:write)
                mode_string = "text_readwrite"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:readwrite])
              else
                mode_string = "text_read"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:read])
              end
            else
              if params[:mode].index(:write)
                mode_string = "text_write"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:write])
              end
            end
          end
          if (params[:mode].index(:overwrite) || params[:mode].index(:truncate) )
            mode_string << "_overwrite"
            mode_numeric = (mode_numeric | mode_flags[:overwrite])
          else
            if params[:mode].index(:append)
              mode_string << "_append"
              mode_numeric = (mode_numeric | mode_flags[:append])
            else
              if params[:mode].index(:create)
                mode_string << "_create"
                mode_numeric = (mode_numeric | mode_flags[:create])
              end
            end
          end
          # [:read, :write, :readwrite, :overwrite, :truncate:, :append, :text, :binary]
          modes.to_enum.each do |mode_entry|
            mode_entry[:synonyms].to_enum.each do |the_synonym|
              if the_synonym.is_a?(Symbol)
                if the_synonym == mode_string.to_sym
                  the_mode_used = mode_entry
                  break
                end
              else
                if the_synonym.is_a?(Numeric)
                  if (the_synonym & mode_numeric == mode_numeric)
                    the_mode_used = mode_entry
                    break
                  end
                end
              end
            end
            if the_mode_used
              break
            end
            #
          end
          if (the_mode_used)
            if params[:file_descriptor]
              # At this point, only fs objects that already exist will be referenced here.
              if (mode_numeric & mode_flags[:create]) == mode_flags[:create]
                if the_mode_used[:if_create]
                  options[:mode] = the_mode_used[:if_create].to_i
                else
                  raise ArgumentError, "you cannot open read-only on a non-existent file system object"
                end
              else
                options[:mode] = the_mode_used[:if_exist].to_i
              end
            else
              # IO-ish object.
              # When the mode of original IO is read only, the mode cannot be changed to be writable. Similarly,
              # the mode cannot be changed from write only to readable.  When such a change is attempted
              # the error is raised in different locations according to the platform.
              if params[:object].is_any?(::IO, GxG::IO::IO)
                if (params[:object].stat.readable? && (params[:mode].include?(:write) || params[:mode].include?(:readwrite)) && (params[:object].stat.writable? == false))
                  raise ArgumentError, "you cannot make a read-only IO writable"
                end
                if (params[:object].stat.writable? && (params[:mode].include?(:read) || params[:mode].include?(:readwrite)) && (params[:object].stat.readable? == false))
                  raise ArgumentError, "you cannot make a write-only IO readable"
                end
                if (params[:object].stat.binmode? && params[:mode].include?(:text))
                  raise ArgumentError, "you cannot make a binary IO text-only"
                end
              else
                unless params[:object].is_any?( ::StringIO, GxG::IO::StringIO)
                  raise ArgumentError, "you MUST specify an IO :object or a :file_descriptor Fixnum"
                end
              end
              #              if params[:mode].include?(:binary)
              #                unless params[:object].binmode?
              #                  params[:object].binmode
              #                end
              #              end
              if (mode_numeric & mode_flags[:create]) == mode_flags[:create]
                if the_mode_used[:if_create]
                  options[:mode] = the_mode_used[:if_create].to_i
                else
                  raise ArgumentError, "you cannot open read-only on a non-existent file system object"
                end
              else
                options[:mode] = the_mode_used[:if_exist].to_i
              end
            end
            #
          else
            modes_list = []
            modes.to_enum.each do |item|
              modes_list << item[:synonyms]
            end
            raise ArgumentError, "#{params[:mode].inspect} is an invalid :mode, use one of the following: #{modes_list.inspect}"
          end
        end
        #
        @conversion_options = {:external => {}, :internal => {}}
        #
        if params[:mode].include?(:binary)
          options[:external_encoding] = ::Encoding::ASCII_8BIT
        else
          if params[:external_encoding].is_a?(::Encoding)
            options[:external_encoding] = params.delete(:external_encoding)
            #:2nd internal_encoding parameter and 3rd parameter optional hash ignored
            # if you want the supplied string's encoding - best to simply pass it on the .new method call params.
          else
            options[:external_encoding] = ::Encoding.default_external
          end
        end
        #
        # if external_encoding is BINARY/ASCII_8BIT - just nullify internal_encoding, and skip external/internal conversion option mapping.
        if params[:mode].include?(:binary)
          @internal_encoding = nil
        else
          if (params[:internal_encoding].is_a?(::Encoding) && params[:internal_encoding] != options[:external_encoding])
            @internal_encoding = params.delete(:internal_encoding)
          else
            @internal_encoding = ::Encoding.default_internal
          end
          #
          if @internal_encoding
            if @internal_encoding != options[:external_encoding]
              if params[:external_conversion]
                # External conversion options will have to be dynamically generated upon transcode_to_external as *any* encoding is possible, not just internal_encoding
                @conversion_options[:external] = ::String::transcode_options(options[:external_encoding],@internal_encoding,params[:external_conversion])
              else
                @conversion_options[:external] = ::String::transcode_options(options[:external_encoding],@internal_encoding)
              end
              #
              if @internal_encoding == ::Encoding::ASCII_8BIT
                #
                if params[:internal_conversion]
                  nl_op = self.newline_option_used(params[:internal_conversion])
                  conv_options = {}
                  if nl_op
                    conv_options[(nl_op)] = true
                  end
                  @conversion_options[:internal] = conv_options
                end
              else
                if params[:internal_conversion]
                  @conversion_options[:internal] = ::String::transcode_options(@internal_encoding,options[:external_encoding],params[:internal_conversion])
                else
                  @conversion_options[:internal] = ::String::transcode_options(@internal_encoding,options[:external_encoding])
                end
              end
              #
            end
          end
          #
        end
        #
        @external_field_separator = nil
        if params[:external_field_separator]
          @external_field_separator = params[:external_field_separator]
        end
        @external_record_separator = nil
        if params[:external_record_separator]
          @external_record_separator = params[:external_record_separator]
        end
        @internal_field_separator = nil
        if params[:internal_field_separator]
          @internal_field_separator = params[:internal_field_separator]
        end
        @internal_record_separator = nil
        if params[:internal_record_separator]
          @internal_record_separator = params[:internal_record_separator]
        end
        #:autoclose
        # If the value is false, the fd will be kept open after this IO instance gets finalized.
        if params[:autoclose]
          options[:autoclose] = params.delete(:autoclose)
        end
        #
        mode_numeric = options.delete(:mode)
        if params[:file_descriptor]
          super(params[:file_descriptor],mode_numeric,options)
        else
          super(params[:object],mode_numeric,options)
        end
        #
        unless params[:object].is_any?(::StringIO, GxG::IO::StringIO)
          self.fcntl(::Fcntl::F_SETFL,::Fcntl::O_NONBLOCK)
        end
        #
        self
      end
      # portable, cross-platform facade for Fcntl (even under Winderz)
      def fcntl(*args)
        # Thanks to Jon Cooper for the find at http://www.mail-archive.com/beanstalk-talk@googlegroups.com/msg01092.html
        #The FD_CLOEXEC flag is part of the POSIX API, which Windows doesn't support,
        #but it does  provide analogous functionality.
        #
        #See http://www.perlmonks.org/index.pl?node_id=574349
        #
        #You can implement a patch with https://github.com/jarib/childprocess/ which
        #appears to provide a consistent facade.
        #
        #See
        #http://rubydoc.info/github/jarib/childprocess/master/ChildProcess#close_on_exec-class_method
        #
        #Cheers,
        #Jon
        #
        # Attribution: https://github.com/jarib for Childprocess work.
        #
        # For Win32 See: http://rxr.whitequark.org/mri/source/win32/win32.c?v=1.9.3#fcntl
        # ... and older stuff at : http://rxr.whitequark.org/mri/source/wince/fcntl.h?v=1.8.7
        # Ruby General Fcntl Stuff: http://ruby-doc.org/stdlib-1.9.3/libdoc/fcntl/rdoc/Fcntl.html
        #
        # ### fcntl commands:
        # F_DUPFD 	Integer 	Positive Integer; -1 on error 	Find the lowest numbered available file descriptor greater than or equal to arg and make it a copy of the receiver’s file descriptor. If arg is omitted, it is assumed to be equal to the receiver’s file descriptor.
        # F_GETFD 	N/A 	File descriptor flags 	Retrieves the associated file descriptor flags. Currently, these are either 0 or FD_CLOEXEC. These flags may be set with F_SETFD.
        # F_GETFL 	N/A 	Integer 	Returns the file status flags, i.e. a bitwise OR of O_APPEND, O_ASYNC, O_DIRECT, etc. O_ACCMODE is a bitmask for extracting the access mode from these flags.
        # F_GETLK 	struct flock * 	N/A 	The argument describes a lock the caller wishes to place on the file. If this is possible, the l_type field of the struct is set to Fcntl::F_UNLCK; otherwise the struct is updated with details of the current lock holder.
        # F_SETFD 	FD_CLOEXEC or 0 	0; -1 on error 	Sets the file descriptor flags to arg.When arg is FD_CLOEXEC, this is equivalent to #close_on_exec=true.
        # F_SETFL 	Integer 	0; -1 on error 	Set the file status flags to arg
        # F_SETLK 	struct flock * 	0; -1 on error. 	When the struct’s l_type field has the value F_RDLCK or F_WRLCK, acquires the lock; when it has the value F_UNLCK, releases the lock.
        # F_SETLKW 	struct flock * 	0; -1 on error. 	Behaves like F_SETLK, except when a conflicting lock is held this call blocks until the lock is released or a signal is caught.
        #
        fcntl_modes = {}
        case GxG::SYSTEM.platform()[:platform]
        when :windows
          #          unless nil
          #            fcntl_modes[:io] = {}
          #          end
          # I *think* as of 1.9.2+ winderz now has fcntl support in ruby code, see: win32.c
          # TODO: test fcntl under Winderz
          super(*args)
        else
          super(*args)
        end
      end
      #
      def read(length=0,outbuffer="")
        if self.fcntl(::Fcntl::F_GETFL,::Fcntl::O_NONBLOCK) & ::Fcntl::O_NONBLOCK == ::Fcntl::O_NONBLOCK
          if outbuffer.is_a?(::String)
            outbuffer = self.transcode_to_internal(outbuffer)
            if self.internal_encoding
              if outbuffer.encoding != self.internal_encoding()
                outbuffer.force_encoding(self.internal_encoding())
              end
            end
          end
          #
          # Attribution: MRI 1.9.3 docs.
          # TODO: research *proper* non-blocking reads and writes
          #read_nonblock just calls the read(2) system call. It causes all errors the
          #read(2) system call causes: Errno::EWOULDBLOCK, Errno::EINTR, etc. The caller
          #should care such errors.
          #
          #If the exception is Errno::EWOULDBLOCK or Errno::AGAIN, it is extended by
          #IO::WaitReadable. So IO::WaitReadable can be used to rescue the exceptions for
          #retrying read_nonblock.
          #
          #read_nonblock causes EOFError on EOF.
          #
          #If the read byte buffer is not empty, read_nonblock reads from the buffer like
          #readpartial. In this case, the read(2) system call is not called.
          #
          #When read_nonblock raises an exception kind of IO::WaitReadable, read_nonblock
          #should not be called until io is readable for avoiding busy loop. This can be
          #done as follows.
          #
          #  # emulates blocking read (readpartial).
          #  begin
          #    result = io.read_nonblock(maxlen)
          #  rescue IO::WaitReadable
          #    IO.select([io])
          #    retry
          #  end
          #
          #Although IO#read_nonblock doesn't raise IO::WaitWritable.
          #OpenSSL::Buffering#read_nonblock can raise IO::WaitWritable. If IO and SSL
          #should be used polymorphically, IO::WaitWritable should be rescued too. See
          #the document of OpenSSL::Buffering#read_nonblock for sample code.
          #
          #Note that this method is identical to readpartial except the non-blocking flag
          #is set.
          # millisecond: 1/1000th of a second (reminder)
          read_bytes = 0
          # unless IO is some other type, use default buffer size
          if (self.tty? || self.stat.pipe?)
            buffer_size = GxG::SYSTEM.memory_limits()[:buffers][:terminal].to_i
          else
            if self.stat.socket?
              buffer_size = GxG::SYSTEM.memory_limits()[:buffers][:socket][:ipc][:read][:initial].to_i
            else
              # assume file
              buffer_size = GxG::SYSTEM.memory_limits()[:buffers][:default].to_i
            end
          end
          #
          until (read_bytes == length)
            begin
              if ((length - read_bytes) < buffer_size)
                outbuffer << self.transcode_to_internal(read_nonblock((length - read_bytes)))
                read_bytes += (length - read_bytes)
              else
                outbuffer << self.transcode_to_internal(read_nonblock(buffer_size))
                read_bytes += buffer_size
              end
              # 
            rescue ::IO::WaitReadable, ::IO::WaitWritable, GxG::IO::IO::WaitReadable, GxG::IO::IO::WaitWritable
              pause
              begin
                # about 10 ms
                selected = GxG::IO::IO::select([self],nil,nil,0.010)
                until selected
                  pause
                  selected = GxG::IO::IO::select([self],nil,nil,0.010)
                end
              rescue Exception
                pause
                retry
              end
              retry
            end
            #
            pause
          end
          #
          outbuffer
        else
          result = self.transcode_to_internal(super(length))
        end
        result
      end
      #
      def readpartial(*args)
        # args[0] maxlen (Fixnum)
        # args[1] (optional) buffer_object
        # Note: use the same approach to pause/retry as IO.read_nonblock.
        #
        # Reads at most maxlen bytes from the I/O stream. It blocks only if ios has no data immediately available. It doesn’t block if some data available.
        # If the optional outbuf argument is present, it must reference a String, which will receive the data. It raises EOFError on end of file.
        # readpartial is designed for streams such as pipe, socket, tty, etc. It blocks only when no data immediately available.
        # This means that it blocks only when following all conditions hold:
        #   the byte buffer in the IO object is empty.
        #   the content of the stream is empty.
        #   the stream is not reached to EOF.
        # When readpartial blocks, it waits data or EOF on the stream. If some data is reached, readpartial returns with the data. If EOF is reached,
        # readpartial raises EOFError.
        # When readpartial doesn’t blocks, it returns or raises immediately. If the byte buffer is not empty, it returns the data in the buffer.
        # Otherwise if the stream has some content, it returns the data in the stream. Otherwise if the stream is reached to EOF, it raises EOFError.
        #
        if self.closed_read?
          raise IOError, "not open for reading"
        else
          if self.eof?
            raise EOFError, "end of stream reached"
          else
            result = ""
            result.force_encoding(self.internal_encoding)
            data = self.read(*args)
            if data
              # non-nil
              if data.is_a?(::String)
                # 'blocking' or not?
                if (self.eof?() || (data && data.to_s.size > 0))
                  # no pseudo-blocking
                  result << data
                  data = nil
                else
                  # pseudo-blocking
                  until (self.eof?() || (data && data.to_s.size > 0))
                    data = self.read(*args)
                    # string, buffer, or nil
                    if data
                      #
                      if data.is_a?(::String)
                        if (data && data.to_s.size > 0)
                          result << data
                          data = nil
                          break
                        else
                          if self.eof?()
                            raise EOFError, "end of stream reached"
                          end
                        end
                      else
                        # buffer
                        result = data
                        data = nil
                        break
                      end
                    else
                      if self.eof?()
                        raise EOFError, "end of stream reached"
                      end
                    end
                    #
                    pause
                    #
                  end
                end
              else
                # buffer
                result = data
              end
            else
              if self.eof?()
                raise EOFError, "end of stream reached"
              end
            end
            #
            if result
              if result.is_a?(::String)
                if result.bytesize > 0
                  result
                else
                  nil
                end
              else
                # buffer
                result
              end
            else
              nil
            end
            # 
          end
        end
      end
      #
      def write(data="")
        if self.fcntl(::Fcntl::F_GETFL,::Fcntl::O_NONBLOCK) & ::Fcntl::O_NONBLOCK == ::Fcntl::O_NONBLOCK
          # on Winderz, just to a buffer sized spoon full until done ??
          # written_bytes = self.write_nonblock(data)
          # TODO: research *proper* non-blocking reads and writes
          data = self.transcode_to_external(data)
          length = data.size
          written_bytes = 0
          # unless IO is some other type, use default buffer size
          if (self.tty? || self.stat.pipe?)
            buffer_size = GxG::SYSTEM.memory_limits()[:buffers][:terminal].to_i
          else
            if self.stat.socket?
              buffer_size = GxG::SYSTEM.memory_limits()[:buffers][:socket][:ipc][:write][:initial].to_i
            else
              # assume file
              buffer_size = GxG::SYSTEM.memory_limits()[:buffers][:default].to_i
            end
          end
          until (written_bytes == length)
            # on Winderz, use self.write(data) ??
            chunk = ""
            chunk.force_encoding(data.encoding)
            if ((written_bytes) + (buffer_size - 1)) > length
              chunk << data.slice((written_bytes),(length - 1))
            else
              chunk << data.slice((written_bytes),((written_bytes) + (buffer_size - 1)))
            end
            #
            begin
              # On some platforms such as Windows, write_nonblock is not supported according
              # to the kind of the IO object. In such cases, write_nonblock raises
              # Errno::EBADF.
              # # write_nonblock writes only 65536 bytes and return 65536.
              # (The pipe size is 65536 bytes on this environment.)
              #  s = "a" * 100000
              #  p w.write_nonblock(s)     #=> 65536
              #
              #  # write_nonblock cannot write a byte and raise EWOULDBLOCK (EAGAIN).
              #  p w.write_nonblock("b")   # Resource temporarily unavailable (Errno::EAGAIN)
              #
              #If the write buffer is not empty, it is flushed at first.
              #
              #When write_nonblock raises an exception kind of IO::WaitWritable,
              #write_nonblock should not be called until io is writable for avoiding busy
              #loop. This can be done as follows.
              #
              # bytes_written = super(data)
              written_bytes += write_nonblock(chunk).to_i
            rescue ::IO::WaitWritable, GxG::IO::IO::WaitWritable, ::Errno::EINTR, ::Errno::EWOULDBLOCK, ::Errno::EAGAIN
              pause
              begin
                selected = GxG::IO::IO::select(nil,[self],nil,0.010)
                until selected
                  pause
                  selected = GxG::IO::IO::select(nil,[self],nil,0.010)
                end
              rescue Exception
                pause
                retry
              end
              retry
            end
            #
            pause
          end
        else
          written_bytes = super(self.transcode_to_external(data))
        end
        written_bytes
      end
      #
      def <<(*args)
        self.write(*args)
        self
      end
      #
      #
    end
    #
    class StringIO < ::StringIO
      # Wrapper class around ::StringIO ensuring cooperative processing, and optional in-line auto-transcoding, on most methods
      #
      protected
      #
      # Protected Instance Methods
      include ::GxG::Support::Library::StringIOPrepare
      include ::GxG::Support::Library::CommonIOPrepare
      include ::GxG::Support::Library::Transcoding
      #
      public
      # Public class methods
      include ::GxG::Support::Library::TranscodingIO
      #
      def self.open(the_string="",mode=::IO::RDWR,&block)
        result = nil
        the_io = GxG::IO::StringIO.new(the_string,mode)
        #
        if block.respond_to?(:call)
          result = block.call(the_io)
          the_io.close
        else
          result = the_io
        end
        #
        result
      end
      #
      # Public instance methods
      def flags()
        result = []
        current = self.fcntl(::Fcntl::F_GETFL)
        flags = {}
        if self.binmode?()
          result << :binary
          if self.external_encoding == ::Encoding::ASCII_8BIT
            result << :setenc_by_bom
          end
        else
          result << :text
          result << :wsplit
        end
        if self.tty?
          result << :tty
        end
        #
        #flag[:read] = 0x00000001
        #flag[:write] = 0x00000002
        #flag[:readwrite] = (flag[:read] | flag[:write])
        #flag[:binmode] = 0x00000004
        #flag[:readwrite] = (flag[:read] | flag[:write])
        flags[:read] = ::Fcntl::O_RDONLY
        flags[:write] = ::Fcntl::O_WRONLY
        flags[:readwrite] =::Fcntl::O_RDWR
        #flags[:binary] = 0x00000004
        flags[:sync] = ::File::SYNC # no internal buffering -- The file will be opened for synchronous I/O. No write operation will complete until the data has been physically written to disk.
        flags[:dsync] = ::File::DSYNC # only normal data be synchronized after each write operation, not metadata.
        flags[:rsync] = ::File::RSYNC # the synchronization of read requests as well as write requests. It must be used with one of IO::SYNC or IO::DSYNC
        #flags[:tty] = 0x00000010
        flags[:notcontrol_tty] = ::Fcntl::O_NOCTTY
        flags[:duplex] = 0x00000020
        flags[:append] = ::Fcntl::O_APPEND
        flags[:create] = ::Fcntl::O_CREAT
        flags[:exclusive] = ::Fcntl::O_EXCL
        # flags[:wsplit] = 0x00000200
        flags[:wsplit_initialized] = 0x00000400
        flags[:trunc] = ::Fcntl::O_TRUNC
        #flags[:text] = 0x00001000
        #flags[:setenc_by_bom] = 0x00100000
        flags[:seek_set] = ::File::SEEK_SET
        flags[:seek_current] = ::File::SEEK_CUR
        flags[:seek_end] = ::File::SEEK_END
        # ### file region locking:
        flags[:shared_lock] = ::File::LOCK_SH # for reading
        flags[:exclusive_lock] = ::File::LOCK_EX # for writing (implies blocking)
        flags[:nonblock_lock] = ::File::LOCK_NB # combine with exclusive_lock for immediate non-blocking lock for writing.
        flags[:unlock] = ::File::LOCK_UN
        #
        flags[:nonblocking] = ::Fcntl::O_NONBLOCK
        flags[:ndelay] = ::Fcntl::O_NDELAY
        # unrelated to in-memory IO-like objects
        #        flags[:nofollow] = ::File::NOFOLLOW # Do not follow symlinks.
        #        flags[:noaccesstime] = ::File::NOATIME # Do not update the access time (atime) of the file.
        #        flags[:match_noescape] = ::File::FNM_NOESCAPE #
        #        flags[:match_pathname] = ::File::FNM_PATHNAME #
        #        flags[:match_dotmatch] = ::File::FNM_DOTMATCH #
        #        flags[:match_casefold] = ::File::FNM_CASEFOLD #
        #        flags[:match_systemcase] = ::File::FNM_SYSCASE #
        #
        flags.keys.to_enum.each do |the_flag_key|
          if (current & flags[(the_flag_key)]) == flags[(the_flag_key)]
            case the_flag_key
            when :readwrite
              if result.index(:write)
                result << :read
              else
                if result.index(:read)
                  result << :write
                end
              end
            when :wsplit_initialized
              if result.index(:wsplit)
                result[(result.index(:wsplit))] = :wsplit_initialized
              else
                result << :wsplit_initialized
              end
            else
              result << the_flag_key
            end
          end
        end
        #
        result
      end
      #
      def initialize(*args)
        # TODO: override methods to operate in cooperative processing event system
        # TODO: provide a REAL external:internal encoding translation aspect (stock version is poorly designed/wrong, it would act *exactly* like a real IO)
        # TODO: optimize this class for memory and call efficiency (see Question at super() call)
        # LATER: GxG::StringIO : create/learn/whatever an optimized any-encoding-to-any-encoding transcoding/normalization matrix : possibly extend Encoding Class? This should include a conversion newline/field_separator/record_separator for each pair of Encodings.
        # Question: is there some possible benefit to using a ByteArray instead of a stock StringIO ?
        params = self.process_parameters(*args)
        unless params[:mode].size > 0
          params[:mode] << :read
          params[:mode] << :write
        end
        if params[:external_encoding] == ::Encoding::ASCII_8BIT
          unless params[:mode].include?(:binary)
            params[:mode] << :binary
          end
        end
        #
        mode_string = ""
        mode_numeric = 0
        @fcntl_mode = ::Fcntl::O_NONBLOCK
        mode_flags = {:binary => ::IO::BINARY, :text => ::IO::TEXT, :read => ::IO::RDONLY, :write => ::IO::WRONLY, :readwrite => ::IO::RDWR, :create => ::IO::CREAT, :overwrite => ::IO::TRUNC, :append => ::IO::APPEND}
        modes = GxG::IO::IO::valid_mode_set({:type => :io, :read => true, :write => true, :text => true, :binary => true})
        the_mode_used = nil
        options = {}
        # :mode
        #Same as mode parameter
        if params[:mode]
          if params[:mode].index(:binary)
            if params[:mode].index(:read)
              if params[:mode].index(:write)
                mode_string = "binary_readwrite"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:readwrite])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_RDWR)
              else
                mode_string = "binary_read"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:read])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_RDONLY)
              end
            else
              if params[:mode].index(:write)
                mode_string = "binary_write"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:write])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_WRONLY)
              end
            end
          else
            if params[:mode].index(:read)
              if params[:mode].index(:write)
                mode_string = "text_readwrite"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:readwrite])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_RDWR)
              else
                mode_string = "text_read"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:read])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_RDONLY)
              end
            else
              if params[:mode].index(:write)
                mode_string = "text_write"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:write])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_WRONLY)
              end
            end
          end
          if (params[:mode].index(:overwrite) || params[:mode].index(:truncate) )
            mode_string << "_overwrite"
            mode_numeric = (mode_numeric | mode_flags[:overwrite])
            @fcntl_mode = (@fcntl_mode | ::Fcntl::O_TRUNC)
          else
            if params[:mode].index(:append)
              mode_string << "_append"
              mode_numeric = (mode_numeric | mode_flags[:append])
              @fcntl_mode = (@fcntl_mode | ::Fcntl::O_APPEND)
            else
              if params[:mode].index(:create)
                mode_string << "_create"
                mode_numeric = (mode_numeric | mode_flags[:create])
                @fcntl_mode = (@fcntl_mode | ::Fcntl::O_CREAT)
              end
            end
          end
          # [:read, :write, :readwrite, :overwrite, :truncate:, :append, :text, :binary]
          modes.to_enum.each do |mode_entry|
            mode_entry[:synonyms].to_enum.each do |the_synonym|
              if the_synonym.is_a?(Symbol)
                if the_synonym == mode_string.to_sym
                  the_mode_used = mode_entry
                  break
                end
              else
                if the_synonym.is_a?(Numeric)
                  if (the_synonym & mode_numeric == mode_numeric)
                    the_mode_used = mode_entry
                    break
                  end
                end
              end
            end
            if the_mode_used
              break
            end
            #
          end
          if (the_mode_used)
            options[:mode] = the_mode_used[:if_exist].to_i
          else
            modes_list = []
            modes.to_enum.each do |item|
              modes_list << item[:synonyms]
            end
            raise ArgumentError, "#{params[:mode].inspect} is an invalid :mode, use one of the following: #{modes_list.inspect}"
          end
        end
        #
        mode_numeric = options.delete(:mode)
        #
        @conversion_options = {:external => {}, :internal => {}}
        # init-text clobber work-around : defer :write of init-text until the end.
        # init_text = params[:object].dup
        # params[:object].clear
        # FORNOW: just use default behavior
        super(params[:object],mode_numeric)
        #
        if params[:mode].include?(:binary)
          self.set_encoding(::Encoding::ASCII_8BIT)
        else
          if params[:external_encoding].is_a?(::Encoding)
            self.set_encoding(params.delete(:external_encoding))
            #:2nd internal_encoding parameter and 3rd parameter optional hash ignored
            # if you want the supplied string's encoding - best to simply pass it on the .new method call params.
          else
            self.set_encoding(::Encoding.default_external)
          end
        end
        #
        # if external_encoding is BINARY/ASCII_8BIT - just nullify internal_encoding, and skip external/internal conversion option mapping.
        if params[:mode].include?(:binary)
          @internal_encoding = nil
        else
          if params[:internal_encoding].is_a?(::Encoding)
            @internal_encoding = params.delete(:internal_encoding)
          else
            @internal_encoding = ::Encoding.default_internal
          end
          #
          if @internal_encoding
            if @internal_encoding != self.external_encoding
              if params[:external_conversion]
                # External conversion options will have to be dynamically generated upon transcode_to_external as *any* encoding is possible, not just internal_encoding
                @conversion_options[:external] = ::String::transcode_options(self.external_encoding,@internal_encoding,params[:external_conversion])
              else
                @conversion_options[:external] = ::String::transcode_options(self.external_encoding,@internal_encoding)
              end
              #
              if @internal_encoding == ::Encoding::ASCII_8BIT
                #
                if params[:internal_conversion]
                  nl_op = self.newline_option_used(params[:internal_conversion])
                  conv_options = {}
                  if nl_op
                    conv_options[(nl_op)] = true
                  end
                  @conversion_options[:internal] = conv_options
                end
              else
                if params[:internal_conversion]
                  @conversion_options[:internal] = ::String::transcode_options(@internal_encoding,self.external_encoding,params[:internal_conversion])
                else
                  @conversion_options[:internal] = ::String::transcode_options(@internal_encoding,self.external_encoding)
                end
              end
              #
            end
          end
          #
        end
        #
        @external_field_separator = nil
        if params[:external_field_separator]
          self.external_field_separator = params[:external_field_separator]
        end
        @external_record_separator = nil
        if params[:external_record_separator]
          self.external_record_separator = params[:external_record_separator]
        end
        @internal_field_separator = nil
        if params[:internal_field_separator]
          self.external_field_separator = params[:internal_field_separator]
        end
        @internal_record_separator = nil
        if params[:internal_record_separator]
          self.external_field_separator = params[:internal_record_separator]
        end
        # 
        # init-text clobber workaround : deferred :write
        #self.write(init_text)
        self
      end
      #
      # :reopen, :string, :string, :lineno, :lineno, :close_read, :close_write, :closed?, :closed_read?, :closed_write?, :eof, :eof?, :fcntl, :flush, :fsync, :pos, :pos, :rewind, :seek, :sync, :sync, :tell, :each, :each_line, :lines, :each_codepoint, :codepoints, :getc, :ungetc, :ungetbyte, :readchar, :getbyte, :readbyte, :gets, :readline, :readlines, :read, :sysread, :readpartial, :read_nonblock, :write, :, :print, :printf, :putc, :puts, :syswrite, :write_nonblock, :isatty, :tty?, :pid, :fileno, :size, :length, :truncate, :external_encoding, :internal_encoding, :set_encoding
      #
      def inspect()
        ("<#" << "#{self.class}:#{super().split(" ")[0].split(":").last}")
      end
      #
      def binmode?()
        if self.external_encoding == ::Encoding::ASCII_8BIT
          true
        else
          false
        end
      end
      #
      def binmode()
        if self.binmode?
          self
        else
          @internal_encoding = nil
          @conversion_options[:internal] = {}
          @conversion_options[:external] = {}
          self.set_encoding(::Encoding::ASCII_8BIT)
          super()
        end
      end
      #
      def external_encoding=(*args)
        #
        unless self.binmode?
          if args[0].is_any?(::Encoding, ::NilClass)
            #
            if args[0] == ::Encoding::ASCII_8BIT
              self.binmode()
            else
              old_data = self.string().dup
              #
              if args[0].is_a?(::Encoding)
                self.set_encoding(args[0])
                if @internal_encoding
                  if @internal_encoding != self.external_encoding
                    # preserve newline settings
                    nl_op = self.newline_option_used(:external)
                    options = {}
                    if nl_op
                      options[(nl_op)] = true
                    end
                    @conversion_options[:external] = ::String::transcoding_options(self.external_encoding,@internal_encoding,options)
                  end
                end
              else
                self.set_encoding(::Encoding.default_external())
              end
              #
              if self.external_encoding() != old_data.encoding()
                # preserve newline settings
                nl_op = self.newline_option_used(:external)
                options = {}
                if nl_op
                  options[(nl_op)] = true
                end
                old_data.transcode!(self.external_encoding(),options)
                #
                self.string.replace(old_data)
              end
              #
            end
            #
          else
            raise ArgumentError, "Expected an Encoding or NilClass, you provided #{args[0].class}"
          end
        end
        #
      end
      #
      def read(*args)
        # read length bytes from StringIO and optionally route to a buffer object
        if self.closed_read?
          raise IOError, "not open for reading"
        else
          if args[0].is_a?(Numeric)
            # length
            data = super(args[0].to_i)
          else
            # LATER: provide for StringIO buffer size manipulation??? what is default read length??
            data = super()
          end
          if data.is_a?(::String)
            data = self.transcode_to_internal(data)
            # buffer
            if args[1].is_any?(::String, ::IO, ::StringIO, ::GxG::ByteArray)
              # check which classes this can use and in what ways.
              data.to_enum(:chars).each do |the_character|
                args[1] << the_character
              end
              # return buffer object
              args[1]
            else
              # return string
              data
            end
          else
            # return nil
            nil
          end
          #
        end
      end
      alias :read_nonblock :read
      alias :sysread :read
      #
      def write(data="")
        # writes from (self.pos) forward : this will clobber any init string that was passed.
        written = 0
        if self.closed_write?
          raise IOError, "not open for writing"
        else
          if data.is_a?(::String)
            data = self.transcode_to_external(data.dup)
          else
            data = self.transcode_to_external(data)
          end
          if data.size > 0
            written = super(data)
          end
        end
        written
      end
      alias :write_nonblock :write
      alias :syswrite :write
      #
      def <<(*args)
        self.write(*args)
        self
      end
      #
      def readpartial(*args)
        # args[0] maxlen (Fixnum)
        # args[1] (optional) buffer_object
        # Note: use the same approach to pause/retry as IO.read_nonblock.
        #
        # Reads at most maxlen bytes from the I/O stream. It blocks only if ios has no data immediately available. It doesn’t block if some data available.
        # If the optional outbuf argument is present, it must reference a String, which will receive the data. It raises EOFError on end of file.
        # readpartial is designed for streams such as pipe, socket, tty, etc. It blocks only when no data immediately available.
        # This means that it blocks only when following all conditions hold:
        #   the byte buffer in the IO object is empty.
        #   the content of the stream is empty.
        #   the stream is not reached to EOF.
        # When readpartial blocks, it waits data or EOF on the stream. If some data is reached, readpartial returns with the data. If EOF is reached,
        # readpartial raises EOFError.
        # When readpartial doesn’t blocks, it returns or raises immediately. If the byte buffer is not empty, it returns the data in the buffer.
        # Otherwise if the stream has some content, it returns the data in the stream. Otherwise if the stream is reached to EOF, it raises EOFError.
        #
        if self.closed_read?
          raise IOError, "not open for reading"
        else
          if self.eof?
            raise EOFError, "end of stream reached"
          else
            result = ""
            result.force_encoding(self.internal_encoding)
            data = self.read(*args)
            if data
              # non-nil
              if data.is_a?(::String)
                # 'blocking' or not?
                if (self.eof?() || (data && data.to_s.size > 0))
                  # no pseudo-blocking
                  result << data
                  data = nil
                else
                  # pseudo-blocking
                  until (self.eof?() || (data && data.to_s.size > 0))
                    data = self.read(*args)
                    # string, buffer, or nil
                    if data
                      #
                      if data.is_a?(::String)
                        if (data && data.to_s.size > 0)
                          result << data
                          data = nil
                          break
                        else
                          if self.eof?()
                            raise EOFError, "end of stream reached"
                          end
                        end
                      else
                        # buffer
                        result = data
                        data = nil
                        break
                      end
                    else
                      if self.eof?()
                        raise EOFError, "end of stream reached"
                      end
                    end
                    #
                    pause
                    #
                  end
                end
              else
                # buffer
                result = data
              end
            else
              if self.eof?()
                raise EOFError, "end of stream reached"
              end
            end
            #
            if result
              if result.is_a?(::String)
                if result.bytesize > 0
                  result
                else
                  nil
                end
              else
                # buffer
                result
              end
            else
              nil
            end
            # 
          end
        end
      end
      #
      def close()
        super()
      end
      #
      def close_read()
        super()
      end
      #
      def close_write()
        super()
      end
      #
    end
    #
    class Input < GxG::IO::IO
      # ensure mode is read-only, else raise Exception
      def initialize(*args)
        params = self.process_parameters(*args)
        if params[:mode].index(:write)
          params[:mode].delete(:write)
        end
        if params[:mode].index(:readwrite)
          params[:mode].delete(:readwrite)
        end
        super(params)
        self
      end
    end
    #
    class Output < GxG::IO::IO
      # ensure mode is write-only, else raise Exception
      def initialize(*args)
        params = self.process_parameters(*args)
        if params[:mode].index(:read)
          params[:mode].delete(:read)
        end
        if params[:mode].index(:readwrite)
          params[:mode].delete(:readwrite)
        end
        unless params[:mode].index(:write)
          params[:mode] << :write
        end
        super(params)
        self
      end
    end
    #
    class Duplex < GxG::IO::IO
      def initialize(*args)
        params = self.process_parameters(*args)
        if params[:mode].index(:read)
          params[:mode].delete(:read)
        end
        if params[:mode].index(:write)
          params[:mode].delete(:write)
        end
        unless params[:mode].index(:readwrite)
          params[:mode] << :readwrite
        end
        super(params)
        self
      end
    end
    #
    class File < GxG::IO::IO
      # As of Ruby 1.9.2: if a file is not set to :binary mode, it defaults to :text mode.
      # See: http://www.tutorialspoint.com/ruby/ruby_input_output.htm
      # <file>.stat table: (mode example : 0100664)
      #      0700	rwx mask for owner
      #      0400	r for owner
      #      0200	w for owner
      #      0100	x for owner
      #      0070	rwx mask for group
      #      0040	r for group
      #      0020	w for group
      #      0010	x for group
      #      0007	rwx mask for other
      #      0004	r for other
      #      0002	w for other
      #      0001	x for other
      #      4000	Set user ID on execution
      #      2000	Set group ID on execution
      #      1000	Save swapped text, even after use
      #
      def initialize(*args)
        if args[0].is_a?(String)
          the_path = args[0]
          the_mode = (args[1] || "r")
          the_permissions = args[2]
          the_options = args[3]
        else
          raise ArgumentError, "filename or path must be passed as a String"
        end
        #
        if the_options
          params = self.process_parameters(0,the_mode,the_options)
        else
          params = self.process_parameters(0,the_mode)
        end
        #
        mode_flags = {:binary => ::File::BINARY, :text => ::File::TEXT, :read => ::File::RDONLY, :write => ::File::WRONLY, :readwrite => ::File::RDWR, :create => ::File::CREAT, :overwrite => ::File::TRUNC, :append => ::File::APPEND}
        modes = GxG::IO::IO::valid_mode_set({:type => :file, :read => true, :write => true, :text => true, :binary => true})
        the_mode_used = nil
        mode_string = ""
        mode_numeric = 0
        #
        if params[:mode]
          if params[:mode].index(:binary)
            if params[:mode].index(:read)
              if params[:mode].index(:write)
                mode_string = "binary_readwrite"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:readwrite])
              else
                mode_string = "binary_read"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:read])
              end
            else
              if params[:mode].index(:write)
                mode_string = "binary_write"
                mode_numeric = (mode_numeric | mode_flags[:binary] | mode_flags[:write])
              end
            end
          else
            if params[:mode].index(:read)
              if params[:mode].index(:write)
                mode_string = "text_readwrite"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:readwrite])
              else
                mode_string = "text_read"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:read])
              end
            else
              if params[:mode].index(:write)
                mode_string = "text_write"
                mode_numeric = (mode_numeric | mode_flags[:text] | mode_flags[:write])
              end
            end
          end
          if (params[:mode].index(:overwrite) || params[:mode].index(:truncate) )
            mode_string << "_overwrite"
            mode_numeric = (mode_numeric | mode_flags[:overwrite])
          else
            if params[:mode].index(:append)
              mode_string << "_append"
              mode_numeric = (mode_numeric | mode_flags[:append])
            end
          end
          # [:read, :write, :readwrite, :overwrite, :truncate:, :append, :text, :binary]
          modes.to_enum.each do |mode_entry|
            if (mode_entry[:synonyms].include?(mode_string.to_sym) && mode_entry[:synonyms].include?(mode_numeric))
              the_mode_used = mode_entry
              break
            end
            #
          end
          if (the_mode_used)
            options = {}
            the_mode = nil
            if params[:external_encoding]
              options[:external_encoding] = params.delete(:external_encoding)
            end
            if params[:internal_encoding]
              #If the value is nil no conversion occurs.
              if params[:internal_encoding] == params[:external_encoding]
                options[:internal_encoding] = nil
              else
                options[:internal_encoding] = params.delete(:internal_encoding)
              end
            end
            if params[:autoclose]
              options[:autoclose] = params.delete(:autoclose)
            end
            if ::File::exist?(the_path)
              the_mode = the_mode_used[:if_exist].to_i
            else
              if the_mode_used[:if_create]
                the_mode = the_mode_used[:if_create].to_i
              else
                raise ArgumentError, "you cannot operate upon a non-existent file in read-only mode"
              end
            end
            if the_mode
              file_descriptor = GxG::IO::IO::sysopen(the_path,the_mode)
            else
              file_descriptor = nil
            end
            #
            if file_descriptor
              #
              if ::File::directory?(the_path)
                raise ArgumentError, "you cannot operate upon a directory as if it were a file"
              else
                if the_permissions
                  super(file_descriptor, the_mode, the_permissions, options)
                else
                  super(file_descriptor, the_mode, nil, options)
                end
              end
              #
            else
              raise Exception, "unable to create a valid file descriptor with: #{args.inspect}"
            end
            #
          else
            modes_list = []
            modes.to_enum.each do |item|
              modes_list << item[:synonyms]
            end
            raise ArgumentError, "#{params[:mode].inspect} is an invalid :mode, use one of the following: #{modes_list.inspect}"
          end
        end
        #
        @path = the_path
        self
      end
      #
      def to_path()
        @path.dup
      end
    end
    # End IO Module
  end
  # End GxG Module
end