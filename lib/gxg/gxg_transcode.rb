# Auto-Transcoding Support Library Module ############################################
module GxG
  module Support
    module Library
      #
      module Transcoding
        # Instance Methods
        def prepare_conversion_options(options={})
          # obsoleted by ::String::transcode_options
          unless options.is_a?(::Hash)
            raise ArgumentError, "You must pass conversion options parameter as a Hash"
          end
          #
          new_options = {}
          #
          valid_options = [:invalid,:undef,:replace,:fallback,:xml,:cr_newline,:crlf_newline,:universal_newline]
          #
          for the_option_key in valid_options
            #
            if options[(the_option_key)]
              # Note Source: http://ruby-doc.org/core-1.9.3/String.html#method-i-encode
              if the_option_key == :fallback
                #    Sets the replacement string by the given object for undefined character. The object should be a Hash, a Proc, a Method,
                #    or an object which has [] method. Its key is an undefined character encoded in the source encoding of current transcoder.
                #    Its value can be any encoding until it can be converted into the destination encoding of the transcoder.
                unless new_options[:replace]
                  if (options[:fallback].is_any?(::Hash, ::Struct, ::Proc, ::Method) || options[:fallback].respond_to?(:[]))
                    # if :fallback will not process an Array as mentioned above ... remove :[] respond_to? condition.
                    new_options[:fallback] = options[:fallback]
                  end
                end
              end
              #
              if the_option_key == :invalid
                #    If the value is :replace, encode replaces invalid byte sequences in str with the replacement character. The default is to
                #    raise the Encoding::InvalidByteSequenceError exception
                unless new_options[:fallback]
                  if options[:invalid] == :replace
                    new_options[:invalid] = :replace
                  end
                end
              end
              #
              if (the_option_key == :undef)
                #    If the value is :replace, encode replaces characters which are undefined in the destination encoding with the replacement character.
                #    The default is to raise the Encoding::UndefinedConversionError.
                unless new_options[:fallback]
                  if options[:undef] == :replace
                    new_options[:undef] = :replace
                  end
                end
              end
              if (the_option_key == :replace)
                #    Sets the replacement string to the given value. The default replacement string is “uFFFD” for Unicode encoding forms, and “?” otherwise.
                unless new_options[:fallback]
                  if options[:replace].is_a?(::String)
                    new_options[:replace] = options[:replace]
                  end
                end
              end
              if the_option_key == :xml
                #    The value must be :text or :attr. If the value is :text encode replaces undefined characters with their (upper-case hexadecimal) numeric character
                #    references. ‘&’, ‘<’, and ‘>’ are converted to “&amp;”, “&lt;”, and “&gt;”, respectively. If the value is :attr, encode also quotes the replacement
                #    result (using ‘“’), and replaces ‘”’ with “&quot;”.
                if [:text, :attr].include?(options[:xml])
                  new_options[:xml] = options[:xml]
                end
              end
              if the_option_key == :cr_newline
                #    Replaces LF (“n”) with CR (“r”) if value is true.
                unless (new_options[:crlf_newline] || new_options[:universal_newline])
                  if options[(the_option_key)] == true
                    new_options[(the_option_key)] = true
                  end
                end
              end
              #
              if the_option_key == :crlf_newline
                #    Replaces LF (“n”) with CRLF (“rn”) if value is true.
                unless (new_options[:cr_newline] || new_options[:universal_newline])
                  if options[(the_option_key)] == true
                    new_options[(the_option_key)] = true
                  end
                end
              end
              #
              if the_option_key == :universal_newline
                #    Replaces CRLF (“rn”) and CR (“r”) with LF (“n”) if value is true.
                unless (new_options[:cr_newline] || new_options[:crlf_newline])
                  if options[(the_option_key)] == true
                    new_options[(the_option_key)] = true
                  end
                end
              end
              #
            end
            #
            pause
          end
          new_options
        end
        #
        def newline_option_used(io_channel=:external)
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          # determine the correct new_line trancoding option used
          if io_channel.is_a?(::Hash)
            options = io_channel
          else
            options = (@conversion_options[(io_channel.to_sym)] || {})
          end
          if options[:cr_newline]
            :cr_newline
          else
            if options[:crlf_newline]
              :crlf_newline
            else
              if options[:universal_newline]
                :universal_newline
              else
                # use nil if none specified
                nil
              end
            end
          end
          #
        end
        #
        def newline_used(io_channel=:external)
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          newline = ""
          if io_channel == :internal
            newline.force_encoding((@internal_encoding || self.external_encoding))
          else
            io_channel = :external
            newline.force_encoding(self.external_encoding)
          end
          # determine the correct new_line_separator
          if @conversion_options[(io_channel)][:cr_newline]
            newline << "\r"
          else
            if @conversion_options[(io_channel)][:crlf_newline]
              newline << "\r\n"
            else
              if @conversion_options[(io_channel)][:universal_newline]
                newline << "\n"
              else
                # use global default if none specified
                newline << $/
              end
            end
          end
          newline
        end
        #
        def field_separator_used(io_channel=:external)
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          unless self.instance_variable_defined?(:@internal_field_separator)
            @internal_field_separator = nil
          end
          unless self.instance_variable_defined?(:@external_field_separator)
            @external_field_separator = nil
          end
          field_separator = ""
          if io_channel == :internal
            field_separator.force_encoding((@internal_encoding || self.external_encoding))
            field_separator << (@internal_field_separator || ($,).to_s)
          else
            io_channel = :external
            field_separator.force_encoding(self.external_encoding)
            field_separator << (@external_field_separator || ($,).to_s)
          end
          if field_separator.size > 0
            field_separator
          else
            nil
          end
        end
        #
        def record_separator_used(io_channel=:external)
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          unless self.instance_variable_defined?(:@internal_record_separator)
            @internal_record_separator = nil
          end
          unless self.instance_variable_defined?(:@external_record_separator)
            @external_record_separator = nil
          end
          record_separator = ""
          if io_channel == :internal
            record_separator.force_encoding((@internal_encoding || self.external_encoding))
            record_separator << (@internal_record_separator || ($\).to_s)
          else
            io_channel = :external
            record_separator.force_encoding(self.external_encoding)
            record_separator << (@external_record_separator || ($\).to_s)
          end
          if record_separator.size > 0
            record_separator
          else
            nil
          end
        end
        #
        def convert_to_string(the_object=nil,encoding=::Encoding.default_external,conversion_options={})
          # return the supplied string, or supported object string data, or UTF_8 codepoint, un-transcoded
          # encoding is used for when a byte value integer is passed to know what encoding to set.
          the_string = ""
          the_string.force_encoding(encoding || ::Encoding.default_external)
          if the_object
            if the_object.is_a?(::Array)
              dataset = the_object.flatten
            else
              dataset = [(the_object)]
            end
            dataset.to_enum(:each).each do |object|
              buffer = ""
              if object.is_a?(::String)
                # find the string content of these classes and pass them for transcoding: Numeric, String, ::IO via gets, ::StringIO via gets, ::GxG::ByteArray
                buffer = object.dup
              else
                if object.is_any?(::IO, ::StringIO)
                  # Note: what issues arise when the_object is in binary mode?  Also, how does this scale to very large things or files?
                  buffer = object.gets().to_s
                end
                if object.is_any?(::GxG::ByteArray)
                  buffer = object.to_s
                end
                if object.is_a?(::Numeric)
                  if object.to_i >= 0
                    data = ""
                    if (0xFFFFFFFF && object.to_i) > 255
                      # interprets as unicode code point
                      data.force_encoding(::Encoding::UTF_8)
                    else
                      # interprets as a char value in its own encoding, no transcoding needed.
                      data.force_encoding(encoding || ::Encoding.default_external)
                    end
                    buffer = (data << object.to_i)
                    data = nil
                  else
                    # signed integers not supported for char values or codepoints at this time.
                  end
                end
              end
              #
              if buffer.size > 0
                if (buffer.encoding == (encoding || ::Encoding.default_external) && ! self.binmode?())
                  the_string << buffer
                else
                  # ::String::transcode_options((encoding || ::Encoding.default_external),buffer.encoding, (conversion_options || {}))
                  if self.binmode?()
                    buffer.to_enum(:chars).each do |the_char|
                      the_char.to_enum(:bytes).each do |the_byte|
                        the_string << the_byte
                      end
                    end
                  else
                    nl_op = self.newline_option_used(conversion_options)
                    options = {}
                    if nl_op
                      options[(nl_op)] = true
                    end
                    #
                    the_string << buffer.transcode!((encoding || ::Encoding.default_external),options)
                  end
                end
              end
              #
            end
          end
          #
          the_string
        end
        #
        # TODO: GxG::StringIO : transcoding methods : tie into conversion-options-set-selector supports (dst-encoding,src-encoding).  Hash deep-merge method needed.
        #
        def transcode_to_external(the_string="")
          # return the supplied string, or supported object string data, or UTF_8 codepoint, transcoded
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          #
          unless the_string.is_a?(::String)
            # External conversion options will have to be dynamically generated upon transcode_to_external as *any* encoding is possible, not just internal_encoding
            the_string = self.convert_to_string(the_string,self.external_encoding,@conversion_options[:external])
          end
          if the_string.size > 0
            if self.binmode?()
              the_string.force_encoding(::Encoding::ASCII_8BIT)
            else
              if (the_string.encoding != self.external_encoding)
                if the_string.encoding == @internal_encoding
                  options = ::String::transcode_options(self.external_encoding,the_string.encoding,@conversion_options[:external])
                else
                  # External conversion options will have to be dynamically generated upon transcode_to_external as *any* encoding is possible, not just internal_encoding
                  nl_op = self.newline_option_used(:external)
                  options = {}
                  if nl_op
                    options[(nl_op)] = true
                  end
                  options = ::String::transcode_options(self.external_encoding,the_string.encoding,options)
                end
                the_string.transcode!(self.external_encoding,options)
              end
            end
          end
          #
          the_string
        end
        #
        def transcode_to_internal(the_string="")
          # return the supplied string, or supported object string data, or UTF_8 codepoint, transcoded
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          #
          if (@internal_encoding && ! self.binmode?())
            unless the_string.is_a?(::String)
              the_string = self.convert_to_string(the_string,@internal_encoding,@conversion_options[:internal])
            end
            if the_string.size > 0
              if @internal_encoding == ::Encoding::ASCII_8BIT
                # for cases where the external encoding is anything but binary, but the internal is set to BINARY.
                # instead of actually transcoding something char by char into binary - just sets the encoding and filters for newline settings.
                #
                the_string.force_encoding(::Encoding::ASCII_8BIT)
                nl_op = self.newline_option_used(:internal)
                options = {}
                if nl_op
                  options[(nl_op)] = true
                end
                the_string = the_string.encode(::Encoding::ASCII_8BIT,::Encoding::ASCII_8BIT,options)
              else
                if (the_string.encoding != @internal_encoding)
                  if the_string.encoding == self.external_encoding
                    options = ::String::transcode_options(@internal_encoding,the_string.encoding,@conversion_options[:internal])
                  else
                    nl_op = self.newline_option_used(:internal)
                    options = {}
                    if nl_op
                      options[(nl_op)] = true
                    end
                    options = ::String::transcode_options(@internal_encoding,the_string.encoding,options)
                  end
                  the_string.transcode!(@internal_encoding,options)
                end
              end
            end
          else
            the_string = self.transcode_to_external(the_string)
          end
          #
          the_string
        end
        #
        #
      end
      #
      module TranscodingIO
        #
        def external_conversion()
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          @conversion_options[:external].clone
        end
        #
        def external_conversion=(*args)
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          @conversion_options[:external] = self.prepare_conversion_options(*args)
          @conversion_options[:external].clone
        end
        #
        def external_newline()
          self.newline_option_used(:external)
        end
        #
        def external_newline=(*args)
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          if [:cr_newline, :crlf_newline, :universal_newline].include?(args[0])
            @conversion_options[:external].delete(:cr_newline)
            @conversion_options[:external].delete(:crlf_newline)
            @conversion_options[:external].delete(:universal_newline)
            @conversion_options[:external][(args[0])] = true
          end
        end
        #
        def external_field_separator()
          unless self.instance_variable_defined?(:@external_field_separator)
            @external_field_separator = nil
          end
          @external_field_separator.dup
        end
        #
        def external_field_separator=(*args)
          unless self.instance_variable_defined?(:@external_field_separator)
            @external_field_separator = nil
          end
          if args[0].is_a?(::String)
            @external_field_separator = args[0]
          else
            case args[0]
            when :globalcopy
              @external_field_separator = ($,).dup
            when :global
              @external_field_separator = $,
            end
          end
        end
        #
        def external_record_separator()
          unless self.instance_variable_defined?(:@external_record_separator)
            @external_record_separator = nil
          end
          @external_record_separator.dup
        end
        #
        def external_record_separator=(*args)
          unless self.instance_variable_defined?(:@external_record_separator)
            @external_record_separator = nil
          end
          if args[0].is_a?(::String)
            @external_record_separator = args[0]
          else
            case args[0]
            when :globalcopy
              @external_record_separator = ($\).dup
            when :global
              @external_record_separator = $\
            end
          end
        end
        #
        def internal_encoding()
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          @internal_encoding
        end
        #
        def internal_encoding=(*args)
          unless self.instance_variable_defined?(:@internal_encoding)
            @internal_encoding = nil
          end
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          unless self.binmode?()
            if args[0].is_any?(::Encoding, ::NilClass)
              if args[0].is_a?(::Encoding)
                @internal_encoding = args[0]
                # preserve newline settings
                nl_op = self.newline_option_used(:internal)
                options = {}
                if nl_op
                  options[(nl_op)] = true
                end
                @conversion_options[:internal] = ::String::transcoding_options(@internal_encoding,self.external_encoding,options)
              else
                @internal_encoding = nil
                @conversion_options[:internal] = {}
              end
            else
              raise ArgumentError, "Expected an Encoding or NilClass, you provided #{args[0].class}"
            end
          end
        end
        #
        def internal_conversion()
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          @conversion_options[:internal].clone
        end
        #
        def internal_conversion=(*args)
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          @conversion_options[:internal] = self.prepare_conversion_options(*args)
          @conversion_options[:internal].clone
        end
        #
        def internal_newline()
          self.newline_option_used(:internal)
        end
        #
        def internal_newline=(*args)
          unless self.instance_variable_defined?(:@conversion_options)
            @conversion_options = {:internal => {}, :external => {}}
          end
          if [:cr_newline, :crlf_newline, :universal_newline].include?(args[0])
            @conversion_options[:internal].delete(:cr_newline)
            @conversion_options[:internal].delete(:crlf_newline)
            @conversion_options[:internal].delete(:universal_newline)
            @conversion_options[:internal][(args[0])] = true
          end
        end
        #
        def internal_field_separator()
          unless self.instance_variable_defined?(:@internal_field_separator)
            @internal_field_separator = nil
          end
          @internal_field_separator.dup
        end
        #
        def internal_field_separator=(*args)
          unless self.instance_variable_defined?(:@internal_field_separator)
            @internal_field_separator = nil
          end
          if args[0].is_a?(::String)
            @internal_field_separator = args[0]
          else
            case args[0]
            when :globalcopy
              @internal_field_separator = ($,).dup
            when :global
              @internal_field_separator = $,
            end
          end
        end
        #
        def internal_record_separator()
          unless self.instance_variable_defined?(:@internal_record_separator)
            @internal_record_separator = nil
          end
          @internal_record_separator.dup
        end
        #
        def internal_record_separator=(*args)
          unless self.instance_variable_defined?(:@internal_record_separator)
            @internal_record_separator = nil
          end
          if args[0].is_a?(::String)
            @internal_record_separator = args[0]
          else
            case args[0]
            when :globalcopy
              @internal_record_separator = ($\).dup
            when :global
              @internal_record_separator = $\
            end
          end
        end
        #
        def gets(*args)
          # Reads the next “line” from the I/O stream; lines are separated by sep. A separator of nil reads the entire contents,
          # and a zero-length separator reads the input a paragraph at a time (two successive newlines in the input separate paragraphs).
          # The stream must be opened for reading or an IOError will be raised. The line read in will be returned and also assigned to $_.
          # Returns nil if called at end of file. If the first argument is an integer, or optional second argument is given, the returning string
          # would not be longer than the given value in bytes.
          if self.closed_read?
            raise IOError, "not open for reading"
          else
            data = super(*args)
            if data.is_a?(::String)
              data = self.transcode_to_internal(data)
              $_ = data.dup
              data
            else
              nil
            end
          end
        end
        #
        def getbyte()
          # regarding getbyte : I don't see any practical way to do auto-transcoding ... leaving that one alone for now.
          super()
        end
        #
        def getbytes()
          result = GxG::ByteArray.new
          until self.eof?()
            data = self.getbyte()
            if data
              result << data
            end
            pause
          end
          result
        end
        #
        def getc()
          data = super()
          if data.is_a?(::String)
            data = self.transcode_to_internal(data)
          end
          data
        end
        #
        def readbyte()
          if self.closed_read?
            raise IOError, "not open for reading"
          else
            if self.eof?
              raise EOFError, "end of stream reached"
            else
              self.getbyte()
            end
          end
        end
        #
        def readchar(*args)
          if self.closed_read?
            raise IOError, "not open for reading"
          else
            if self.eof?
              raise EOFError, "end of stream reached"
            else
              self.transcode_to_internal(self.read(1))
            end
          end
        end
        #
        def readline(*args)
          if self.closed_read?
            raise IOError, "not open for reading"
          else
            if self.eof?
              raise EOFError, "end of stream reached"
            else
              self.gets(*args)
            end
          end
        end
        #
        def each_char(&block)
          if block.respond_to?(:call)
            if self.closed_read?
              raise IOError, "not open for reading"
            else
              #
              # Note: this approach burns another 20 or 40 bytes (depending on arch-bits) for extra cooperative Enumerator encapsulation,
              # but avoids stack-too-deep errors..
              super().to_enum.each do |the_character|
                block.call(self.transcode_to_internal(the_character))
              end
              #
              self
            end
          else
            # Note: when each_char alias is called, will be cosmetic off, but will work.
            self.to_enum(:each_char)
          end
        end
        alias :chars :each_char
        #
        def each_byte(&block)
          if block.respond_to?(:call)
            if self.closed_read?
              raise IOError, "not open for reading"
            else
              until self.eof?()
                data = self.getbyte()
                if data
                  block.call(data)
                end
                pause
              end
              #
              self
            end
          else
            # Note: when each_byte alias is called, will be cosmetic off, but will work.
            self.to_enum(:each_byte)
          end
        end
        alias :bytes :each_byte
        #
        def each_transcoded_byte(&block)
          if block.respond_to?(:call)
            if self.closed_read?
              raise IOError, "not open for reading"
            else
              # transcodes at the character level prior to byte passage to the block.
              self.each_char do |the_character|
                # the_character is pre-transcoded by each_char where appropriate.
                the_character.to_enum(:bytes).each do |the_byte|
                  block.call(the_byte)
                end
              end
              #
              self
            end
          else
            # Note: when each_transcoded_byte alias is called, will be cosmetic off, but will work.
            self.to_enum(:each_transcoded_byte)
          end
        end
        alias :transcoded_bytes :each_transcoded_byte
        #
        def each_codepoint(&block)
          if block.respond_to?(:call)
            if self.closed_read?
              raise IOError, "not open for reading"
            else
              # transcodes at the character level prior to codepoint passage to the block.
              self.each_char do |the_character|
                block.call(the_character.codepoints.first)
              end
              #
              self
            end
          else
            # Note: when each_codepoint alias is called, will be cosmetic off, but will work.
            self.to_enum(:each_codepoint)
          end
        end
        alias :codepoints :each_codepoint
        #
        def each_line(separator=$/, limit=nil,&block)
          # should not do an *args param capture for interface behavior compatibility.
          # use of limit and separator appear exclusive in this method.
          if separator.is_a?(Numeric)
            limit = separator.to_i
            separator = nil
          end
          # if transcoding is set, overwrite default separator according to translation flag settings.
          if (self.internal_encoding() && self.internal_encoding() != self.external_encoding)
            if separator == $/
              #Note : line separator supplied as method parameter will be applied to the transcoded string, not the StringIO data itself.
              separator = self.newline_used(:internal)
            end
          end
          #
          if limit
            limit = limit.to_i
            unless limit > 0
              # Note: a work-around : irb FREAKS entire system when you call readlines with limit equal to 0 (memleak: IO lock up)
              limit = 1
            end
            args = [(separator),(limit)]
          else
            args = [(separator)]
          end
          #
          if block.respond_to?(:call)
            if self.closed_read?
              raise IOError, "not open for reading"
            else
              # Note: this approach burns another 20 or 40 bytes (depending on arch-bits) for extra cooperative Enumerator encapsulation,
              # but avoids stack-too-deep errors..
              super(*args) do |the_line|
                block.call(self.transcode_to_internal(the_line))
                pause
              end
              #
              self
            end
          else
            # Note: when each_line alias is called, will be cosmetic off, but will work.          
            self.to_enum(:each_line,*args)
          end
        end
        alias :each :each_line
        alias :lines :each_line
        #
        def readlines(*args)
          # Reads all of the lines in ios, and returns them in anArray. Lines are separated by the optional sep.
          # If sep is nil, the rest of the stream is returned as a single record. If the first argument is an integer,
          # or optional second argument is given, the returning string would not be longer than the given value in bytes.
          # The stream must be opened for reading or an IOError will be raised.
          if self.closed_read?
            raise IOError, "not open for reading"
          else
            data = []
            self.each_line(*args) { |the_line|  data << the_line }
            data
          end
        end
        # Transcoding 'write' methods:
        def putc(the_object=nil)
          # make multi-byte safe version of putc for StringIO. (alternate3)
          # unlike stock putc : multi-byte char safe, can accept arrays of objects : where this will read the first char available on each object and write it.
          if the_object
            if the_object.is_a?(::Array)
              dataset = the_object.flatten
            else
              dataset = [(the_object)]
            end
            dataset.to_enum(:each).each do |object|
              buffer = ""
              if object.is_a?(::String)
                # find the string content of these classes and pass them for transcoding: Numeric, String, ::IO via gets, ::StringIO via gets, ::GxG::ByteArray
                buffer = object.chars.first
              else
                if object.is_any?(::IO, ::StringIO)
                  # Note: what issues arise when the_object is in binary mode?  Also, how does this scale to very large things or files?
                  buffer = object.getc.to_s
                end
                if object.is_any?(::GxG::ByteArray)
                  buffer = object.to_s.chars.first
                end
                if object.is_a?(::Numeric)
                  if object.to_i >= 0
                    data = ""
                    if (0xFFFFFFFF && object.to_i) > 255
                      # interprets as unicode code point
                      data.force_encoding(::Encoding::UTF_8)
                    else
                      # interprets as a char value in its own encoding, no transcoding needed.
                      data.force_encoding(self.external_encoding)
                    end
                    buffer = (data << object.to_i)
                    data = nil
                  else
                    # signed integers not supported for char values or codepoints at this time.
                  end
                end
              end
              #
              if buffer.size > 0
                if buffer.encoding == (self.external_encoding)
                  self.write(buffer.chars.first)
                else
                  self.write(self.transcode_to_external(buffer).chars.first)
                end
              end
              #
            end
          end
          #
          nil
        end
        alias :put_codepoint :putc
        alias :putwc :putc
        #
        def printf(*args)
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            formatting = ""
            args = args.flatten
            if args[0].is_a?(::String)
              formatting = args.delete_at(0)
            end
            args.to_enum(:each_with_index) do |element,index|
              if element.is_any?(::String, ::Numeric, ::IO, ::StringIO, ::GxG::ByteArray)
                args[(index)] = self.transcode_to_external(element)
              else
                args[(index)] = self.transcode_to_external(element.inspect)
              end
            end
            data = ""
            data.force_encoding(self.external_encoding)
            data << formatting.%(*args)
            #
            if data.size > 0
              self.write(data)
            end
            #
          end
          #
          nil
        end
        #
        def print(*args)
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            fieldseparator = self.field_separator_used(:external)
            recordseparator = self.record_separator_used(:external)
            args = args.flatten
            if args.size > 0
              data = ""
              data.force_encoding(self.external_encoding)
              args.to_enum(:each_with_index) do |element,index|
                if element.is_any?(::String, ::Numeric, ::IO, ::StringIO, ::GxG::ByteArray)
                  args[(index)] = self.transcode_to_external(element)
                else
                  args[(index)] = self.transcode_to_external(element.to_s)
                end
              end
              args.to_enum(:each_with_index).each do |element,index|
                data << element
                unless index == (args.size - 1)
                  if fieldseparator
                    data << fieldseparator
                  end
                end
              end
              if recordseparator
                data << recordseparator
              end
              if data.size > 0
                self.write(data)
              end
            end
          end
          #
          nil
        end
        #
        def puts(*args)
          # Writes the given objects to ios as with IO#print. Writes a record separator (typically a newline) after any
          # that do not already end with a newline sequence. If called with an array argument, writes each element on a new line.
          # If called without arguments, outputs a single record separator.
          #  ###
          # determine the correct new_line_separator
          newline = self.newline_used(:external)
          #
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            args = args.flatten
            if args.size > 0
              args.to_enum(:each_with_index) do |element,index|
                if element.is_any?(::String, ::Numeric, ::IO, ::StringIO, ::GxG::ByteArray)
                  args[(index)] = self.transcode_to_external(element)
                else
                  args[(index)] = self.transcode_to_external(element.to_s)
                end
              end
              #
              data = ""
              data.force_encoding(self.external_encoding)
              args.to_enum.each do |element|
                if newline.size > 0
                  # sense if newline is already present, add if not
                  if element.size >= newline.size
                    if element.slice((newline.size * -1)..-1) == newline
                      data << element
                    else
                      data << element
                      data << newline
                    end
                  else
                    data << element
                    data << newline
                  end
                else
                  data << element
                end
              end
              if data.size > 0
                self.write(data)
              end
              #
            else
              self.write(newline)
            end
          end
          #
          nil
        end
        #
        def ungetbyte(the_byte=nil)
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            #
            if the_byte.is_a?(::Numeric)
              if (0..255).include?(the_byte.to_i)
                super(the_byte.to_i)
              else
                self.ungetbytes(the_byte)
              end
            else
              self.ungetbytes(the_byte)
            end
            #
          end
          nil
        end
        alias :unget_transcoded_byte :ungetbyte
        #
        def ungetbytes(*args)
          # unget the string content of these classes and pre-pend them to the StringIO: Numeric, String, ::IO via gets, ::StringIO via gets, ::GxG::ByteArray
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            args = args.flatten
            args.to_enum.each do |the_object|
              #
              the_string = self.transcode_to_external(the_object)
              if the_string.size > 0
                the_string.reverse.each_char do |the_character|
                  bytes = []
                  the_character.each_byte do |the_byte_value|
                    bytes.unshift(the_byte_value)
                  end
                  bytes.to_enum.each do |the_byte_value|
                    self.ungetbyte(the_byte_value)
                  end
                end
              end
              #
            end
          end
          nil
        end
        alias :unget_transcoded_bytes :ungetbytes
        #
        def ungetc(the_character="")
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            unless the_character.is_a?(::String)
              the_character = the_character.to_s.chars.first
            end
            if the_character.size > 1
              the_character = the_character.chars.first
            end
            self.ungetbytes(the_character)
          end
          nil
        end
        #
        def ungets(*args)
          # unget the string content of these classes and pre-pend them to the StringIO: Numeric, String, ::IO via gets, ::StringIO via gets, ::GxG::ByteArray
          if self.closed_write?
            raise IOError, "not open for writing"
          else
            args = args.flatten
            args.to_enum.each do |the_object|
              #
              the_string = self.transcode_to_external(the_object)
              if the_string.size > 0
                the_string.reverse.to_enum(:each_char).each do |the_character|
                  self.ungetc(the_character)
                end
              end
              #
            end
          end
          nil
        end
        #
      end
      #
    end
  end
end
