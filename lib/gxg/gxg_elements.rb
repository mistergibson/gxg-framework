
# ---------------------------------------------------------------------------------------------------------------------
# Various data element classes:
module GxG
  #
  class Version
    def initialize(params={})
      unless params.is_a?(::Hash)
        params = {:interpret => (params.to_s)}
      end
      @encoded_value = encode(params)
    end
    def value()
      decode({:value => @encoded_value})
    end
    def encoded_value()
      @encoded_value
    end
    def <=>(other)
      return @encoded_value <=> other.encoded_value()
    end
    def to_d()
      ::BigDecimal.new(@encoded_value)
    end
    def to_s()
      value.inspect
    end
    def inspect()
      value.inspect
    end
    def increment(params={:revision => 1})
      current = decode({:value => @encoded_value})
      if current[:phase].is_a?(Hash)
        numeric_phase = current[:phase][:candidate].to_i + 2
      else
        case current[:phase]
        when :alpha
          numeric_phase = 0
        when :beta
          numeric_phase = 1
        when :release
          numeric_phase = 99
        end
      end
      if params[:phase].is_a?(Numeric)
        phase_increment = params[:phase]
      else
        phase_increment = 0
      end
      new_value = {}
      #
      if params[:revision].is_a?(Numeric)
        if (params[:revision].to_i + current[:revision]) > 9999
          params[:patch_level] = params[:patch_level].to_i + 1
          new_value[:revision] = 0
        else
          new_value[:revision] = (params[:revision].to_i + current[:revision])
        end
      else
        new_value[:revision] = current[:revision]
      end
      #
      if params[:patch_level].is_a?(Numeric)
        if (params[:patch_level].to_i + current[:patch_level]) > 9999
          phase_increment = phase_increment + 1
          new_value[:patch_level] = 0
        else
          new_value[:patch_level] = (params[:patch_level].to_i + current[:patch_level])
        end
      else
        new_value[:patch_level] = current[:patch_level]
      end
      #
      if phase_increment > 0
        if (phase_increment + numeric_phase) > 99
          params[:tiny] = params[:tiny].to_i + 1
          new_value[:phase] = 99
        else
          new_value[:phase] = (phase_increment + numeric_phase)
        end
      else
        new_value[:phase] = numeric_phase
      end
      #
      if params[:tiny].is_a?(Numeric)
        if (params[:tiny].to_i + current[:tiny]) > 999
          params[:minor] = params[:minor].to_i + 1
          new_value[:tiny] = 0
        else
          new_value[:tiny] = (params[:tiny].to_i + current[:tiny])
        end
      else
        new_value[:tiny] = current[:tiny]
      end
      #
      if params[:minor].is_a?(Numeric)
        if (params[:minor].to_i + current[:minor]) > 999
          params[:major] = params[:major].to_i + 1
          new_value[:minor] = 0
        else
          new_value[:minor] = (params[:minor].to_i + current[:minor])
        end
      else
        new_value[:minor] = current[:minor]
      end
      #
      if params[:major].is_a?(Numeric)
        new_value[:major] = current[:major] + params[:major].to_i
      else
        new_value[:major] = current[:major]
      end
      # convert phase numeric value to Symbol / Hash
      if (2..98).include?(new_value[:phase])
        new_value[:phase] = {:candidate => (new_value[:phase] - 2)}
      else
        case new_value[:phase]
        when 0
          new_value[:phase] = :alpha
        when 1
          new_value[:phase] = :beta
        when 99
          new_value[:phase] = :release
        end
      end
      #
      @encoded_value = encode(new_value)
      self
    end
    def decode(params={:value => 0.0})
      # numeric value format: MmmmtttPPpppp.rrrrr
      string_value = params[:value].to_s
      major = string_value.split(".")[0][0..-13].to_i
      minor = string_value.split(".")[0][-12..-10].to_i
      teeny = string_value.split(".")[0][-9..-7].to_i
      phase = string_value.split(".")[0][-6..-5].to_i
      if (2..98).include?(phase)
        phase = {:candidate => (phase - 2)}
      else
        case phase
        when 0
          phase = :alpha
        when 1
          phase = :beta
        when 99
          phase = :release
        end
      end
      patch_level = string_value.split(".")[0][-4..-1].to_i
      revision = string_value.split(".")[1].to_i
      #
      {:major => major, :minor => minor, :teeny => teeny, :phase => phase, :patch_level => patch_level, :revision => revision}
    end
    def interpret_version(params={})
      result = {:phase => :release}
      # params[:interpret]
      sections = params[:interpret].split(".")
      major_string = ""
      minor_string = ""
      teeny_string = ""
      phase_string = ""
      patch_level = ""
      revision = ""
      # *very* simple at this point
      result[:major] = sections[0].to_i
      result[:minor] = sections[1].to_i
      result[:teeny] = sections[2].to_i
      if sections.last.to_s.include?("alpha")
        result[:phase] = :alpha
      end
      if sections.last.to_s.include?("beta")
        result[:phase] = :beta
      end
      # TODO: Version.intereperet_version : add patch-level & revision detect (need a numeric string scrubber)
      #
      result
    end
    #
    def encode(params={})
      # numeric value format: MmmmtttPPpppp.rrrrr
      #
      if params[:interpret].is_a?(String)
        params = params.merge(interpret_version(params))
      end
      #
      major = 0
      minor = 0
      teeny = 0
      phase = :release
      patch_level = 0
      revision = 0
      #
      if params[:major].is_a?(Numeric)
        major = params[:major].to_i
      end
      if params[:minor].is_a?(Numeric)
        minor = params[:minor].to_i
      end
      if params[:teeny].is_a?(Numeric)
        teeny = params[:teeny].to_i
      end
      if params[:phase].is_a?(Hash)
        # :phase => :alpha
        # :phase => :beta
        # :phase => {:candidate => 12} (0 to 96)
        # :phase => :release
        if params[:phase][:candidate].is_a?(Numeric)
          phase = params[:phase]
          phase[:candidate] = phase[:candidate].to_i
          unless (0..96).include?(phase[:candidate])
            raise ArgumentError, ":phase[:candidate] must be between 0 and 96, consider incrementing teeny version beyond that"
          end
        else
          raise ArgumentError, ":phase[:candidate] must be an Numeric, you provided a #{params[:phase][:candidate].class}"
        end
      else
        if params[:phase].is_a?(Symbol)
          if [:alpha, :beta, :release].include?(params[:phase])
            phase = params[:phase]
          else
            #
          end
        end
      end
      if params[:patch_level].is_a?(Numeric)
        patch_level = params[:patch_level].to_i
      end
      if params[:revision].is_a?(Numeric)
        revision = params[:revision].to_i
      end
      # numeric value format: MmmmtttPPpppp.rrrrr
      #
      string_value = "#{major}"
      (3 - minor.to_s.size).times do
        string_value << "0"
      end
      string_value << minor.to_s
      #
      (3 - teeny.to_s.size).times do
        string_value << "0"
      end
      string_value << teeny.to_s
      #
      if phase.is_a?(Hash)
        if phase[:candidate]
          phase[:candidate] += 2
          (2 - phase[:candidate].to_s.size).times do
            string_value << "0"
          end
          string_value << "#{phase[:candidate]}"
        end
      else
        case phase
        when :alpha
          string_value << "00"
        when :beta
          string_value << "01"
        when :release
          string_value << "99"
        end
      end
      #
      (4 - patch_level.to_s.size).times do
        string_value << "0"
      end
      string_value << patch_level.to_s
      string_value << "."
      #
      (4 - revision.to_s.size).times do
        string_value << "0"
      end
      string_value << revision.to_s
      #
      string_value
    end
    private :decode, :encode, :interpret_version
  end
  #
  class Enumerator < ::Enumerator
    # this is a bit inefficient, but it gets the job done.  It is essentially an each wrapper to do a cooperative pauses for non-blocking goodness. :)
    # TODO: inspiration: what about just leveraging 'super' after a pause operation on all overrides. (thx)
    #
    def initialize(object=nil,method=:each,*args, &block)
      # Without the call to super() it works, but will be uninitialized
      # super(object,method,*args)
      @collection = object.stock_to_enum(method,*args, &block)
      # @collection = ::Enumerator.new(object,method,*args,&block)
      self
    end
    #
    def each(&block)
      # reference = {:object => self, :method => __callee__, :fiber => Fiber.current, :thread => Thread.current}
      if block.respond_to?(:call)
        if ::GxG::EventManager::manager_running?
          @collection.each do |*args|
            block.call(*args)
            pause
          end
          self
        else
          @collection.each(&block)
          self
        end
      else
        self
      end
    end
    #
    def next()
      pause
      @collection.next()
    end
    #
    def next_values()
      pause
      @collection.next_values()
    end
    #
    def peek()
      pause
      @collection.peek()
    end
    #
    def peek_values()
      pause
      @collection.peek_values()
    end
    #
    def rewind()
      if @collection.respond_to?(:rewind)
        @collection.rewind
      end
      self
    end
    #
    def with_index(offset=0,&block)
      enumerator = GxG::Enumerator.new(@collection.with_index(offset))
      if block.respond_to?(:call)
        enumerator.each do |entry,index|
          block.call(entry,index)
        end
      else
        enumerator
      end
    end
    alias :each_with_index :with_index
    #
    def with_object(an_object=nil,&block)
      enumerator = GxG::Enumerator.new(@collection.with_object(an_object))
      if block.respond_to?(:call)
        enumerator.each do |entry,the_object|
          block.call(entry,the_object)
        end
        an_object
      else
        enumerator
      end
    end
    #
  end
  #
  class ReturnResponse
    # this class allows for characterized muli-part return values for Procs and Methods
    # this was created for a variety of reasons.  Hope this isn't a dead end.
    def initialize(response={})
      unless response.is_a?(::Hash)
        raise ArgumentError.new("Response must be passed as a Hash")
      end
      @details = response
    end
    def new_selector()
      @details[:new_selector]
    end
    def result()
      @details[:result]
    end
    def error()
      @details[:error]
    end
    def warning()
      @details[:warning]
    end
    def info()
      @details[:info]
    end
    def debug()
      @details[:debug]
    end
    def inspect()
      @details.inspect
    end
  end
  #
  class Tuple
    # Inspired by Python's Tuple class, in this case: allows any object to be a key for any other object
    # Monkey-patch notes: http://stackoverflow.com/questions/4470108/when-monkey-patching-a-method-can-you-call-the-overridden-method-from-the-new-i
    # (Array integration)
    def initialize(key=nil,value=nil)
      @thread_safety = ::Mutex.new
      @key = key
      @value = value
    end
    #
    def key()
      @thread_safety.synchronize { @key }
    end
    def key= (new_key=nil)
      @thread_safety.synchronize { @key = new_key }
    end
    #
    def value()
      @thread_safety.synchronize { @value }
    end
    def value= (new_value=nil)
      @thread_safety.synchronize { @value = new_value }
    end
    #
    def <=>(other_value=nil)
      if other_value.respone_to?(:<=>)
        if other_value.is_a?(GxG::Tuple)
          @thread_safety.synchronize { @value <=> other_value.value }
        else
          @thread_safety.synchronize { @value <=> other_value }
        end
      else
        # taking liberties here, if other object does not support compare, then this obj is construed as greater than. (bias)
        1
      end
    end
    def to_s()
      @thread_safety.synchronize { @value.to_s }
    end
    def inspect()
      @thread_safety.synchronize { "#{@key.inspect} => #{@value.inspect}" }
    end
    #
  end
  #
	class ByteArray
    # make as close to array as possible with one exception: only works-with/accepts Integer between 0 and 255 as elements.
    # Also: ByteArray is one-dimensional/flat --> cannot encapsulate other arrays, just Integers between 0 and 255.
    # TODO: ByteArray : fill in missing methods compared to standard Array class.
    # GxG::ByteArray::missing_methods(Array)
    protected
    #
    def filter_data(the_data="")
      #
      error_message = ("ByteArray.new expects a String, a Integer or Float between 0 and 255, a nil ( counted as padvalue() ), a ByteArray, or an Array of any of those; you provided #{the_data.inspect}")
      #
      unless the_data.is_any?(::NilClass,::String,::Numeric, ::Array, ::GxG::ByteArray)
        raise Exception.new(error_message)
      end
      if the_data.is_a?(::String)
        the_data = the_data.slice_bytes((0..-1))
      end
      if the_data.is_a?(::Numeric)
        the_data = the_data.to_i
        if (0..255).include?(the_data)
          the_data = the_data.chr
          the_data.force_encoding(Encoding::ASCII_8BIT)
        else
          raise Exception.new(error_message)
        end
      end
      if the_data.is_a?(::GxG::ByteArray)
        the_data = the_data.data().clone
      end
      if the_data.is_a?(::Array)
        temp_string = ""
        temp_string.force_encoding(Encoding::ASCII_8BIT)
        the_data.flatten.to_enum.each do |element|
          temp_string << self.filter_data(element)
        end
        if temp_string.size > 0
          the_data = temp_string
        else
          the_data = ""
          the_data.force_encoding(Encoding::ASCII_8BIT)
        end
      end
      unless the_data
        the_data = @pad_value.to_i.chr
        the_data.force_encoding(Encoding::ASCII_8BIT)
      end
      #
      the_data
    end
    #
    def filter_parameters(*args)
      # puts "Got: #{args.inspect}"
      the_range = nil
      if args[0].is_any?(::Numeric, ::Integer, ::Float, ::BigDecimal)
        args[0] = args[0].to_i
        if args[0] < 0
          args[0] = @data.bytesize + args[0]
        end
        the_range = ((args[0])..(args[0]))
        if args[1].is_a?(Numeric)
          args[1] = args[1].to_i
          if args[1] < 1
            raise ArgumentError.new("Second parameter needs to be a Numeric greater than 0, you provided #{args[1].inspect}")
          else
            the_range = ((args[0])..(args[0] + (args[1] - 1)))
          end
        end
      else
        if args[0].is_a?(Range)
          if args[0].first < 0
            args[1] = @data.bytesize + args[0].first
          else
            args[1] = args[0].first
          end
          if args[0].last < 0
            args[2] = @data.bytesize + args[0].last
          else
            args[2] = args[0].last
          end
          if args[1] <= args[2]
            the_range = ((args[1])..(args[2]))
          else
            the_range = ((args[2])..(args[1]))
          end
        else
          unless the_range
            raise ArgumentError.new("First parameter needs to be a Numeric or a Range, you provided #{args[0].inspect}")
          end
        end
      end
      the_range
    end
    #
    public
    #
    def self.try_convert(*args)
      begin
        GxG::ByteArray.new(1,[(args)])
      rescue Exception
        nil
      end
    end
    #
    def self.[](*args)
      GxG::ByteArray.new(*args)
    end
    #
    def self.process(the_array=GxG::ByteArray.new,&block)
      new_array = GxG::ByteArray.new
      if block.respond_to?(:call)
        if the_array.is_any?(::Array, ::Hash, ::GxG::ByteArray, ::Set, ::Struct)
          new_array = the_array.process(&block)
        else
          raise ArgumentError, "you must pass an Array, a ByteArray, or a Hash"
        end
      end
      new_array
    end
    #
    def self.search(the_array=GxG::ByteArray.new,&block)
      new_array = GxG::ByteArray.new
      if block.respond_to?(:call)
        if the_array.is_any?(::Array, ::Hash, ::GxG::ByteArray, ::Set, ::Struct)
          new_array = the_array.search(&block)
        else
          raise ArgumentError, "you must pass an Array, a ByteArray, or a Hash"
        end
      end
      new_array
    end
    #
    def data()
      @data
    end
    #
    def as_segments(segment_size=65536, as_bytearrays=false, &block)
      result = []
      if segment_size.is_any?(::TrueClass, ::FalseClass, NilClass)
        as_bytearrays = segment_size
        segment_size = 65536
      end
      #
      if block.respond_to?(:call)
        GxG::apportioned_ranges(self.size, segment_size).each do |portion_range|
          if as_bytearrays
            block.call(self[portion_range])
          else
            block.call(self[portion_range].to_s)
          end
        end
      else
        GxG::apportioned_ranges(self.size, segment_size).each do |portion_range|
          if as_bytearrays
            result << (self[portion_range])
          else
            result << (self[portion_range].to_s)
          end
        end
      end
      #
      result
    end
    #
	# instance methods:
	def initialize(*args,&block)
   		# Integer(how_many), <Acceptable-data-type>, <Max-size>, <Pad-value>, <Outer-value>
    	# --OR--
    	# Integer(how_many), <Max-size>, <Pad-value>, <Outer-value> &block
      @data = ""
      @data.force_encoding(Encoding::ASCII_8BIT)
      #
      memory_limits = GxG::SYSTEM.memory_limits()
			@max_size = nil
			@pad_value = 0
      @outer = nil
      # *should* create a 'self' to call upon.
      super()
      #
		if args.size > 0
        if block.respond_to?(:call)
          if args[0].is_a?(Numeric)
            args[0] = args[0].to_i
            if args[0] >= 0
              if args[0] > memory_limits[:process].first
                args[0] = memory_limits[:process].first
              end
              if args[1].is_a?(Numeric)
                self.maxsize = args[1].to_i
              end
              if args[2].is_a?(Numeric)
                self.padvalue = args[1].to_i
              end
              if args[3].is_a?(Numeric)
                self.outervalue = args[1].to_i
              end
              #
              (0..(args[0] - 1)).to_enum.each do |index|
                raw_data_array = [(block.call(index))].flatten
                raw_data_array.to_enum.each do |raw_data|
                  #
                  raw_data = (self.filter_data(raw_data) || "")
                  #
                  if raw_data.bytesize > 0
                    if (args[0] * raw_data.bytesize) > memory_limits[:process].first
                      # Attempts to project whether or not maximum memory limits will be exceeded.
                      # LATER: ByteArray.new: Might get false positives on variable return data from block (re-think this)
                      raise NoMemoryError.new("This operation will exceed available per-process memory limits")
                    end
                    @data << raw_data
                  end
                end
                #
              end
              #
              if @max_size
                if @data.bytesize > @max_size
                  @max_size = @data.bytesize
                end
              end
              #
            end
          end
        else
          #
          if args[0].is_a?(Numeric)
            how_many = args[0].to_i
            if args[1]
              raw_data_array = [(args[1])].flatten
            else
              raw_data_array = [(@pad_value.to_i.chr)]
            end
            if args[2].is_a?(Numeric)
              self.maxsize = args[2].to_i
            end
            if args[3].is_a?(Numeric)
              self.padvalue = args[3].to_i
            end
            if args[4].is_a?(Numeric)
              self.outervalue = args[4].to_i
            end
          else
            how_many = 1
            raw_data_array = [(args[0])].flatten
            if args[1].is_a?(Numeric)
              self.maxsize = args[1].to_i
            end
            if args[2].is_a?(Numeric)
              self.padvalue = args[2].to_i
            end
            if args[3].is_a?(Numeric)
              self.outervalue = args[3].to_i
            end
          end
          #
          new_data = ""
          new_data.force_encoding(Encoding::ASCII_8BIT)
          raw_data_array.to_enum.each do |raw_data|
            new_data << (self.filter_data(raw_data) || "")
          end
          if new_data.bytesize > 0
            if (how_many * new_data.bytesize) > memory_limits[:process].first
              raise NoMemoryError.new("This operation will exceed available per-process memory limits")
            end
            how_many.times do
              @data << new_data
            end
          end
          #
          if @max_size
            if @data.bytesize > @max_size
              @max_size = @data.bytesize
            end
          end
          #
        end
				#
			end
			self
		end
    #
    def mime_type()
      @data.mime_type()
    end
    #
    def process(&block)
      result = self.clone
      if block.respond_to?(:call)
        result.each_with_index do |entry,index|
          result[(index)] = block.call(entry, index, self)
        end
      end
      result
    end
    #
    def process!(&block)
      if block.respond_to?(:call)
        self.replace(self.process(&block).data())
      end
      self
    end
    #
    def search(&block)
      result = []
      if block.respond_to?(:call)
        self.each_with_index do |entry,index|
          raw_result = block.call(entry,index,self)
          if raw_result
            result << raw_result
          end
        end
      end
      result
    end
    #
    def pattern_range(the_pattern="", initial_offset=0)
      result = nil
      if the_pattern.is_a?(::ByteArray)
        the_pattern = the_pattern.to_s
      end
      if the_pattern.is_a?(::String)
        if initial_offset.is_a?(::Integer)
          if @max_size
            if initial_offset > @max_size
              raise ArgumentError, "Offset exceeds the maximum size."
            end
          end
          if the_pattern.encoding != ::Encoding::ASCII_8BIT
            the_pattern = the_pattern.clone
            the_pattern.force_encoding(::Encoding::ASCII_8BIT)
          end
          offset = @data.index(the_pattern, initial_offset)
          if offset.is_a?(::Integer)
            result = ((offset)..(offset + (the_pattern.size - 1)))
          end
        else
          raise ArgumentError, "You MUST provide the offset as an Integer."
        end
      else
        raise ArgumentError, "You MUST provide a String to find."
      end
      result
    end
    #
    def pattern_ranges(the_pattern="")
      result = []
      offset = 0
      if the_pattern.is_a?(::ByteArray)
        the_pattern = the_pattern.to_s
      end
      last_found = self.pattern_range(the_pattern,offset)
      while last_found != nil do
        if last_found.is_a?(::Range)
          result << last_found
          if (last_found.last() + 1) <= @data.bytesize
            offset = (last_found.last() + 1)
          else
            break
          end
        end
        last_found = self.pattern_range(the_pattern,offset)
      end
      result
    end
    #
    def padvalue()
      @pad_value.clone
    end
    #
		def padvalue=(*args)
			if args.size > 0
				if args[0].is_a?(Float)
					args[0] = args[0].to_i
				end
				if args[0].is_a?(Integer)
					if (0..255).include?(args[0])
            @pad_value = args[0]
					end
				else
					raise TypeError.new("Value type: expected Float or Integer.  You provided #{args[0].class}")
				end
			end
      @pad_value.clone
		end
    #
    def match(regular_expression)
      @data.match(regular_expression)
    end
    #
    def maxsize()
      @max_size.clone
    end
    #
		def maxsize=(*args)
      # Set @maxsize: Warning: setting @maxsize lower than the @data.bytesize will truncate the data
			if args.size > 0
        if args[0]
          if args[0].is_a?(Numeric)
            args[0] = args[0].to_i
          end
          #
          if args[0].is_a?(Integer)
            if args[0] > GxG::SYSTEM.memory_limits()[:process].first
              raise NoMemoryError.new("Setting maxsize this high exceeds per-process memory limits")
            end
            if args[0] > @max_size.to_i
              @max_size = args[0]
            else
              if args[0] < @max_size.to_i
                # truncate data if @max_size lowered below @data.bytesize
                @max_size = args[0]
                if @data.bytesize > args[0]
                  @data.replace(@data[0..(args[0] - 1)])
                end
              end
            end
          else
            raise ArgumentError.new("Expected NilClass or Numeric class.  You provided #{args[0].class}")
          end
        else
          @max_size = nil
        end
      else
        @max_size = nil
			end
      @max_size.clone
		end
    #
    def outervalue()
      @outer.clone
    end
    #
    def outervalue=(*args)
			if args.size > 0
        if args[0]
          if args[0].is_a?(Float)
            args[0] = args[0].to_i
          end
          if args[0].is_a?(Integer)
            if (0..255).include?(args[0])
              @outer = args[0]
            end
          else
            raise TypeError.new("Expected a NilClass, a Float, or a Integer.  You provided #{args[0].class}")
          end
        else
          @outer = nil
        end
      else
        @outer = nil
			end
      self.outervalue()
    end
    #
		def dclone()
			result = GxG::ByteArray.new(@data.clone)
			result.padvalue = (self.padvalue())
			result.maxsize = (self.maxsize())
      result.outervalue = (self.outervalue())
			result
		end
    #
    def initialize_clone()
      result = self.dclone
      if self.frozen?
        result.freeze
      end
      result
    end
    #
    def initialize_dup()
      # ByteArry is one-dimensional anyhow
      self.dclone
    end
    alias :dup :initialize_dup
    alias :initialize_copy :initialize_dup
    def clone()
      initialize_dup()
    end
    #
		def [](indexer=0, length=nil)
      self.slice(indexer,length)
		end
    #
		def []=(indexer=0, length=nil, value=nil)
      #
      if length
        unless value
          value = length
          length = nil
        end
      end
      value = self.filter_data(value)
      error = nil
      result = nil
      #
      if value
        if value.bytesize > 0
          #
          the_range = self.filter_parameters(indexer,length)
          #
          unless the_range
            if length
              error = ArgumentError.new("#{indexer.inspect},#{length.inspect} could not be fashioned into a valid Indexer")
            else
              error = ArgumentError.new("#{indexer.inspect} could not be fashioned into a valid Indexer")
            end
          end
          if error
            raise error
          end
          # check overall compliance with maxsize
          if @max_size
            if (the_range.count > @max_size || the_range.first > (@max_size - 1) || the_range.last > (@max_size - 1))
              error = IndexError.new("Index exceeds #{@max_size} limit.  You might need to adjust maxsize.")
            end
            if (the_range.first + (value.bytesize - 1)) > (@max_size - 1)
              error = RangeError.new("Data size at specified Index exceeds #{@max_size} limit.  You might need to adjust maxsize.")
            end
            #
            if indexer.is_a?(Integer)
              if length
                # replace operation
                if (the_range.first + (the_range.count - 1)) > (@max_size - 1)
                  error = RangeError.new("Range exceeds #{@max_size} limit.  You might need to adjust maxsize.")
                else
                  if the_range.count < value.bytesize and (the_range.first + (the_range.count - 1) + ((value.bytesize - 1) - (the_range.count - 1))) > (@max_size - 1)
                    error = RangeError.new("Value size exceeds #{@max_size} limit.  You might need to adjust maxsize.")
                  end
                end
              else
                # insert operation
                if (@data.size - 1 + value.bytesize) > @max_size
                  error = RangeError.new("Operation exceeds #{@max_size} limit.  You might need to adjust maxsize.")
                end
                if (the_range.first + (value.bytesize - 1)) > (@max_size - 1)
                  error = RangeError.new("Value size exceeds #{@max_size} limit.  You might need to adjust maxsize.")
                end
              end
            else
              if the_range.count > @max_size
                error = RangeError.new("Range exceeds #{@max_size} limit.  You might need to adjust maxsize.")
              else
                if the_range.count < value.bytesize and (the_range.first + (the_range.count - 1) + ((value.bytesize - 1) - (the_range.count - 1))) > (@max_size - 1)
                  error = RangeError.new("Value size exceeds #{@max_size} limit.  You might need to adjust maxsize.")
                end
              end
            end
            if error
              raise error
            end
          end
          #
          if the_range.first > (@data.bytesize - 1)
            (the_range.first - (@data.bytesize - 1)).times do
              @data << @pad_value.chr
            end
          end
          #
          if length
            @data[(the_range.first),(the_range.count)] = value
          else
            if indexer.is_a?(Numeric)
              @data[(the_range.first)] = value
            else
              @data[(the_range)] = value
            end
          end
          #
        end
        result = GxG::ByteArray.new(value)
      end
      result
		end
    #
		def |(*args)
			scrap = GxG::ByteArray::try_convert(args)
			result = self.dclone
      if scrap
        scrap.each do |byte|
          unless result.include?(byte)
            result << byte
          end
        end
      end
			result
		end
    #
		def &(*args)
      result = GxG::ByteArray.new
			if args.size > 0
        other = GxG::ByteArray::try_convert(args)
        if other
          result_scrap = ""
          result_scrap.force_encoding(Encoding::ASCII_8BIT)
          self.each do |the_byte|
            if other.include?(the_byte)
              result_scrap << the_byte.chr
            end
          end
          result = GxG::ByteArray.new(result_scrap)
        end
			end
      result
		end
    #
		def *(*args)
      result = GxG::ByteArray.new
      if self.size > 0
        if args.size > 0
          if args[0].is_a?(::String)
            result = self.join(args[0])
          else
            if args[0].is_a?(Numeric)
              scrap_size = ((args[0].to_f % args[0].to_i.to_f) * self.size.to_f).to_i
              args[0] = args[0].to_i
              if (args[0] * self.size) <= GxG::SYSTEM.memory_limits()[:process].first
                args[0].times do
                  result << self.data().clone
                end
                if scrap_size > 0
                  result << self.data()[0..(scrap_size)]
                end
              else
                raise NoMemoryError.new("This operation will exceed per-process memory limits")
              end
            else
              raise ArgumentError.new("a String or Numeric is required, you provied #{args[0].inspect}")
            end
          end
        else
          raise TypeError.new("Can't convert nil to ByteArray")
        end
      end
      result
		end
    #
		def +(*args)
      result = GxG::ByteArray.new
			if args.size > 0
        other = GxG::ByteArray::try_convert(args)
        if other
          if other.size > 0
            result = GxG::ByteArray.new(1,[(self.data().clone),(other.data())])
          end
        end
			else
				raise TypeError.new("Can't convert nil to ByteArray")
			end
      result
		end
    #
		def -(*args)
      result = GxG::ByteArray.new
      if args.size > 0
        scrap = GxG::ByteArray::try_convert(args)
        if scrap
          result_scrap = ""
          result_scrap.force_encoding(Encoding::ASCII_8BIT)
          self.each do |the_byte|
            unless scrap.include?(the_byte)
              result_scrap << the_byte.chr
            end
          end
          result = GxG::ByteArray.new(result_scrap)
        end
      end
			result
		end
    #
		def <<(*args)
			if args.size > 0
        value = GxG::ByteArray::try_convert(args)
        if value
          if @max_size
            if (@data.bytesize + value.size) > @max_size
              raise RangeError.new("Operation exceeds #{@max_size} limit.  You might need to adjust maxsize.")
            end
          end
          @data << value.data()
        end
			end
			self
		end
    #
		def <=>(*args)
      result = 1
			if args.size > 0
        if args[0].is_a?(::GxG::ByteArray)
          result = (self.data() <=> args[0].data())
        else
          # Allows sorting against std. Array or String that *would* sort normal if it were a ByteArray (byte comparison)
          other = GxG::ByteArray::try_convert(args)
          if other
            result = (self.data() <=> other.data())
          end
        end
			end
      result
		end
    #
		def ==(*args)
      result = false
			if args.size > 0
        if args[0].is_a?(::GxG::ByteArray)
          result = (self.data() == args[0].data())
        else
          # kinda cool, but might be a bridge too far for strict equivalence.
          # other = GxG::ByteArray::try_convert(args)
          # if other
          #  result = (self.data() == other.data())
          #end
        end
			end
      result
		end
    #
		def at(*args)
			if args[0].is_a?(Float)
				args[0] = args[0].to_i
			end
			if args[0].is_a?(Integer)
				self[(args[0])]
			else
				raise TypeError.new("Expected Integer or Float.  You provided #{args[0].class}")
			end
		end
    #
		def clear()
			@data.clear
			self
		end
    #
		def collect(&block)
      result = GxG::ByteArray.new
      if block.respond_to?(:call)
        result_scrap = ""
        result_scrap.force_encoding(Encoding::ASCII_8BIT)
        self.each do |the_byte|
          result_scrap << self.filter_data(block.call(the_byte))
        end
        result = GxG::ByteArray.new(result_scrap)
      else
        result = self.to_enum(:each)
      end
      result
		end
    #
		def collect!(&block)
      if block.respond_to?(:call)
        self.replace(self.collect(&block).data())
        self
      else
        self.to_enum(:each)
      end
		end
    #
    def combination(*args,&block)
      # TODO: port c code to ruby (true-enumeration-as-bytearray support)
      enumerator = @data.to_enum(:bytes).to_a.to_enum(:combination,*args)
      if block.respond_to?(:call)
        enumerator.each do |the_combination|
          block.call(GxG::ByteArray.new(the_combination))
        end
        self
      else
        # Note: this form does not put bytearrays of each combination into the block, just arrays (please fix)
        GxG::Enumerator.new(enumerator)
      end
    end
    #
    def repeated_combination(*args,&block)
      # TODO: port c code to ruby (true-enumeration-as-bytearray support)
      enumerator = @data.to_enum(:bytes).to_a.to_enum(:repeated_combination,*args)
      if block.respond_to?(:call)
        enumerator.each do |the_combination|
          block.call(GxG::ByteArray.new(the_combination))
        end
        self
      else
        GxG::Enumerator.new(enumerator)
      end
    end
    #
		def compact()
			self
		end
    #
		def concat(*args)
      result = self
			if args.size > 0
        other = GxG::ByteArray::try_convert(args)
        if other
          result = (self + other)
        else
          raise Exception.new("Could not convert #{args.inspect} to ByteArray")
        end
			end
      result
		end
    #
    def count(match_value=nil,&block)
      result = 0
      if match_value.is_a?(Numeric)
        self.each do |the_byte|
          if the_byte == match_value.to_i
            result += 1
          end
        end
      else
        if block.respond_to?(:call)
          self.each do |the_byte|
            if block.call(the_byte) == true
              result += 1
            end
          end
        else
          result = @data.bytesize
        end
      end
      result
    end
    #
    def cycle(iterations=nil,&block)
      if @data.bytesize > 0
        unless iterations.to_i < 0
          if block.respond_to?(:call)
            if iterations
              iterations.to_i.times do 
                self.each do |the_byte|
                  block.call(the_byte)
                end
              end
              nil
            else
              while true do
                self.each do |the_byte|
                  block.call(the_byte)
                end
              end
            end
          else
            @data.to_enum(:bytes).to_a.to_enum(:cycle,iterations)
          end
        end
      end
    end
    #
		def delete(*args,&block)
			result = nil
      if args[0].is_a?(Numeric)
        comparitor = self.filter_data(args[0].to_i)
        if comparitor.bytesize > 1
          comparitor = comparitor[0]
        end
        scrap = @data.delete(comparitor)
        if scrap == @data
          if block.respond_to?(:call)
            result = block.call()
          end
        else
          @data.replace(scrap)
          result = args[0]
        end
      end
      result
		end
    #
		def delete_at(*args)
			result = nil
			if args.size > 0
        the_range = self.filter_parameters(*args)
        if the_range.last < self.size
          result = @data.slice!(the_range)
        end
			end
			result
		end
    #
		def delete_if(&block)
      self.reject!(&block)
		end
    #
    def drop(length)
      self.slice((length.to_i - 1)..-1)
    end
    #
    def drop_while(&block)
      accumulator = GxG::ByteArray.new
      if block.respond_to?(:call)
        self.each do |the_byte|
          result = block.call(the_byte)
          unless result
            accumulator << the_byte
          end
        end
        accumulator
      else
        # TODO: 5xMem efficiency fix for various engine run conditions
        GxG::Enumeratior.new(@data.to_enum(:bytes).to_a.to_enum(:drop_while))
      end
    end
    #
    # TODO: GxG::ByteArray.each_index/each_with_index: improve memory efficiency and speed significantly (!)
    #
		def each(&block)
      if block.respond_to?(:call)
        if @data.bytesize > 0
          @data.to_enum(:bytes).each {|the_byte| block.call(the_byte)}
        end
        self
      else
        self.to_enum(:each)
      end
		end
    #
		def each_index(&block)
      if block.respond_to?(:call)
        if @data.bytesize > 0
          (0..(@data.bytesize - 1)).to_enum.each {|index| block.call(index)}
        end
        self
      else
        self.to_enum(:each_index)
      end
		end
    #
		def each_with_index(offset=0,&block)
      if block.respond_to?(:call)
        if @data.bytesize > 0
          # bulky, but required to support self.reject!, etc :
          @data.to_enum(:bytes).with_index(offset).each {|value,index| block.call(value,index)}
          #old : (0..(@data.bytesize - 1)).to_enum.each {|index| block.call(@data[(index)].ord,index)}
        end
        self
      else
        self.to_enum(:each_with_index,offset)
      end
		end
    #
		def empty?()
			@data.bytesize == 0
		end
    #
		def eql?(*args)
      if args.size > 0
        self == args[0]
      else
        false
      end
		end
    #
		def fetch(*args,&block)
      #fetch(index) → obj click to toggle source
      #fetch(index, default ) → obj
      #fetch(index) {|index| block } → obj
      #
      #Tries to return the element at position index. If the index lies outside the array, the first form throws an IndexError exception,
      # the second form returns default, and the third form returns the value of invoking the block, passing in the index.
      # Negative values of index count from the end of the array.
      # LATER: ByteArray.fetch: check how to incorporate 'padded-edges' feature
      if args.size > 0
        if args[0].is_a?(Numeric)
          args[0] = self.filter_parameters(args[0].to_i).first
          if args[0] >= self.size
            if args[1]
              if block.respond_to?(:call)
                block.call(args[0])
              else
                args[1]
              end
            else
              raise IndexError.new("Index specified lies outside the ByteArray")
            end
          else
            self.at(args[0])
          end
        end
      end
		end
    #
		def fill(*args,&block)
      #fill(obj) → ary click to toggle source
      #fill(obj, start [, length]) → ary
      #fill(obj, range ) → ary
      #fill {|index| block } → ary
      #fill(start [, length] ) {|index| block } → ary
      #fill(range) {|index| block } → ary
      #
      #The first three forms set the selected elements of self (which may be the entire array) to obj. A start of nil is equivalent to zero. 
      #A length of nil is equivalent to self.length. The last three forms fill the array with the value of the block. 
      #The block is passed the absolute index of each element to be filled. Negative values of start count from the end of the array.
      #a = [ "a", "b", "c", "d" ]
      #a.fill("x")              #=> ["x", "x", "x", "x"]
      #a.fill("z", 2, 2)        #=> ["x", "x", "z", "z"]
      #a.fill("y", 0..1)        #=> ["y", "y", "z", "z"]
      #a.fill {|i| i*i}         #=> [0, 1, 4, 9]
      #a.fill(-2) {|i| i*i*i}   #=> [0, 1, 8, 27]
      # Note: if ByteArray is empty, it will be filled to @max_size, otherwise only the used portion or specified range.
      result = nil
      result_scrap = ""
      result_scrap.force_encoding(Encoding::ASCII_8BIT)
      #
      if block.respond_to?(:call)
        if args.size > 0
          if args[0].is_a?(Numeric)
            args[0] = args[0].to_i
            if args[0] < 0
              if args[1].is_a?(Numeric)
                if args[1].to_i > 0
                  args = [((@data.bytesize + args[0])..(@data.bytesize + args[0] + (args[1].to_i - 1)))]
                else
                  raise ArgumentError.new("length specified should be a positive Integer for Float")
                end
              else
                args = [((@data.bytesize + args[0])..(@data.bytesize - 1))]
              end
            end
          end
          fillrange = self.filter_parameters(*args)
        else
          fillrange = (0..((@max_size || @data.bytesize) - 1))
        end
        (0..(@data.bytesize - 1)).to_enum.each do |index|
          if fillrange.include?(index)
            raw_value = self.filter_data(block.call(index))
            if raw_value.size > 0
              # Allow only single byte results to merge into fill
              # since the concept is 'per-item' which in this case is a single byte only.
              result_scrap << raw_value[0]
            else
              result_scrap << @pad_value.chr
            end
          else
            result_scrap << @data[(index)]
          end
        end
      else
        if args.size > 0
          value = nil
          case args.size
          when 1
            fillrange = (0..((@max_size || @data.bytesize) - 1))
            value = self.filter_data(args[0])
          when 2
            fillrange = self.filter_parameters(args[1])
            value = self.filter_data(args[0])
          when 3
            fillrange = self.filter_parameters(args[1],args[2])
            value = self.filter_data(args[0])
          else
            fillrange = self.filter_parameters(args[1],args[2])
            value = self.filter_data(args[0])
          end
          value = (value || @pad_value.chr)
          #
          (0..(@data.bytesize - 1)).to_enum.each do |index|
            if fillrange.include?(index)
              result_scrap << value
            else
              result_scrap << @data[(index)]
            end
          end
        else
          raise ArgumentError.new("wrong number of arguments (0 for 1..3)")
        end
      end
      if result_scrap.size > 0
        self.replace(result_scrap)
      end
      self
		end
    #
		def first(*args)
			if args.size > 0
				if args[0].is_a?(Float)
					args[0] = args[0].to_i
				end
				if args[0].is_a?(Integer)
					if args[0] > 0
            if @max_size
              unless args[0] <= @max_size
                raise RangeError.new("#{args[0]} is out of range (1 - #{@max_size}).")
              end
            end
						self[(0..(args[0] - 1))]
					end
				else
					raise TypeError.new("Expected Integer.  You provided #{args[0].class}")
				end
			else
				self[0]
			end
		end
    #
		def flatten()
			# ByteArray is always flat anyhow
			self.dclone
		end
    #
		def flatten!()
			# ByteArray is always flat anyhow
			self
		end
    #
    def freeze()
      @data.freeze
      @max_size.freeze
      @pad_value.freeze
      @outer.freeze
      super()
    end
    #
		def hash()
			@data.hash
		end
    #
		def include?(*args)
			if args.size > 0
				if args[0].is_a?(Float)
					args[0] = args[0].to_i
				end
				if args[0].is_a?(Integer)
					if (0..255).include?(args[0])
						@data.include?(args[0].chr)
					else
						raise RangeError.new("Value out of range: range is 0 to 255.  You provided #{args[0]}")
					end
				else
					raise TypeError.new("Expected Integer or Float.  You provided #{args[0].class}")
				end
			else
				raise ArgumentError.new("Wrong number of arguments (#{args.size} for 1).")
			end
		end
    #
		def find_index(*args, &block)
			result = nil
      if block.respond_to?(:call)
        found_at = 0
        @data.to_enum(:bytes).each do |the_byte|
          if block.call(the_byte) == true
            result = found_at
            break
          end
          found_at += 1
        end
      else
        if args.size > 0
          if args[0].is_a?(Float)
            args[0] = args[0].to_i
          end
          if args[0].is_a?(Integer)
            if (0..255).include?(args[0])
              if args[1]
                # offset specified (addtional option vs standard Array)
                result = @data.index(args[0].chr,args[1])
              else
                result = @data.index(args[0].chr)
              end
            end
          else
            raise TypeError.new("Expected Integer or Float.  You provided #{args[0].class}")
          end
        else
          result = @data.to_enum(:bytes)
        end
      end
			result
		end
    #
		def insert(*args)
			if args.size > 1
				if args[0].is_a?(Float)
					args[0] = args[0].to_i
				end
				if args[0].is_a?(Integer)
					value = self.filter_data(args[(1..(args.size - 1))])
          if @max_size
            unless (@data.bytesize + value.bytesize) <= @max_size
              raise RangeError.new("Operation exceeds #{@max_size} limit.  You need to adjust maxsize.")
            end
          end
          begin
            @data.insert(args[0],value)
          rescue Exception => error
            raise error.exception(error.message.gsub("string",(self.class.to_s)))
          end
				else
					raise TypeError.new("Expected Integer or Float.  You provided #{args[0].class}")
				end
			else
				raise ArgumentError.new("Wrong number of arguments (#{args.size} for 2).")
			end
			self
		end
    #
		def inspect()
      result = "["
      @data.to_enum(:bytes).each do |the_byte|
        if result.size > 1
          result << ", "
        end
        if the_byte > 10
          result << "0x#{the_byte.to_s(16).upcase}"
        else
          result << "0x0#{the_byte.to_s(16).upcase}"
        end
      end
      result << "]"
      result
		end
    #
		def join(*args)
      result = ""
      if args[1].is_a?(Encoding)
        # Extra optional encoding vs standard Array
        result.force_encoding(args[1])
      else
        result.force_encoding(Encoding::ASCII_8BIT)
      end
      @data.to_enum(:bytes).each do |the_byte|
        if (args[0].is_a?(String) && result.size > 0)
          result << (args[0] + the_byte.chr)
        else
          result << the_byte.chr
        end
      end
      result
		end
    #
		def last(*args)
			if args.size > 0
				if args[0].is_a?(Float)
					args[0] = args[0].to_i
				end
				if args[0].is_a?(Integer)
					if args[0] > 0
            the_range = ((@data.bytesize - 1 - (args[0] - 1))..(@data.bytesize - 1))
            if @max_size
              unless args[0] <= @max_size
                raise RangeError.new("#{args[0]} is out of range (1 - #{@max_size}).")
              end
            end
						self[(the_range)]
					else
						raise RangeError.new("#{args[0]} is out of range (1 - #{@max_size}).")
					end
				else
					raise TypeError.new("Expected Integer.  You provided #{args[0].class}")
				end
			else
				self[(@data.bytesize - 1)]
			end
		end
    #
		def pack(*args)
      result = ""
			if args.size >= 1
				args[0] = (args[0] || "")
				if args[0].is_a?(String)
          if args[1].is_a?(Encoding)
            # Extra optional encoding vs standard Array
            result.force_encoding(args[1])
          end
          # LATER: ByteArray.pack: a more memory-efficient method is needed here long term.  For now: leverage Array.pack.
          # Each byte will take up 4 to 8 bytes depending just to get packed into a string ... gotta fix this.
					result << self.to_a.pack(args[0])
				else
					raise TypeError.new("Expected String.  You provided #{args[0].class}")
				end
			else
				raise ArgumentError.new("Wrong number of arguments (#{args.size} for 1+).")
			end
      result
		end
    #
    def permutation(*args,&block)
      # TODO: port c code to ruby (true-enumeration-as-bytearray support)
      enumerator = @data.to_enum(:bytes).to_a.to_enum(:permutation,*args)
      if block.respond_to?(:call)
        enumerator.each do |the_permutation|
          block.call(GxG::ByteArray.new(the_permutation))
        end
        self
      else
        GxG::Enumerator.new(enumerator)
      end
    end
    #
    def repeated_permutation(*args,&block)
      # TODO: port c code to ruby (true-enumeration-as-bytearray support)
      enumerator = @data.to_enum(:bytes).to_a.to_enum(:repeated_permutation,*args)
      if block.respond_to?(:call)
        enumerator.each do |the_permutation|
          block.call(GxG::ByteArray.new(the_permutation))
        end
        self
      else
        GxG::Enumerator.new(enumerator)
      end
    end
    #
		def pop(how_many=nil)
      # LIFO style stack operation
      result = nil
      if how_many.is_a?(Numeric)
        unless how_many.to_i > 0
          raise ArgumentError.new("#{how_many} needs to be a positive Numeric")
        end
        result = ::GxG::ByteArray.new
        how_many.times do
          result << self.delete_at(-1)
        end
      else
        result = self.delete_at(-1)
      end
      result
		end
    #
    def product(*others,&block)
      if @data.bytesize > 0
        others = GxG::ByteArray.new(others)
        if block.respond_to?(:call)
          self.each do |the_byte|
            others.each do |other_byte|
              block.call(GxG::ByteArray.new([(the_byte),(other_byte)]))
            end
          end
          self
        else
          accumulator = GxG::ByteArray.new
          self.each do |the_byte|
            others.each do |other_byte|
              accumulator << the_byte
              accumulator << other_byte
            end
          end
          accumulator
        end
      else
        self
      end
    end
    #
		def push(*args)
      # LIFO style stack operation
			self << GxG::ByteArray.new(args)
		end
    #
		def rassoc(key=nil)
			nil
		end
    #
		def reject(&block)
			result = nil
      if block.respond_to?(:call)
        result = GxG::ByteArray.new
				result.padvalue = (@pad_value)
        if @max_size
          result.maxsize = (@max_size)
        end
        self.to_enum.each do |the_byte|
          result << the_byte
        end
      else
        result = self.to_enum
      end
			result
		end
    #
		def reject!(&block)
      result = nil
      if block.respond_to?(:call)
        purgelist = []
        self.each_with_index do |value, index|
          if block.call(value) == true
            @data[(index)] = ""
            purgelist << index
          end
        end
        result = self
      else
        result = self.to_a.to_enum(:reject!)
      end
      result
		end
    #
		def replace(*args)
      # replace data payload while leaving max_size and pad_value untouched, fitting replacement data into in-place constraints if any.
			if args.size > 0
        replacement = nil
        if args[0].is_a?(::GxG::ByteArray)
          replacement = args[0].data()
        end
        unless replacement.is_a?(::String)
          replacement = GxG::ByteArray::try_convert(args)
          if replacement
            replacement = replacement.data()
          end
        end
        if replacement
          replacement.force_encoding(Encoding::ASCII_8BIT)
          if @max_size
            if replacement.bytesize <= @max_size
              @data.replace(replacement)
            else
              @data.replace(replacement[(0..(@max_size - 1))])
            end
          else
            @data.replace(replacement)
          end
        else
          raise Exception.new("Could not convert #{args[0].class} to ByteArray")
        end
			end
			self
		end
    #
		def reverse()
			result = GxG::ByteArray.new(@data.reverse)
			result.padvalue = (@pad_value.clone)
      if @max_size
        result.maxsize = (@max_size.clone)
      end
			result
		end
    #
		def reverse!()
			@data.reverse!
			self
		end
    #
		def reverse_each(&block)
      result = nil
			if block.respond_to?(:call)
        # use duplicate of self, do not preserve frozen state.
        result = self.dup
        result.clear
				@data.reverse.to_enum(:bytes).each {|the_byte| result << block.call(the_byte)}
			else
				# ballons mem footprint x2: *ouch* - don't know a better way yet.
        result = self.clone.reverse!.to_enum
			end
      result
		end
    #
    def rotate(vector=1)
      unless vector.is_a?(Numeric)
        raise ArgumentError.new("Expected a Numeric, you provided #{vector.class}")
      end
      # from array.c : rotate_count
      if vector < 0
        vector = (self.size - (~vector % self.size) - 1).to_i
      else
        vector = (vector % self.size).to_i
      end
      if GxG::Engine.memory_load_high?
        # trade speed for (2x) space
        scrap = []
        unless vector == 0
          the_range = self.filter_parameters(((vector)..-1))
          scrap << self[(the_range)]
          if the_range.first > 0
            scrap << self[(0..(the_range.first - 1))]
          end
        end
        if scrap.size > 0
          result = GxG::ByteArray.new(scrap)
        else
          result = self.dclone
        end
      else
        # trade (5x) space for speed
        result = GxG::ByteArray.new(self.to_a.rotate(vector))
      end
      result
    end
    #
		def rotate!(vector=1)
      if vector.is_a?(Numeric)
        if vector.to_i != 0
          new_data = self.rotate(vector).data()
          unless @data.hash == new_data.hash
            self.replace(new_data)
          end
        end
      else
        raise ArgumentError.new("Expected a Numeric, you provided #{vector.class}")
      end
			self
		end
    #
    def sample(*args)
      GxG::ByteArray.new(@data.to_enum(:bytes).to_a.sample(*args))
    end
    #
		def select(&block)
			result = GxG::ByteArray.new
			result.maxsize = (@max_size)
			result.padvalue = (@pad_value)
      result.outervalue = (@outer)
			if block.respond_to?(:call)
				self.each do |value|
					unless block.call(value) == false
						result << value
					end
				end
      else
        self.to_enum(:each)
			end
			result
		end
    #
		def select!(&block)
      if block.respond_to?(:call)
        state = @data.hash
        self.replace(self.select(&block).data())
        if state == @data.hash
          nil
        else
          self
        end
      else
        self.to_enum(:each)
      end
		end
    #
		def shift()
      # FIFO style pop
			self.delete_at(0)
		end
    #
    def shuffle(*args)
      GxG::ByteArray.new(@data.to_enum(:bytes).to_a.shuffle(*args))
    end
    #
    def shuffle!(*args)
      self.replace(self.shuffle(*args))
      self
    end
    #
		def size()
      @data.bytesize
		end
    #
    def slice(indexer=0, length=nil)
      the_range = self.filter_parameters(indexer,length)
      unless the_range
        if length
          raise ArgumentError.new("#{indexer.inspect},#{length.inspect} could not be fashioned into a valid Indexer")
        else
          raise ArgumentError.new("#{indexer.inspect} could not be fashioned into a valid Indexer")
        end
      end
			# check overall compliance with maxsize
      if @max_size
        if ((the_range.count > @max_size) || (the_range.first > (@max_size - 1)) || (the_range.last > (@max_size - 1)))
          raise IndexError.new("Index exceeds #{@max_size} limit.  You need to adjust maxsize.")
        end
      end
			#
			result = nil
      #
      if the_range
        if the_range.first == the_range.last
          result = @data.byte_at(the_range.first)
        else
          result = @data.bytes_at(the_range)
        end
      end
      #
			result
    end
    #
		def slice!(indexer=0, length=nil)
      replacement = self.slice(indexer,length)
      if replacement.is_a?(Numeric)
        self.replace(replacement.chr)
      else
        self.replace(replacement)
      end
      if self.size == 1
        self.slice(0)
      else
        self
      end
		end
    #
    # BETA: ByteArray : see about self.to_a replacement (memory efficiency) in sort methods.
    #
		def sort(&block)
			if block.respond_to?(:call)
				GxG::ByteArray.new(self.to_a.sort {|a,b| pause;block.call(a,b)})
			else
				GxG::ByteArray.new(self.to_a.sort)
			end
		end
    #
		def sort!(&block)
			if block.respond_to?(:call)
        self.replace(self.sort(&block).data())
			end
			self
		end
    #
		def sort_by!(&block)
			if block.respond_to?(:call)
        self.replace(GxG::ByteArray.new(self.to_a.sort_by! {|a,b| pause;block.call(a,b)}).data())
        self
			else
				self.to_enum(:sort_by!)
			end
		end
    #
    def take(length)
      self.slice(0..(length.to_i - 1))
    end
    #
    def take_while(&block)
      if block.respond_to?(:call)
        accumulator = GxG::ByteArray.new
        self.each do |the_byte|
          result = block.call(the_byte)
          if result
            accumulator << the_byte
          else
            break
          end
        end
        accumulator
      else
        self.to_enum(:take_while)
      end
    end
    #
		def to_a()
			result = []
			if @data.bytesize > 0
				(0..(@data.bytesize - 1)).to_enum.each {|index| result << self[(index)]}
			end
			result
		end
    #
		def to_s()
			@data.dup
		end
    #
    def to_json()
      (("binary:" + self.to_s).encode64)
    end
    #
		def transpose()
			self.dclone
		end
    #
		def uniq(&block)
      if block.respond_to?(:call)
        harness = Proc.new do |element|
          pause
          block.call(element)
        end
        GxG::ByteArray.new(self.to_a.uniq(&harness))
      else
        self
      end
		end
    #
		def uniq!(&block)
			scrap = self.uniq(&block)
			if scrap.size == self.size
				nil
			else
				self.replace(scrap)
				self
			end
		end
    #
		def unshift(*args)
      # FIFO style push
			if args.size > 0
				self.insert(0,args)
			end
			self
		end
    #
		def values_at(*args)
			result = GxG::ByteArray.new
			if args.size > 0
        result_scrap = ""
        result_scrap.force_encoding(Encoding::ASCII_8BIT)
				args.to_enum.each do |selector|
					if selector.is_a?(Numeric) or selector.is_a?(Range)
            unless selector.is_a?(Range)
              selector = selector.to_i
            end
						scrap = self[(selector)]
            if scrap.is_a?(Integer)
              result_scrap << scrap.chr
            else
              result_scrap << scrap.data()
            end
					else
						raise TypeError.new("Expected Integer, Float or Range.  You provided #{selector.class}")
					end
				end
        result = GxG::ByteArray.new(result_scrap)
			end
			result
		end
    #
		def zip(*args,&block)
			# Converts any valid argument values to array, then merges elements of self with corresponding elements from each argument
			# This generates a sequence of self.size n-element ByteArrays as step buffers, where n is one more that the count of arguments
			# * Then flattened output as ByteArray *
			# If the size of any argument is less than enumObj.size, @pad_value is supplied
			# If a block given, it is invoked for each output array.
			# If block returns an array or ByteArray, it replaces the provided buffer and is appended to output.
			#
      result = nil
      if args.size > 0
        result_scrap = ""
        result_scrap.force_encoding(Encoding::ASCII_8BIT)
        args.to_enum(:each_index).each do |index|
          unless args[(index)].is_a?(GxG::ByteArray)
            args[(index)] = GxG::ByteArray.new(args[(index)])
          end
        end
        self.each_with_index do |byte,index|
          #
          buffer = ""
          buffer.force_encoding(Encoding::ASCII_8BIT)
          buffer << byte.chr
          args.to_enum(:each_index).each do |arg_index|
            if index >= args[(arg_index)].size
              buffer << @pad_value.chr
            else
              buffer << args[(arg_index)].data()[(index)]
            end
          end
          #
          if block.respond_to?(:call)
            # I want to differ from stock array.zip behavior:
            # I want to have it possible to return the processed buffer back -
            # to a result ByteArray if result of yield = array/ByteArray.
            raw_new = block.call(GxG::ByteArray.new(buffer))
            if raw_new
              buffer = GxG::ByteArray.new(raw_new).data()
            end
          end
          result_scrap << buffer
        end
        result = GxG::ByteArray.new(result_scrap)
      else
        result = self.dclone
      end
      result
		end

		# Method Aliases
    alias :assoc :rassoc
		alias :map :collect
		alias :map! :collect!
		alias :compact! :compact
		alias :indices :values_at
		alias :indexes :values_at
    alias :rindex :find_index
    alias :index :find_index
		alias :length :size
		alias :nitems :size
		alias :to_ary :to_a
    alias :keep_if :select!

		# Byte Operations
    
    # GxG Convenience Methods:
    def paths_to(object=nil,base_path="")
      # new idea here:
      search_results = []
      # TODO: if paths can use ranges, expand to use string or byte or int byte or byte-pattern matching to define returned valid path for get/set.
      if object.is_a?(Numeric)
        self.to_enum.each_with_index do |entry,index|
          if entry == object.to_i
            search_results << (base_path + "/" + index.to_s)
          end
        end
      end
      search_results
    end
    #
    def get_at_path(the_path="/")
      # TODO: question: would it serve much to allow ranges as structure-path specifier?  What would that involve?
      # /^(?:[0-9])*[0-9](?:[0-9])*$/ = nil if an alpha present there, else 0 only numeric
      # Attribution : http://stackoverflow.com/questions/1240674/regex-match-a-string-containing-numbers-and-letters-but-not-a-string-of-just-nu
      #
      # if ":" detected do: (str.gsub("%2f","/").to_sym) as key else (str.gsub("%2f","/"))
      result = nil
      if the_path == "/"
        result = self
      else
        object_stack = [(self)]
        path_stack = the_path.split("/")
        path_stack.to_enum.each do |path_element|
          element = nil
          if path_element.size > 0
            if (path_element =~ /^(?:[0-9])*[0-9](?:[0-9])*$/) == 0
              element = path_element.to_i
            end
          end
          if element
            result = object_stack.first[(element)]
            if result.is_a?(NilClass)
              break
            else
              object_stack.unshift(result)
            end
          else
            # ignore double slashes? '//'
            # break
          end
        end
      end
      result
    end
    #
    def set_at_path(the_path="/",the_value=nil)
      result = nil
      if the_path != "/"
        container = self
        if container
          raw_selector = ::File::basename(the_path)
          selector = nil
          if raw_selector.size > 0
            if (raw_selector =~ /^(?:[0-9])*[0-9](?:[0-9])*$/) == 0
              selector = raw_selector.to_i
            end
          end
          if selector
            container[(selector)] = the_value
            if container[(selector)] == the_value
              result = true
            end
          else
            # ignore double slashes? '//'
            # break
          end
          #
        end
      end
      result
    end
	end
  #
end
#
