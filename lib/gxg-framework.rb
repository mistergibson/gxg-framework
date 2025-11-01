# shell command:
module Kernel
  def shell(command=nil,&block)
    if command.to_s.size > 0
      block.call(`#{command.to_s}`)
      true
    end
  end
end
# bootstrap.rb is a separate file so other external scripts can avail themselves of it.
require(::File.expand_path(::File.dirname(__FILE__) << "/gxg/bootstrap.rb"))
# Load base requirements: 
requirements = []
requirements.push({:requirement => "ostruct", :gem => nil})
requirements.push({:requirement => "logger", :gem => nil})
requirements.push({:requirement => "fileutils", :gem => nil})
requirements.push({:requirement => "bigdecimal", :gem => nil})
requirements.push({:requirement => "singleton", :gem => nil})
requirements.push({:requirement => "set", :gem => nil})
requirements.push({:requirement => "csv", :gem => nil})
requirements.push({:requirement => "uri", :gem => nil})
requirements.push({:requirement => "socket", :gem => nil})
requirements.push({:requirement => "resolv", :gem => nil})
requirements.push({:requirement => "stringio", :gem => nil})
requirements.push({:requirement => "date", :gem => nil})
requirements.push({:requirement => "ffi", :gem => "ffi"})
requirements.push({:requirement => "base64", :gem => nil})
requirements.push({:requirement => "digest/md5", :gem => nil})
requirements.push({:requirement => "digest/sha2", :gem => nil})
requirements.push({:requirement => "securerandom", :gem => nil})
requirements.push({:requirement => "json", :gem => nil})
requirements.push({:requirement => "sys-cpu", :gem => "sys-cpu"})
requirements.push({:requirement => "sys-proctable", :gem => "sys-proctable"})
requirements.push({:requirement => "chronic", :gem => "chronic"})
# FIX : big hassle with windows - exclude for now
# requirements.push({:requirement => "ffi-rzmq", :gem => "ffi-rzmq"})
# requirements.push({:requirement => "ezmq", :gem => "ezmq"})
# requirements.push({:requirement => "nokogiri", :gem => "nokogiri"})
requirements.push({:requirement => "rufus-scheduler", :gem => "rufus-scheduler"})
requirements.push({:requirement => "shared-mime-info", :gem => "shared-mime-info"})
requirements.push({:requirement => "mimemagic", :gem => "mimemagic"})
#requirements.push({:requirement => "mimemagic/overlay", :gem => "mimemagic"})
requirements.push({:requirement => "bcrypt", :gem => "bcrypt"})
requirements.push({:requirement => "matrix_sdk", :gem => "matrix_sdk"})
requirements.push({:requirement => "state_machines", :gem => "state_machines"})
# consider adding facets later - esp. if file io needs extension
# ### Database Adapter for JRuby:
if ::RUBY_ENGINE == "jruby"
  requirements.push({:requirement => "jdbc/sqlite3", :gem => "jdbc-sqlite3"})
  requirements.push({:requirement => "jdbc/mysql", :gem => "jdbc-mysql"})
  requirements.push({:requirement => "jdbc-postgresql", :gem => "jdbc-postgresql"})
  requirements.push({:requirement => "jdbc/as400", :gem => "jdbc-as400"})
  requirements.push({:requirement => "jdbc/cassandra", :gem => "jdbc-cassandra"})
  requirements.push({:requirement => "jdbc/crate", :gem => "jdbc-crate"})
  requirements.push({:requirement => "jdbc/derby", :gem => "jdbc-derby"})
  requirements.push({:requirement => "jdbc/filemaker", :gem => "jdbc-filemaker"})
  requirements.push({:requirement => "jdbc/firebird", :gem => "jdbc-firebird"})
  requirements.push({:requirement => "jdbc/h2", :gem => "jdbc-h2"})
  requirements.push({:requirement => "jdbc/hive2", :gem => "jdbc-hive2"})
  requirements.push({:requirement => "jdbc/hsqldb", :gem => "jdbc-hsqldb"})
  requirements.push({:requirement => "jdbc/jt400", :gem => "jdbc-jt400"})
  requirements.push({:requirement => "jdbc/jtds", :gem => "jdbc-jtds"})
  requirements.push({:requirement => "jdbc/luciddb", :gem => "jdbc-luciddb"})
  # ### FIX : MS-SQL Server driver not in OpenJDK 14 - exclude on THAT JDK for now
  if ENV_JAVA.is_a?(::Hash)
    if ENV_JAVA['java.specification.version'] == "1.8"
      requirements.push({:requirement => "jdbc/mssql", :gem => "jdbc-mssql"})
    end
  end
  requirements.push({:requirement => "jdbc/nuodb", :gem => "jdbc-nuodb"})
  # ### FIX : openedge requires external .jars in classpath -- exclude for now.
  # requirements.push({:requirement => "jdbc/openedge", :gem => "jdbc-openedge"})
  requirements.push({:requirement => "jdbc/orientdb", :gem => "jdbc-orientdb"})
  requirements.push({:requirement => "jdbc/phoenix", :gem => "jdbc-phoenix"})
  # ### FIX : redshift is missing the RedshiftJDBC4.jar file
  # requirements.push({:requirement => "redshift", :gem => "jdbc-redshift"})
  requirements.push({:requirement => "jdbc/splice", :gem => "jdbc-splice"})
  requirements.push({:requirement => "jdbc/vertica", :gem => "jdbc-vertica"})
end
# ### Load Requirements
load_error = nil
requirements.to_enum.each do |entry|
	begin
    require entry[:requirement]
	rescue LoadError => the_error
		puts "Error: Missing Requirement\n" + the_error.to_s + "\n"
		if entry[:gem]
			puts "You need to install " + (entry[:gem]) + ", like so:\n"
			puts "sudo gem install '" + (entry[:gem]) + "'"
		else
			puts "You need to install " + (entry[:requirement]) + "."
		end
		load_error = true
    break
	end
end
unless load_error
  ## ---------------------------------------------------------------------------------------------------------------------
  # Various preliminary patches to dependencies:
  # ---------------------------------------------------------------------------------------------------------------------
  # Various preliminary patches to standard classes:
  # <none>
  # ---------------------------------------------------------------------------------------------------------------------
  # main module declaration:
  module GxG
    #
    def self.uuid_generate()
      ::SecureRandom::uuid.to_s
    end
    # LOG = $LOG
    LOG = ::Logger.new(STDOUT)
    #
  end
  #
  # ---------------------------------------------------------------------------------------------------------------------
  # Various data element classes:
  require File.expand_path("./gxg/gxg_elements.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # Preliminary alternations to Kernel/Object class: Actor/Event support
  class Object
    # private methods
    private
    def this()
      self
    end
    #
    def pause(params={})
      #
    end
    # public methods
    public
    def is_any?(*args)
      result = false
      args.flatten.to_enum.each do |thing|
        if thing.class == Class
          if self.is_a?(thing)
            result = true
            break
          end
        end
      end
      result
    end
    #
    def alive?()
      # Why: adjusting the entire object space to dealing with possibilities introduced by Celluloid.
      true
    end
    #
    def actor?()
      false
    end
    #
    def handle_error(the_error={})
      if the_error[:error].is_a?(::Exception)
        log_error(the_error)
      end
    end
    #
    def serialize()
      if self.is_any?(::Array, ::Hash, ::Set, ::Struct)
        data = self.process do |entry, selector|
          entry.serialize()
        end
        begin
          ("structure:" + ::Marshal.dump(data).encode64())
        rescue Exception => the_error
          "marshal:BAgw"
        end
      else
        if self.is_a?(::String)
          if self.serialized?()
            self
          else
            ("marshal:" + ::Marshal.dump(self).encode64())
          end
        else
          # by default, or upon error, returns marshaled nil, must override to get other serialization
          begin
            ("marshal:" + ::Marshal.dump(self).encode64())
          rescue Exception => the_error
            "marshal:BAgw"
          end
        end
      end
    end
    #
  end
  # ---------------------------------------------------------------------------------------------------------------------
  # Units and support element classes:
  require File.expand_path("./gxg/gxg_units.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # Event classes:
  require File.expand_path("./gxg/gxg_events.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # ---------------------------------------------------------------------------------------------------------------------
  # Additional alternations to Kernel/Object class: Data element class support, quota support functions
  module Kernel
    #
    #  alias :stock_enum_for :enum_for
    #  alias :stock_to_enum :to_enum
    #  def enum_for(method=:each,*args)
    #    GxG::Enumerator.new(self,method,*args)
    #  end
    #  alias :to_enum :enum_for
    #
    def slots_used(counted=[], options={})
      # returns how many heap slots are consumed by this *instance* (and elements) and its instance variables (and elements) all the way down.
      # General Research: see memprof for how much is consumed by a Module or Class or Method.
      # TODO: ::Kernel#slots_used : find the byte-size of a given :method and add it to slot_count initial value.
      unless counted.is_a?(Array)
        if counted.is_a?(Hash)
          options = counted
        end
        counted = []
      end
      # warning: assumes references to nil incur no RVALUE allocation.
      exclusions = [nil]
      if options[:exclude]
        unless options[:exclude].is_a?(Array)
          options[:exclude] = [(options[:exclude])]
        end
        exclusions = (options[:exclude] << nil)
      end
      slot_count = 0
      unless (counted.include?(self) || exclusions.include?(self))
        counted << self
        slot_count = 1
        if self.is_any?(::Array,::Hash,::Set,::Struct)
          self.search do |entry,selector,container|
            unless (counted.include?(entry) || exclusions.include?(entry))
              unless selector.is_a?(Numeric)
                slot_count += selector.slots_used(counted, {:exclude => exclusions})
              end
              slot_count += entry.slots_used(counted, {:exclude => exclusions})
            end
          end
        end
      end
      self.instance_variables.to_enum.each do |ivar|
        unless (counted.include?(ivar) || exclusions.include?(ivar))
          if ivar.is_any?(::Array,::Hash,::Set,::Struct)
            ivar.search do |entry,selector,container|
              unless (counted.include?(entry) || exclusions.include?(entry))
                unless selector.is_a?(Numeric)
                  slot_count += selector.slots_used(counted, {:exclude => exclusions})
                end
                slot_count += entry.slots_used(counted, {:exclude => exclusions})
              end
            end
          else
            slot_count += ivar.slots_used(counted, {:exclude => exclusions})
          end
        end
      end
      slot_count
    end
    #
    def content_size_used(counted=[], options={})
      # returns how many bytes are consumed by this *instance* (and elements) and its instance variables (and elements) all the way down.
      unless counted.is_a?(Array)
        if counted.is_a?(Hash)
          options = counted
        end
        counted = []
      end
      exclusions = [nil]
      if options[:exclude]
        unless options[:exclude].is_a?(Array)
          options[:exclude] = [(options[:exclude])]
        end
        exclusions = (options[:exclude] << nil)
      end
      count = 0
      unless (counted.include?(self) || exclusions.include?(self))
        counted << self
        if self.is_any?(::Array,::Hash,::Struct)
          self.search do |entry,selector,container|
            unless counted.include?(entry)
              unless selector.is_a?(Numeric)
                count += selector.content_size_used(counted, {:exclude => exclusions})
              end
              count += entry.content_size_used(counted, {:exclude => exclusions})
            end
          end
        else
          unless self.is_a?(::GxG::ByteArray)
            if self.respond_to?(:bytesize)
              count = self.bytesize
            else
              if self.respond_to?(:size)
                count = self.size
              else
                # TODO: cull the size of more exotic classes by class:
                count = 0
              end
            end
          end
        end
      end
      #
      self.instance_variables.to_enum.each do |ivar|
        # must decode from symbol to actual instance var
        ivar = self.instance_eval(ivar.to_s)
        unless (counted.include?(ivar) || exclusions.include?(ivar))
          if ivar.is_any?(::Array,::Hash,::Struct)
            ivar.search do |entry,selector,container|
              unless (counted.include?(entry) || exclusions.include?(entry))
                unless selector.is_a?(Numeric)
                  # Symbols and Strings in Hashes take up heap space, so lets count it.
                  count += selector.content_size_used(counted, {:exclude => exclusions})
                end
                count += entry.content_size_used(counted, {:exclude => exclusions})
              end
            end
          else
            unless (counted.include?(ivar) || exclusions.include?(ivar))
              count += ivar.content_size_used(counted, {:exclude => exclusions}).to_i
              # Subsequent references to this object will only incur an RVALUE slot count (me thinks)
              counted << ivar
            end
          end
        end
      end
      count
    end
    #
  end
  #
  class Object
    include Kernel
    #
    private
    #
    # logging hooks
    def log_unknown(message = nil, progname = nil, &block)
      # a.k.a 'unknown'
      if message.is_a?(::Hash)
        if message[:trace]
          message = (message[:trace].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
        else
          message = (message[:unknown].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
        end
      end
      ::GxG::LOG.unknown(message.to_s)
    end
    alias :log_trace :log_unknown
    def log_fatal(message = nil, progname = nil, &block)
      if message.is_a?(::Hash)
        if message[:error].is_a?(::Exception) || message[:fatal].is_a?(::Exception)
          if message[:error]
            message = (message[:error].to_s + "\n Parameters: #{message[:parameters].inspect.to_s},\n Backtrace: " + message[:error].backtrace.join("\n"))
          else
            message = (message[:fatal].to_s + "\n Parameters: #{message[:parameters].inspect.to_s},\n Backtrace: " + message[:fatal].backtrace.join("\n"))
          end
        else
          if message[:error]
            message = (message[:error].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
          else
            message = (message[:fatal].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
          end
        end
      end
      ::GxG::LOG.fatal(message.to_s)
    end
    def log_error(message = nil, progname = nil, &block)
      if message.is_a?(::Hash)
        if message[:error].is_a?(::Exception)
          message = (message[:error].to_s + "\n Parameters: #{message[:parameters].inspect.to_s},\n Backtrace: " + (message[:error].backtrace || []).join("\n"))
        else
          message = (message[:error].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
        end
      end
      ::GxG::LOG.error(message.to_s)
    end
    def log_warn(message = nil, progname = nil, &block)
      if message.is_a?(::Hash)
        if message[:warning]
          message = (message[:warning].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
        else
          message = (message[:warn].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
        end
      end
      ::GxG::LOG.warn(message.to_s)
    end
    alias :log_warning :log_warn
    def log_info(message = nil, progname = nil, &block)
      if message.is_a?(::Hash)
        message = (message[:info].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
      end
      ::GxG::LOG.info(message.to_s)
    end
    def log_debug(message = nil, progname = nil, &block)
      if message.is_a?(::Hash)
        if message[:dev] || message[:development]
          if message[:dev]
            message = (message[:dev].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
          else
            message = (message[:development].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
          end
        else
          message = (message[:debug].to_s + "\n Parameters: #{message[:parameters].inspect.to_s}")
        end
      end
      ::GxG::LOG.debug(message.to_s)
    end
    alias :log_dev :log_debug
    alias :log_development :log_debug
    #
    def bytes(*args)
      GxG::ByteArray::try_convert(args)
    end
    #
    def new_message(*args)
      unless @uuid
        @uuid = ::GxG::uuid_generate.to_s.to_sym
        ::GxG::CHANNELS.create_channel(@uuid)
      end
      ::GxG::Events::Message.new({:sender => @uuid, :subject => args[1], :body => args[0]})
    end
    #
    public
    #
    def defederate()
      if @uuid
        the_channel = ::GxG::CHANNELS.fetch_channel(@uuid)
        if the_channel
          ::GxG::CHANNELS.destroy_channel(@uuid)
        end
      end
      true
    end
    #
    def millisecond_latency(*args,&block)
      if block
        starting = Time.now.to_f
        result = block.call(*args)
        ending = Time.now.to_f
        # Results are approximate: does not include the time ruby needs to return from the call,
        # assign the result RVALUE, collect a time, convert it to a Float, and assign ending RVALUE..
        # However, it is pretty darn close.
        {:result => result, :milliseconds => (ending - starting)}
      else
        # If :milliseconds are nil then the block was not passed and since it never ran, there is no latency to count up.
        # Simply do a return_var[:milliseconds].to_f for auto-accumulators w/o post-call comparison.
        {:result => nil, :milliseconds => 0.0}
      end
      # Attribution : http://stackoverflow.com/questions/2289381/how-to-time-an-operation-in-milliseconds-in-ruby
    end
  end
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/gxg_augmented.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/gxg_entities.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  if ::RUBY_ENGINE == "jruby"
    require 'jruby'
    JRuby.objectspace = true
  end
  require File.expand_path("./gxg/gxg_engine.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # Alterations to Object class: GxG::Engine dependency - quota supports
  class Object
    public
    #
    def heap_used(options={})
      unless options.is_a?(Hash)
        options={}
      end
      (self.content_size_used(options).to_i + (self.slots_used(options).to_i * GxG::Engine::profile[:slot_size]).to_i)
    end
    #
  end
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/gxg_transcode.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  if GxG::SYSTEM.platform[:platform] == :windows
    # Fixes an issue where IO::SYNC and File::SYNC are not defined on Windows.
    class IO
      SYNC = DSYNC
    end
    class File
      SYNC = DSYNC
    end
  end
  require File.expand_path("./gxg/gxg_io.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/gxg_net.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # FIX : big hassle with windows - exclude for now
  # require File.expand_path("./gxg/gxg_zmq.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # Set GxG Version and instantiate GxG::SYSTEM object:
  module GxG
    # setup constants, dispose of BOOTSTRAP data.
    VERSION = GxG::Version.new({:phase => :alpha, :revision => 50})
    VERSION.freeze
    #
    def self.shutdown()
      [::GxG::Networking::SshClient, ::GxG::Networking::ImapClient, ::GxG::Networking::RestClient, ::GxG::Networking::SoapClient, ::GxG::Networking::SmtpClient, ::GxG::Networking::XmlrpcClient, ::GxG::Networking::SftpClient, ::GxG::Networking::Pop3Client, ::GxG::Networking::HttpsClient, ::GxG::Networking::HttpClient, ::GxG::Networking::MatrixClient, ::GxG::Networking::FtpClient].each do |the_class|
        ::GxG::Engine::instance_process(the_class) do |the_object|
          if the_object.respond_to?(:logout)
            the_object.logout()
          end
        end
      end
      $Dispatcher.shutdown()
      # FOR NOW : ZMQ is excluded awaiting dep fix.
      # ::GxG::Networking::ZMQ::zmq_default_context.terminate()
    end
  end
  # First attempt at object serialization/reconstitution:
  module GxG
    def self.reconstitute(raw_data="")
      # See: http://stackoverflow.com/questions/5758464/ruby-how-do-i-check-if-a-class-is-defined
      #
      if raw_data.is_a?(::String)
        if raw_data.serialized?()
          result = nil
          if raw_data.include?("marshal:")
            begin
              result = ::Marshal.load(raw_data[(8..-1)].decode64())
            rescue Exception
              # Question : what to do here.
            end
          else
            if raw_data.include?("structure:")
              data = ::Marshal.load(raw_data[(10..-1)].decode64())
              if data.is_any?(::Array, ::Hash, ::Set, ::Struct)
                result = data.process do |entry, selector|
                  if entry.is_a?(::String)
                    if entry.serialized?()
                      ::GxG::reconstitute(entry)
                      # entry.unserialize()
                    else
                      entry
                    end
                  else
                    entry
                  end
                end
              end
            else
              raise Exception, "unrecognized serialization format"
            end
          end
        else
          result = raw_data
        end
      else
        result = raw_data
      end
      result
      #
    end
    #
    # Generic toolbox of methods
    def self.passes_needed(size_used=0, container_limit=0)
      if size_used > 0 and container_limit > 0
        needed_raw = size_used.to_f / container_limit.to_f
        overhang = needed_raw - needed_raw.to_i.to_f
        needed_raw = needed_raw.to_i.to_f
        if overhang > 0.0
          needed_raw += 1.0
        end
        needed_raw.to_i
      else
        0
      end
    end
    #
    def self.apportioned_ranges(how_much_data=0, container_limit=0, original_offset=0)
      result = []
      the_count = ::GxG::passes_needed(how_much_data, container_limit)
      if the_count > 0
        offset = original_offset
        the_count.times do
          if (offset + (container_limit - 1)) <= (how_much_data - 1)
            end_point = (offset + (container_limit - 1))
          else
            end_point = (how_much_data - 1)
          end
          result << ((offset)..(end_point))
          offset = (end_point + 1)
        end
      end
      result
    end
    #
    def self.valid_uuid?(uuid=nil,strict=true)
      if uuid.is_any?(::String, ::Symbol)
        if strict == true
          pattern = /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[4][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/
        else
          pattern = /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/
        end
        if uuid.to_s.match(pattern)
          if uuid.to_s.size == 36
            true
          else
            false
          end
        else
          false
        end
      else
        false
      end
    end
    #
    def self.sql_statement?(the_string)
      # See: https://larrysteinle.com/2011/02/20/use-regular-expressions-to-detect-sql-code-injection/
      if /('(''|[^'])*')|(;)|(\\x08(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE|UNION( +ALL){0,1})\\x08)/.match(the_string)
        true
      else
        false
      end
    end
    #
    def self.valid_domain_name?(the_string)
      if /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.match(the_string)
        true
      else
        false
      end
    end
    #
    def self.status()
      result = nil
      # Review : do some planning on tasks --> how does that impact status object cloning??
      $ThreadSafety.synchronize { result = $Status.clone }
      result
    end
    #
    def self.set_mode(the_mode=nil)
      if the_mode
        $ThreadSafety.synchronize { $Status[:mode] = the_mode.to_s.to_sym }
      end
    end
    #
  end
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/gxg_database.rb",File.dirname(__FILE__))
  require File.expand_path("./gxg/gxg_dbfs.rb",File.dirname(__FILE__))
  require File.expand_path("./gxg/net_clients.rb",File.dirname(__FILE__))
  # Database record retrieval methods:
  class Object
    # private methods
    private
    #
    def fetch(reference=nil)
      result = nil
      #
      if ::GxG::valid_uuid?(reference)
        record = ::GxG::DB[:roles][:data].retrieve_by_uuid(reference, ::GxG::DB[:administrator])
        if record
          result = record
        end
      else
        if reference.to_s.valid_path?
          result = ::GxG::VFS.open(reference)
        else
          criteria = {}
          if reference.is_a?(::Hash)
            criteria = reference
          else
            criteria[:title] = reference.to_s
          end
          list = []
          ::GxG::DB[:roles].keys.each do |db_role|
            list << ::GxG::DB[:roles][(db_role)].search_database(::GxG::DB[:administrator], criteria)
          end
          list = list.flatten!
          if list[0].is_a?(::Hash)
            result = ::GxG::DB[:roles][:data].retrieve_by_uuid(list[0][:uuid], ::GxG::DB[:administrator])
          end
        end
      end
      #
      result
    end
    #
    def fetch_structure(reference=nil)
      record = fetch(reference)
      if record
        record.as_structure
      else
        nil
      end
    end
    #
    def fetch_detached(reference=nil)
      record = nil
      if ::GxG::valid_uuid?(reference)
        if ::GxG::DB_SAFETY.synchronize { ::GxG::DB[:cache][(reference.to_s.to_sym)].is_any?(::GxG::Database::DetachedArray, ::GxG::Database::DetachedHash) }
          record = ::GxG::DB_SAFETY.synchronize { ::GxG::DB[:cache][(reference.to_s.to_sym)] }
        end
      else
        found = nil
        ::GxG::DB_SAFETY.synchronize {
          ::GxG::DB[:cache].values.each do |the_record|
            if the_record.title == reference
              found = the_record.uuid
              break
            end
          end
        }
        if found
          record = ::GxG::DB_SAFETY.synchronize { ::GxG::DB[:cache][(found)] }
        end
      end
      unless record.is_any?(::GxG::Database::DetachedArray, ::GxG::Database::DetachedHash)
        record = fetch(reference)
        if record.is_any?(::GxG::Database::PersistedArray, ::GxG::Database::PersistedHash)
          record = record.detach
          ::GxG::DB_SAFETY.synchronize { ::GxG::DB[:cache][(record.uuid)] = record }
        else
          record = nil
        end
      end
      record
    end
    #
    def new_structure(credential=nil, ufs_criteria=nil, the_role=:data)
      result = nil
      if ::GxG::valud_uuid?(credential)
        unless ufs_criteria.is_a?(::Hash)
          ufs_criteria = nil
        end
        unless the_role.is_a?(::Symbol)
          the_role = :data
        end
        the_database = nil
        if ::GxG::DB[:roles][(the_role)]
          the_database = ::GxG::DB[:roles][(the_role)]
        end
        if the_database.is_a?(::GxG::Database::Database)
          if ufs_criteria
            result = the_database.new_structure_from_format(credential, ufs_criteria)
          else
            result = the_database.try_persist({}, credential)
          end
        end
      end
      result
    end
    #
  end
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/net_tools.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  require File.expand_path("./gxg/gxg_communications.rb",File.dirname(__FILE__))
  # ---------------------------------------------------------------------------------------------------------------------
  # Register Database as supported protocol classes
  ::GxG::CLIENTS.register_client("sqlite", ::GxG::Database::Database)
  ::GxG::CLIENTS.register_client("mysql", ::GxG::Database::Database)
  # ### Define runtime constants
  module GxG
    DOCUMENTS = {}
  end
  #
  $ThreadSafety = ::Mutex.new
  $Status = {:mode => :loading, :tasks => :undefined, :load => nil}
  $Dispatcher = ::GxG::Events::EventDispatcher.new(0.333)
  $Dispatcher.startup
  $Dispatcher.every("5 seconds") do
    load = GxG::Engine.determine_loads
    $ThreadSafety.synchronize { $Status[:load] = load }
  end
  ::GxG::LOG[:default] = ::Logger.new(STDOUT)
  ::GxG::LOG[:default].level = ::Logger::ERROR
  $Dispatcher.every("0.333 seconds") do
    ::GxG::CHANNELS.update_channels
    ::GxG::LOG.process_messages()
  end
  # ### Defer long-runnign cpu info gather on Winderz
  if ::GxG::SYSTEM.platform[:platform] == :windows
    $Dispatcher.post_event(:root) do
      gxg_template = {
        :processor=>0,
        :vendor_id=>"",
        :cpu_family=> -1,
        :model=> -1,
        :model_name=>"",
        :stepping=> -1,
        :microcode=>"",
        :cpu_mhz=>0.0,
        :cache_size=>0,
        :physical_id=> -1,
        :siblings=> -1,
        :core_id=> -1,
        :cpu_cores=> 0,
        :apicid=> -1,
        :initial_apicid=>0,
        :fpu=>false,
        :fpu_exception=>false,
        :cpuid_level=> -1,
        :wp=>false,
        :flags=>[],
        :bugs=>"",
        :bogomips=> 0.0,
        :tlb_size=>"",
        :clflush_size=> -1,
        :cache_alignment=> -1,
        :address_sizes=>{
          :physical_bits=> -1,
          :virtual_bits=> -1
          }, 
          :power_management=>""
      }
      #
      local_mapping = {
        :AddressWidth=>"64",
        :Architecture=>"9 ",
        :AssetTag=>"",
        :Availability=>"3 ",
        :Caption=>"AMD64 Family 21 Model 2 Stepping 0",
        :Characteristics=>" ",
        :ConfigManagerErrorCode=>"",
        :ConfigManagerUserConfig=>" ",
        :CpuStatus=>"0",
        :CreationClassName=>"Win32_Processor",
        :CurrentClockSpeed=>:cpu_mhz,
        :CurrentVoltage=>"",
        :DataWidth=>"64 ",
        :Description=>"AMD64 Family 21 Model 2 Stepping 0",
        :DeviceID=>"CPU0",
        :ErrorCleared=>"",
        :ErrorDescription=>"",
        :ExtClock=>"",
        :Family=>:cpu_family,
        :InstallDate=>" ",
        :L2CacheSize=>" ",
        :L2CacheSpeed=>"",
        :L3CacheSize=>:cache_size,
        :L3CacheSpeed=>"0 ",
        :LastErrorCode=>" ",
        :Level=>:cpuid_level,
        :LoadPercentage=>"6 ",
        :Manufacturer=>:vendor_id,
        :MaxClockSpeed=>"4013 ",
        :Name=>:model_name,
        :NumberOfCores=>:cpu_cores,
        :NumberOfEnabledCore=>" ",
        :NumberOfLogicalProcessors=>"4",
        :OtherFamilyDescription=>"",
        :PartNumber=>"",
        :PNPDeviceID=>" ",
        :PowerManagementCapabilities=>" ",
        :PowerManagementSupported=>"FALSE ",
        :ProcessorId=>:physical_id,
        :ProcessorType=>" ",
        :Revision=>"512 ",
        :Role=>"CPU ",
        :SecondLevelAddressTranslationExtensions=>"FALSE",
        :SerialNumber=>"",
        :SocketDesignation=>" ",
        :Status=>"OK",
        :StatusInfo=>"3 ",
        :Stepping=>:stepping,
        :SystemCreationClassName=>"Win32_ComputerSystem ",
        :SystemName=>"DESKTOP-D87M3K5",
        :ThreadCount=>" ",
        :UniqueId=>"",
        :UpgradeMethod=>:model,
        :Version=>"Model 2, Stepping 0",
        :VirtualizationFirmwareEnabled=>"TRUE ",
        :VMMonitorModeExtensions=>"FALSE",
        :VoltageCaps=>" "
      }
      headers = ["AddressWidth", "Architecture", "AssetTag", "Availability", "Caption", "Characteristics", "ConfigManagerErrorCode", "ConfigManagerUserConfig", "CpuStatus", "CreationClassName", "CurrentClockSpeed", "CurrentVoltage", "DataWidth", "Description", "DeviceID", "ErrorCleared", "ErrorDescription", "ExtClock", "Family", "InstallDate", "L2CacheSize", "L2CacheSpeed", "L3CacheSize", "L3CacheSpeed", "LastErrorCode", "Level", "LoadPercentage", "Manufacturer", "MaxClockSpeed", "Name", "NumberOfCores", "NumberOfEnabledCore", "NumberOfLogicalProcessors", "OtherFamilyDescription", "PartNumber", "PNPDeviceID", "PowerManagementCapabilities", "PowerManagementSupported", "ProcessorId", "ProcessorType", "Revision", "Role", "SecondLevelAddressTranslationExtensions", "SerialNumber", "SocketDesignation", "Status", "StatusInfo", "Stepping", "SystemCreationClassName", "SystemName", "ThreadCount", "UniqueId", "UpgradeMethod", "Version", "VirtualizationFirmwareEnabled", "VMMonitorModeExtensions", "VoltageCaps"]
      local_data = {}
      headers.each do |the_header|
        raw_data = `wmic cpu get #{the_header}`.split("\r\n")
        data = raw_data[1].gsub("  ","")
        #
        if ["AddressWidth", "Architecture", "Availability", "CpuStatus","CurrentClockSpeed","DataWidth","Family","L2CacheSize","L2CacheSpeed","L3CacheSize","L3CacheSpeed","Level","LoadPercentage","MaxClockSpeed","NumberOfCores","NumberOfEnabledCore","NumberOfLogicalProcessors","StatusInfo","Stepping","ThreadCount","UpgradeMethod"].include?(the_header)
          if data.to_s.size > 0 && data.to_s != " "
            data = data.to_i
          else
            data = 0
          end
        end
        if ["PowerManagementSupported","SecondLevelAddressTranslationExtensions","VirtualizationFirmwareEnabled","VMMonitorModeExtensions"].include?(the_header)
          if data.to_s.size > 0 && (data.to_s.include?("TRUE") || data.to_s.include?("true"))
            data = true
          else
            data = false
          end
        end
        if ["CurrentVoltage","VoltageCaps"].include?(the_header)
          if data.to_s.size > 0 && data.to_s != " "
            data = data.to_f
          else
            data = 0.0
          end
        end
        #
        local_data[(raw_data[0].gsub(" ","").to_sym)] = data
      end
      local_data[:NumberOfLogicalProcessors].times do |the_cpu_selector|
        cpu_record = gxg_template.clone
        cpu_record[:processor] = the_cpu_selector
        local_mapping.keys.each do |the_key|
          if local_mapping[(the_key)].is_a?(::Symbol)
            cpu_record[(local_mapping[(the_key)])] = local_data[(the_key)]
          end
          if the_key == :AddressWidth
            cpu_record[:address_sizes][:physical_bits] = local_data[:AddressWidth]
            cpu_record[:address_sizes][:virtual_bits] = local_data[:AddressWidth]
          end
        end
        ::GxG::SYSTEM.gxg_cpu_add(cpu_record)
      end
    end
  end
  #
  ::GxG::set_mode(:running)
  #
end
#