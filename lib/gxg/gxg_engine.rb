
# ---------------------------------------------------------------------------------------------------------------------
# GxG Engine interface: rational memory management, and quota supports
module GxG
  #
  module Engine
    # ok... why?
    # example: ::Process::getrlimit(:AS) => [<1Exabyte>,<1Exabyte>]
    # Now that is the Amsterdam-style pull on a bong with stirrups - so far as dealing with real memory limits goes.
    # Rather - I want my apps to be *able* to deal with reality as the system resources determine
    # Eventually provides a *corrected* drop-in replacement for Process module in standard MRI 1.9.2
    # See : http://www.ruby-doc.org/core-1.9.3/Process.html
    #
    @@details = {}
    # running effectively in 32 or 64 bits?  See: http://www.ruby-forum.com/topic/164583
    @@details[:runtime_bits] = ([ -1 ].pack('l!').length * 8)
    # default to 32 bit size:
    if @@details[:runtime_bits] == 64
      @@details[:runtime_rvalue_size] = 40
    else
      @@details[:runtime_rvalue_size] = 20
    end
    #
    @@details[:files] = {:maximum_file_descriptors => 1024}
    # FORNOW : Review : server claims 50% of all system threads
    @@details[:events] = {:maximum_event_descriptors => (GxG::SYSTEM["kernel.threads_max"]["kernel.threads_max"].to_f * 0.5).to_i , :event_descriptors_threshold => 0.05, :event_descriptors_envelope => (20..100), :event_minimum_threshold => 20}
    # Fix for Windows: per-process theads max is 2000.
    if GxG::SYSTEM.platform[:platform] == :windows
      @@details[:files][:maximum_file_descriptors] = 512
      @@details[:events][:maximum_event_descriptors] = 2000
    end
    #
    @@details[:runtime] = RUBY_ENGINE.to_sym
    @@details[:runtime_version] = GxG::Version.new({:interpret => RUBY_VERSION, :patch_level => RUBY_PATCHLEVEL, :revision => RUBY_REVISION})
    # determine the byte size of a Ruby RVALUE (a.k.a :slot_size)
    # See: http://www.engineyard.com/blog/2010/mri-memory-allocation-a-primer-for-developers/
    #
    @@details[:memory_load] = {:high => false, :medium => false, :low => true, :percent => 0.0}
    @@details[:engine_load] = {:high => false, :medium => false, :low => true, :percent => 0.0}
    #
    @@details[:key_map] = []
    @@details[:key_map] << {:key => "files.max_descriptors", :path => "/:files/:maximum_file_descriptors"}
    @@details[:key_map] << {:key => "events.max_descriptors", :path => "/:events/:maximum_event_descriptors"}
    #
    @@thread_safety = Mutex.new
    @@event_descriptors = 0
    #
    def self.detail_mapping()
      @@details[:key_map]
    end
    #
    def self.[](the_path="")
      # Public interface for accessing system keyed values.
      # access cached or system-read values on /proc (sysctl-style) keys. (frankly missing from BSD, etc)
      result = nil
      reference = ::GxG::Engine::detail_mapping()
      #
      reference.to_enum.each do |mapping|
        if mapping[:key] == the_path
          @@thread_safety.synchronize {
            result = @@details.get_at_path(mapping[:path]).clone
          }
          break
        end
      end
      #      unless result
      #        # attempt to fetch the data from the system somehow.
      #        result = get_system_data(the_path)
      #        unless result.keys.size > 0
      #          result = nil
      #        end
      #      end
      #
      result
    end
    #
    def self.memory_load_high?()
      @@thread_safety.synchronize {
        @@details[:memory_load][:high]
      }
    end
    #
    def self.memory_load_medium?()
      @@thread_safety.synchronize {
        @@details[:memory_load][:medium]
      }
    end
    #
    def self.memory_load_low?()
      @@thread_safety.synchronize {
        @@details[:memory_load][:low]
      }
    end
    #
    def self.memory_load()
      @@thread_safety.synchronize {
        @@details[:memory_load][:percent]
      }
    end
    #
    def self.engine_load_high?()
      @@thread_safety.synchronize {
        @@details[:engine_load][:high]
      }
    end
    #
    def self.engine_load_medium?()
      @@thread_safety.synchronize {
        @@details[:engine_load][:medium]
      }
    end
    #
    def self.engine_load_low?()
      @@thread_safety.synchronize {
        @@details[:engine_load][:low]
      }
    end
    #
    def self.engine_load()
      @@thread_safety.synchronize {
        @@details[:engine_load][:percent]
      }
    end
    #
    def self.determine_memory_load()
      current_load = ((GxG::Engine::memory_used()[:total].to_f / GxG::SYSTEM.memory_limits()[:process].first.to_f) * 100.0)
      if (0.0..40.0).include?(current_load)
        # low
        @@thread_safety.synchronize {
          @@details[:memory_load][:high] = false
          @@details[:memory_load][:medium] = false
          @@details[:memory_load][:low] = true
          @@details[:memory_load][:percent] = current_load
        }
      else
        if (40.0..70.0).include?(current_load)
          # medium
          @@thread_safety.synchronize {
            @@details[:memory_load][:high] = false
            @@details[:memory_load][:medium] = true
            @@details[:memory_load][:low] = false
            @@details[:memory_load][:percent] = current_load
          }
        else
          if current_load > 70.0
            # high
            @@thread_safety.synchronize {
              @@details[:memory_load][:high] = true
              @@details[:memory_load][:medium] = false
              @@details[:memory_load][:low] = false
              @@details[:memory_load][:percent] = current_load
            }
          end
        end
      end
    end
    #
    def self.determine_engine_load()
      max_event_descriptors = ::GxG::Engine::maximum_event_descriptors()
      available_events = ::GxG::Engine::available_event_descriptors()
      current_load = (((max_event_descriptors - available_events).to_f / max_event_descriptors.to_f) * 100.0)
      if (0.0..40.0).include?(current_load)
        # low
        @@thread_safety.synchronize {
          @@details[:engine_load][:high] = false
          @@details[:engine_load][:medium] = false
          @@details[:engine_load][:low] = true
          @@details[:memory_load][:percent] = current_load
        }
      else
        if (40.0..70.0).include?(current_load)
          # medium
          @@thread_safety.synchronize {
            @@details[:engine_load][:high] = false
            @@details[:engine_load][:medium] = true
            @@details[:engine_load][:low] = false
            @@details[:engine_load][:percent] = current_load
          }
        else
          if current_load > 70.0
            # high
            @@thread_safety.synchronize {
              @@details[:engine_load][:high] = true
              @@details[:engine_load][:medium] = false
              @@details[:engine_load][:low] = false
              @@details[:engine_load][:percent] = current_load
            }
          end
        end
      end
    end
    #
    def self.engine_gear()
      # inverse of load
      result = :low
      @@thread_safety.synchronize {
        if @@details[:engine_load][:medium]
          result = :medium
        end
        if @@details[:engine_load][:low]
          result = :high
        end
      }
      result
    end
    #
    def self.memory_gear()
      # inverse of load
      result = :low
      @@thread_safety.synchronize {
        if @@details[:memory_load][:medium]
          result = :medium
        end
        if @@details[:memory_load][:low]
          result = :high
        end
      }
      result
    end
    #
    def self.gear()
      "#{::GxG::Engine::engine_gear().to_s}_#{::GxG::Engine::memory_gear().to_s}".to_sym
    end
    #
    def self.determine_loads()
      mem_gear = ::GxG::Engine::memory_gear()
      eng_gear = ::GxG::Engine::engine_gear()
      {
        :engine => {:load => ::GxG::Engine::determine_engine_load(), :gear => eng_gear},
        :memory => {:load => ::GxG::Engine::determine_memory_load(), :gear => mem_gear},
        :gear => "#{eng_gear.to_s}_#{mem_gear.to_s}".to_sym
      }
    end
    #
    include ::Process
    # overrides
    #
    # [:exec, :fork, :spawn, :exit!, :exit, :abort, :kill, :wait, :wait2, :waitpid, :waitpid2, :waitall, :detach, :pid, :ppid,
    # .
    def self.exec(*args)
      ::Process::exec(*args)
    end
    #
    def self.fork(*args)
      ::Process::fork(*args)
    end
    #
    def self.spawn(*args)
      ::Process::spawn(*args)
    end
    #
    def self.exit!(*args)
      ::Process::exit!(*args)
    end
    #
    def self.exit(*args)
      ::Process::exit(*args)
    end
    #
    def self.abort(*args)
      ::Process::abort(*args)
    end
    #
    def self.kill(*args)
      ::Process::kill(*args)
    end
    #
    def self.wait(*args)
      ::Process::wait(*args)
    end
    #
    def self.wait2(*args)
      ::Process::wait2(*args)
    end
    #
    def self.waitpid(*args)
      ::Process::waitpid(*args)
    end
    #
    def self.waitpid2(*args)
      ::Process::waitpid2(*args)
    end
    #
    def self.waitall(*args)
      ::Process::waitall(*args)
    end
    #
    def self.detach(*args)
      ::Process::detach(*args)
    end
    #
    def self.pid(*args)
      ::Process::pid(*args)
    end
    #
    def self.ppid(*args)
      ::Process::ppid(*args)
    end
    #
    # :getpgrp, :setpgrp, :getpgid, :setpgid, :setsid, :getpriority, :setpriority, :getrlimit, :setrlimit, :uid, :gid, :euid, :egid,
    #
    def self.getpgrp(*args)
      ::Process::getpgrp(*args)
    end
    #
    def self.setpgrp(*args)
      ::Process::setpgrp(*args)
    end
    #
    def self.getpgid(*args)
      ::Process::getpgid(*args)
    end
    #
    def self.setpgid(*args)
      ::Process::setpgid(*args)
    end
    #
    def self.setsid(*args)
      ::Process::setsid(*args)
    end
    #
    def self.getpriority(*args)
      ::Process::getpriority(*args)
    end
    #
    def self.setpriority(*args)
      ::Process::setpriority(*args)
    end
    #
    def self.getrlimit(key)
      result = nil
      # FIX: GxG::Engine::getrlimit : Awaiting rbx bug #2112 fix : https://github.com/rubinius/rubinius/issues/2112
      case ::GxG::Engine::profile()[:engine]
      when :ruby
        raw_data = ::Process::getrlimit(key)
        case key
        when :AS
          if GxG::SYSTEM
            memory_limits = GxG::SYSTEM.memory_limits()
            result = [raw_data[0],(memory_limits[:process].max)]
          else
            result = raw_data
          end
        else
          result = raw_data
        end
      when :jruby
        memory_limits = GxG::SYSTEM.memory_limits()
        result = [(memory_limits[:process].first),(memory_limits[:process].last)]
      when :rbx
        memory_limits = GxG::SYSTEM.memory_limits()
        result = [(memory_limits[:process].first),(memory_limits[:process].last)]
      end
      result
    end
    #
    def self.setrlimit(*args)
      ::Process::setrlimit(*args)
    end
    #
    def self.uid(*args)
      ::Process::uid(*args)
    end
    #
    def self.gid(*args)
      ::Process::gid(*args)
    end
    #
    def self.euid(*args)
      ::Process::euid(*args)
    end
    #
    def self.egid(*args)
      ::Process::egid(*args)
    end
    #
    #  :initgroups, :groups, :maxgroups, :daemon, :times]
    #
    def self.initgroups(*args)
      ::Process::initgroups(*args)
    end
    #
    def self.groups(*args)
      ::Process::groups(*args)
    end
    #
    def self.maxgroups(*args)
      ::Process::maxgroups(*args)
    end
    #
    def self.daemon(*args)
      ::Process::daemon(*args)
    end
    #
    def self.times(*args)
      ::Process::times(*args)
    end
    #
    # extensions
    #
    def self.profile()
      @@thread_safety.synchronize {
        {:engine => @@details[:runtime], :version => @@details[:runtime_version], :bits => @@details[:runtime_bits], :slot_size => @@details[:runtime_rvalue_size]}.clone
      }
    end
    #
    def self.instance_process(the_class, &block)
      if block.respond_to?(:call)
        ::ObjectSpace.each_object(Class) do |the_object|
          if the_object.alive?()
            if the_object.is_a?(the_class)
                block.call(the_object)
            end
          end
        end
      end
    end
    #
    def self.object_memory_used()
      #
      slots = 0
      other = 0
      ::ObjectSpace.each_object(Class) do |the_object|
        slots += 1
        if the_object.alive?()
          if the_object.is_a?(::String)
            other += the_object.bytesize()
          end
        end
      end
      #
      ((::GxG::Engine::profile()[:slot_size].to_i * slots) + other)
    end
    #
    def self.memory_used()
      # ok... why in the fly'n F isn't this provided by core ruby?!?
      # Attribution: http://stackoverflow.com/questions/7220896/get-current-ruby-process-memory-usage
      result = {:actual => 0, :virtual => 0, :total => 0}
      #
      if ::GxG::SYSTEM
        case ::GxG::SYSTEM.platform[:platform]
        when :windows
          # FORNOW: user object space enumeration
          result[:actual] = ::GxG::Engine::object_memory_used()
        when :bsd
          pid_string = "#{::Process::pid}"
          env = self.environment()
          case env[:environment]
          when :openbsd
            # See: http://modman.unixdev.net/?sektion=1&page=procmap&manpath=OpenBSD-3.6
            # use `procmap -p #{pid_string}`
            # LATER: GxG::Engine::memory_used (OpenBSD) : determine how to cull procmap text data into :actual and :virtual memory usage.
            # FORNOW: user object space enumeration
            result[:actual] = ::GxG::Engine::object_memory_used()
            #
          when :freebsd, :dragonfly, :pcbsd
            # TODO: GxG::Engine::memory_used: Test with FreeBSD, DragonFlyBSD, and PCBSD.
            raw_data = `top -d 1`
            raw_data.to_enum(:each_line).each do |the_line|
              if the_line.split(" ")[0] == pid_string
                result[:actual] = (the_line.split(" ")[6] << "B").numeric_values([:byte])[:byte].to_i
                # TODO: GxG::Engine.memory_used() (netbsd) : Find a reliable way to get result[:virtual] mem used.
                break
              end
            end
          when :netbsd
            # TODO: GxG::Engine::memory_used: Test with NetBSD.
            raw_data = `top -d 1`
            raw_data.to_enum(:each_line).each do |the_line|
              if the_line.split(" ")[0] == pid_string
                result[:actual] = (the_line.split(" ")[4] << "B").numeric_values([:byte])[:byte].to_i
                # TODO: GxG::Engine.memory_used() (netbsd) : Find a reliable way to get result[:virtual] mem used.
                break
              end
            end
          when :darwin, :macos
            # TODO: GxG::Engine::memory_used: Test with Darwin/MacOSX.
            raw_data = `top -l 1`
            raw_data.to_enum(:each_line).each do |the_line|
              if the_line.split(" ")[0] == pid_string
                result[:actual] = (the_line.split(" ")[9] << "B").numeric_values([:byte])[:byte].to_i
                # TODO: GxG::Engine.memory_used() (darwin) : Find a reliable way to get result[:virtual] mem used.
                break
              end
            end
          end
        when :linux, :solaris
          # PS is universal, but unfortunately universally incorrect, See: http://stackoverflow.com/questions/131303/linux-how-to-measure-actual-memory-usage-of-an-application-or-process
          # TODO: GxG::Engine::memory_used: create a non-toolbox version for bootstrap memory profiling.
          # TODO: GxG::Engine::memory_used: Test with Solaris.
          raw_data = `pmap -d #{::Process::pid} | tail -n 1`.split(" ")
          result[:actual] = (raw_data[3].to_s << "B").numeric_values()[:byte].to_i
          result[:virtual] = (raw_data[1].to_s << "B").numeric_values()[:byte].to_i
          # result[:shared] = (raw_data[5] << "B").numeric_values()[:byte].to_i
        end
      end
      result[:total] = (result[:actual] + result[:virtual])
      result
    end
    #
    def self.memory_available()
      # Memory available for this process
      result = {:actual => 0, :virtual => 0, :total => 0}
      if ::GxG::SYSTEM
        used_memory = ::GxG::Engine::memory_used()
        free_memory = ::GxG::SYSTEM.memory()
        limits = ::GxG::Engine::getrlimit(:AS)
        latitude_total = (limits[0] - used_memory[:actual])
        if latitude_total < 0
          latitude_total = 0
        end
        # latitude_virtual = (limits[0] - used_memory[:actual])
        # latitude_actual = (limits[0] - used_memory[:virtual])
        # indicates available ram vs. paged swap first
        if free_memory[:actual][:free].to_i > limits[0]
          result[:actual] = latitude_total
          result[:virtual] = 0
        else
          result[:actual] = free_memory[:actual][:free]
          # vm calc is crack-monkey, but someplace close to reality.
          if free_memory[:virtual][:free] > ((limits[0] - result[:actual]) - used_memory[:total])
            result[:virtual] = ((limits[0] - result[:actual]) - used_memory[:total])
            unless result[:virtual] > 0
              result[:virtual] = 0
            end
          else
            if ((free_memory[:virtual][:free] - result[:actual]) - used_memory[:total]) > 0
              result[:virtual] = ((free_memory[:virtual][:free] - result[:actual]) - used_memory[:total])
            else
              result[:virtual] = 0
            end
          end
        end
        #
      end
      result[:total] = (result[:actual] + result[:virtual])
      result
    end
    #
    def self.engine_data_keys(other_platform=nil)
      #
      result = []
      data = []
      data << {:key => "files.max_descriptors", :platforms => [:linux], :operation => {:getconf => "OPEN_MAX", :format => :to_int}}
      # TODO: Research maximum socket limit under zmq:
      # See: http://news.ycombinator.com/item?id=1740823
      # Also : http://stackoverflow.com/questions/651665/how-many-socket-connections-possible
      # inventory the various platform variables that affect what threshold of max_socket_count a given system would end up with.
      # TODO: find a way to ask the OS and ZMQ for: how many descriptors available to this process, and how many in use under zmq 2.x & 3.x respectively?
      # ALSO: factor in passed preferences for these settings.
      # update available_file_descriptors when all that becomes clear and is a bit settled.
      # current_memory = ::GxG::Engine::memory_available()[:actual]
      # TODO: GxG::Engine::engine_data_keys : determine precise socket size (32bit/64bit arch) for event zmq sockets used (exact type used).
      # GxG::Engine::profile()[:bits]
      # zmq_socket_size = 16384
      #
      # event_allocation = 0.5
      #
      # TODO: GxG::Engine::engine_data_keys : tie event allocation percentage into defaults / config.file loader.
      data << {:key => "events.max_descriptors", :platforms => [:linux], :operation => {:event_allocation => 0.5, :format => :noop}}
      # See: http://www.metabrew.com/article/a-million-user-comet-application-with-mochiweb-part-3
      # Sysctl tuning: http://www.metabrew.com/article/a-million-user-comet-application-with-mochiweb-part-1
      # LATER: develop a series of formulas for calculating approx. how many clients one can support under one 'cluster' controller (session manager).
      data.to_enum.each do |entry|
        if entry[:platforms].include?((other_platform || ::GxG::SYSTEM.platform()[:platform]))
          result << entry
        end
      end
      #
      result
    end
    #
    def self.get_engine_data(keys=[])
      # Support for <SYSTEM>.refresh_data_for(a_path) (private_method)
      # some sort of sysctl + config + etc for *all* platforms:
      # "sysctl -n net.ipv4.tcp_sack" becomes: "/net/ipv4/tcp/selective_ack" (external use path)
      # @details[:memory_limits][:buffers][:socket][:ipc] becomes colllection_point = @details.at_path(":memory_limits/:buffers/:socket/:ipc");collection_point[(key)]=value
      # procs for gathering data, and formatting for use.
      # by_platform key between sysctl/config-key and @details hash path.
      # {:synonyms => ["external-path"], :sysctl => "key-string', :format => :proc-name, :location => "hash-path", :location_key => (:sym or int)}
      #
      unless keys.is_a?(::Array)
        keys = [(keys)]
      end
      result = {}
      #
      format_noop = Proc.new do |the_data|
        the_data
      end
      format_to_int = Proc.new do |the_string|
        (the_string.numeric_values()[:integer] || 0)
      end
      format_to_float = Proc.new do |the_string|
        (the_string.numeric_values()[:float] || 0.0)
      end
      format_zerofalse = Proc.new do |the_string|
        ( format_to_int.call(the_string) > 0 )
      end
      format_valid_with_initial = Proc.new do |the_string|
        raw_data = the_string.split(" ")
        {:initial => format_to_int.call(raw_data[1]), :valid => ((format_to_int.call(raw_data[0]))..(format_to_int.call(raw_data[2])))}
      end
      sysctl_read = Proc.new do |a_key,the_formatter|
        ( the_formatter.call(`sysctl -n #{a_key.to_s}`.split("\n")[0]) )
      end
      getconf_read = Proc.new do |a_key, the_formatter|
        ( the_formatter.call(`getconf #{a_key.to_s}`.split("\n")[0]) )
      end
      event_allocation = Proc.new do |the_allocation, the_formatter|
        # more precise zmq socket byte size goes here.
        zmq_socket_size = 16384
        #
        (((::GxG::Engine::memory_available()[:actual].to_f * the_allocation.to_f).to_i / zmq_socket_size) - 1)
      end
      #
      reference = ::GxG::Engine::engine_data_keys()
      #
      fetch_data = Proc.new do |the_key|
        data = nil
        reference.to_enum.each do |entry|
          if entry[:key] == the_key
            case entry[:operation][:format]
            when :noop
              the_formatter = format_noop
            when :zerofalse
              the_formatter = format_zerofalse
            when :to_int
              the_formatter = format_to_int
            when :to_float
              the_formatter = format_to_float
            when :valid_with_initial
              the_formatter = format_valid_with_initial
            else
              the_formatter = format_noop
            end
            if entry[:operation][:sysctl]
              data = sysctl_read.call(entry[:operation][:sysctl],the_formatter)
            else
              if entry[:operation][:getconf]
                data = getconf_read.call(entry[:operation][:getconf],the_formatter)
              else
                if entry[:operation][:event_allocation]
                  data = event_allocation.call(entry[:operation][:event_allocation],the_formatter)
                else
                  #
                end
                #
              end
            end
            if data
              break
            end
          end
        end
        data
      end
      #
      keys.to_enum.each do |specifier|
        if specifier.is_a?(::String)
          # if element is String: serves as result Hash key to hold result value.
          # single result with this result key
          result[(specifier)] = fetch_data.call(specifier)
        else
          if specifier.is_a?(::Hash)
            # if element is Hash: {ukey => hash_path}, {:key => <keystring>, :path => <hash_path>}
            # if hash_path supplied, read the data; set the @details hash element, and return the formatted data
            if specifier[:key]
              # {:key => <keystring>, :path => <hash_path>}
              result[(specifier[:key])] = fetch_data.call(specifier[:key])
              if specifier[:path]
                @@thread_safety.synchronize {
                  @@details.set_at_path(specifier[:path],result[(specifier[:key])])
                }
              end
            else
              # {ukey => hash_path}
              subkeys = specifier.keys
              subkeys.to_enum.each do |a_key|
                result[(a_key)] = fetch_data.call(a_key)
                @@thread_safety.synchronize {
                  @@details.set_at_path(specifier[(a_key)],result[(a_key)])
                }
              end
            end
          end
        end
      end
      #
      result
    end
    #
    def self.set_engine_data(keys=[])
      # LATER: GxG::Engine::set_engine_data : when you figure out system(sudo) authentication - use this for ops that require elevated privs to set system parameters.
      # Define a set of universal_keys that affect what other keys; upon setting any one, unique-list a set of keys to read back in w/ hash paths.
      result = nil
      if nil
        ::GxG::Engine::get_engine_data(nil,nil)
        # compare hash value to the_value; return true if successful
      end
      result
    end
    # ### Descriptors in general
    def self.descriptor_limits()
      {:events => @@details[:events][:maximum_event_descriptors], :files => @@details[:files][:maximum_file_descriptors]}.clone
    end
    #
    def self.descriptor_heap_used()
      result = {:total => 0}
      slot_size = ::GxG::Engine::profile[:slot_size]
      file_total = 0
      GxG::Engine::file_descriptors().to_enum.each do |item|
        file_total += item.heap_used()
      end
      @@thread_safety.synchronize {
        result[:files] = file_total
        unless ::GxG::Engine::descriptor_limits()[:events] == :files
          # see available_file_descriptors : beware counting event descriptors twice (w/ file descriptors)
          # TODO: GxG::Engine::descriptor_heap_used : sync w/ more precise event socket size determination
          result[:events] = (@@event_descriptors * (slot_size + 4))
        end
      }
      result[:total] = (result[:files].to_i + result[:events].to_i)
      #
      result
    end
    # ### File Descriptors
    def self.maximum_file_descriptors()
        ::GxG::Engine::descriptor_limits()[:files]
    end
    #
    def self.file_descriptors()
      # Return an Array of currently opened file descriptors.
      # About File Descriptors: http://stackoverflow.com/questions/848717/handling-more-than-1024-file-descriptors-in-c-on-linux
      # 
      result = []
      exclude_list = []
      [::IO, ::IO::descendants()].flatten!.to_enum.each do |the_class|
        unless exclude_list.include?(the_class)
          ::ObjectSpace.each_object(the_class) do |the_io|
            unless (the_io.closed? || result.include?(the_io))
              result << the_io
            end
          end
        end
      end
      result
    end
    #
    def self.available_file_descriptors()
      (::GxG::Engine::maximum_file_descriptors() - ::GxG::Engine::file_descriptors().size)
    end
    #
    # ### Event Descriptors
    def self.maximum_event_descriptors()
      ::GxG::Engine::descriptor_limits()[:events]
    end
    #
    def self.event_descriptors_threshold()
      # Percentage of allocation that must be available for events to be released.
      @@thread_safety.synchronize {
        @@details[:events][:event_descriptors_threshold].clone
      }
    end
    #
    def self.event_minimum_threshold()
      # Percentage of allocation that must be available for events to be released.
      @@thread_safety.synchronize {
        @@details[:events][:event_minimum_threshold].clone
      }
    end
    #
    def self.events_in_use()
      @@thread_safety.synchronize {
        @@event_descriptors
      }
    end
    #
    def self.available_event_descriptors()
      result = 0
      current = 0
      @@thread_safety.synchronize {
        current = (::GxG::Engine::maximum_event_descriptors() - @@event_descriptors)
      }
      if current > 0
        result = current
      end
      result
    end
    #
    def self.reserve_event_descriptor()
      result = false
      if ::GxG::Engine::available_event_descriptors() > 0
        @@thread_safety.synchronize {
          @@event_descriptors += 1
        }
        result = true
      else
        raise Errno::ENOMEM, "maximum number of event descriptors in use (#{GxG::Engine::maximum_event_descriptors().to_s})"
      end
      result
    end
    #
    def self.release_event_descriptor()
      result = false
      @@thread_safety.synchronize {
        if @@event_descriptors > 0
          @@event_descriptors -= 1
        end
      }
      result = true
      result
    end
    #
    def self.determine_event_allocations()
      #
      total = ::GxG::Engine::maximum_event_descriptors()
      dispatchers = []
      [::GxG::Events::EventDispatcher, ::GxG::Events::EventDispatcher::descendants()].flatten!.each do |the_class|
        ::ObjectSpace.each_object(the_class) do |the_dispatcher|
          if the_dispatcher.alive?()
            if the_dispatcher.running?()
              dispatchers << the_dispatcher
            end
          end
        end
      end
      # Note : a ghost-dispatcher representing all other system funcitons is added to the dispatcher count.
      maximum_events = (total.to_f / (dispatchers.size + 1).to_f).to_i
      threshold = (maximum_events.to_f * ::GxG::Engine::event_descriptors_threshold().to_f).to_i
      unless threshold > 0
        threshold = 1
      end
      @@thread_safety.synchronize {
        @@details[:events][:event_minimum_threshold] = threshold
        @@details[:events][:event_descriptors_envelope] = ((threshold)..(maximum_events))
      }
      true
    end
    #
    def self.event_allocation_envelope()
      result = (20..100)
      @@thread_safety.synchronize {
        result = @@details[:events][:event_descriptors_envelope]
      }
      result
    end
    #
  end
  # FIX / Review : this appears to set file and event max descriptors to NIL on Winderz. Do I need this?
  # ::GxG::Engine::get_engine_data(::GxG::Engine::detail_mapping())
  #
end
#