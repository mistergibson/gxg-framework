#
# ---------------------------------------------------------------------------------------------------------------------
# Preliminary Entity supports
module GxG
  #
  def find_local(the_key)
    nil
  end
  #
  module Entity
    # SysInfo
    # provide default filesystem object
    class LocalSystem
      #
      def initialize(bootstrap_data={})
        # Rather than only using RUBY_PLATFORM, I want to define the *specific* environment on that platform to help further characterize what is at hand.
        super()
        # @thread_safety = ::Mutex.new
        @thread_safety = ::Mutex.new
        @details = {}
        #
        @details[:architecture] = bootstrap_data.delete(:architecture)
        #
        # ### Process bootstrap_data regarding platform and environment
        @details[:platform] = bootstrap_data.delete(:platform)
        @details[:platform_version] = GxG::Version.new(bootstrap_data.delete(:platform_version))
        @details[:platform_configuration] = {:process => {}, :flags => {}}
        @details[:environment] = bootstrap_data.delete(:environment)
        @details[:environment_variant] = bootstrap_data.delete(:environment_variant)
        if bootstrap_data[:environment_version]
          @details[:environment_version] = GxG::Version.new(bootstrap_data.delete(:environment_version))
        else
          @details[:environment_version] = nil
        end
        @details[:environment_configuration] = {}
        #
        # ### Process CPU info
        @details[:processors] = bootstrap_data.delete(:processors)
        @details[:processors].process! do |item, selector, container|
          if selector.is_any?(::String, ::Symbol)
            # hash/struct processing
            if selector.is_a?(Symbol)
              key = selector
            else
              key = selector.to_s.to_sym
            end
            # massage data by key
            # [:processor, :vendor_id, :cpu_family, :model, :model_name, :stepping, :cpu_mhz, :cache_size, :physical_id, :siblings, :core_id, :cpu_cores, :apicid, :initial_apicid, ::fpu, :fpu_exception, :cpuid_level, :wp, :flags, :bogomips, :clflush_size, :cache_alignment, :address_sizes, :power_management]
            entry = nil
            case key
            when :processor, :cpu_family, :model, :stepping, :physical_id, :siblings, :core_id, :cpu_cores, :apicid, :initial_apicid, :cpuid_level, :clflush_size, :cache_alignment
              entry = item.to_s.numeric_values()
              if entry.is_a?(Hash)
                item = entry[:integer]
              end
            when :cpu_mhz, :bogomips
              entry = item.to_s.numeric_values()
              if entry.is_a?(Hash)
                item = entry[:float]
              end
            when :cache_size
              entry = item.to_s.numeric_values([:byte])
              if entry.is_a?(Hash)
                item = entry[:byte]
              end
            when :address_sizes
              entry = item.to_s.numeric_values([:bit],",")
              if entry.is_a?(Array)
                item = {:physical_bits => (entry[0][:bit] || entry[0][:integer]), :virtual_bits => (entry[1][:bit] || entry[1][:integer])}
              end
            when :flags
              item = item.to_s.split(" ").to_enum.map do |flag|
                flag.to_sym
              end
            end
            if item
              if container.is_a?(::Hash)
                container.delete(selector)
                container[(key)] = item
              end
            end
          end
          nil
        end
        # TODO: Build up a list of flags that the cpu supports and are *actually* in use (i.e. PAE, ...)
        @details[:platform_flags] = {}
        # Gather platform kernel configuration data for processing.
        case @details[:platform]
        when :linux
          release = (`uname -r`.split("\n")[0])
          likely_paths = ["/proc/config.gz",("/lib/modules/#{release}/build/.config"),("/usr/src/linux-#{release}/.config"),("/usr/src/linux-#{release}/configs/#{release}-#{@details[:architecture]}.config"),("/boot/config-#{release}")]
          raw_data = ""
          likely_paths.to_enum.each do |the_path|
            if ::File.exist?(the_path)
              # Note: at this point in everything it is ok for file io that blocks.
              if the_path == "/proc/config.gz"
                ::Zlib::GzipReader.open(the_path) { |gz|  raw_data = gz.read }
              else
                ::File.open(the_path, "r") { |i|  raw_data = i.read }
              end
              break
            end
          end
          # process raw_data (each line)
          raw_flags = {}
          raw_data.to_enum(:each_line).each do |line_text|
            flag = nil
            setting = nil
            if line_text.size > 0
              if line_text[0] == "#"
                if line_text.include?("is not set")
                  # cull unset thing and make its value nil.
                  flag = line_text[1..-1].scan(/[A-Z_]*/)[0]
                  if flag.size > 0
                    # exclude redundant 'CONFIG' portion
                    flag = flag.split("_")[1..-1].join("_")
                  else
                    flag = nil
                  end
                end
              else
                flag, setting = line_text.split("=")
                # exclude redundant 'CONFIG' portion
                flag = flag.split("_")[1..-1].join("_")
                if (setting == "y" || setting == "y\n")
                  setting = true
                end
                if (setting == "n" || setting == "n\n")
                  setting = false
                end
              end
            end
            if (flag)
              raw_flags[(flag)] = setting
            end
          end
          raw_data = nil
          # Note: I am *loathe* to use strings instead of symbols in hashes generally, but I don't like what ruby does
          # with symbols and memory for temporary data sets (looking at you matz and my slapping hand twitches).
          universal_synonyms = {"X86_PAE" => "physical_address_extension"}
          universal_synonyms["X86_32_SMP"] = "symetric_multiprocessing"
          universal_synonyms["X86_64_SMP"] = "symetric_multiprocessing"
          universal_synonyms["X86_HT"] = "hyperthreading"
          universal_synonyms["SWAP"] = "virtual_memory"
          #
          raw_flags.each_pair do |selector,value|
            #
            if universal_synonyms[(selector)]
              # include the flag ONLY if it is actually enabled (in use) on this build of the kernel
              if value
                @details[:platform_configuration][:flags][(universal_synonyms[(selector)].to_sym)] = value
              end
            end
          end
          # end linux area
        end
        #
        # ### Memory crap:
        #
        # Set computational and storage/memory limits by platform and environment:
        # See (with respect to Ruby) : http://www.rubynotes.net/uk/operating-systems/windows/item/82-physical-memory-limits.html
        # Note: RVALUE size (consumption size) is determined in a completely separate manner than the limit size (according to cpu virtual addressing bits used).
        # default for 32 bit OS used:
        system_memory = self.memory()
        per_process_max = 2147483648
        case @details[:platform]
        when :linux
          # for :linux : See http://linuxfollies.blogspot.com/2010/10/linux-memory-limits-rlimits.html
          # Note: Process::getrlimit("AS") does not reflect the reality of total ram + total swap space as a limit.
          if @details[:processors][0][:address_sizes].is_a?(::Hash)
            if @details[:processors][0][:address_sizes][:virtual_bits] == 32
              if @details[:platform_configuration][:flags][:physical_address_extension]
                # ??? what does that do to the memory limit under 32 bits
                # 3.12GB rumored: 3350074490.88 (rounded-down)
                per_process_max = 3350074490
              else
                per_process_max = 3221225472
              end
            end
          end
          if @details[:processors][0][:address_sizes].is_a?(::Hash)
            if @details[:processors][0][:address_sizes][:virtual_bits] == 64
              # odd thing: they built 64bit computers that only have slots enough for 2GB max ram (imagine!)
              # So... to deal with this dilemma, I'm going to set the per_process_max to system_memory[:actual][:total] (:actual=RAM) unless it is really a full 8TB+.
              if system_memory[:actual][:total] >= 8796093022208
                per_process_max = 8796093022208
              else
                per_process_max = system_memory[:actual][:total]
              end
            end
          else
            # virtual bits reading NOT supported:
            if ([ -1 ].pack('l!').length * 8) == 32
              if @details[:platform_configuration][:flags][:physical_address_extension]
                # ??? what does that do to the memory limit under 32 bits
                # 3.12GB rumored: 3350074490.88 (rounded-down)
                per_process_max = 3350074490
              else
                per_process_max = 3221225472
              end
            end
            if ([ -1 ].pack('l!').length * 8) == 64
              if system_memory[:actual][:total] >= 8796093022208
                per_process_max = 8796093022208
              else
                per_process_max = system_memory[:actual][:total]
              end
            end
          end
        when :windows
          # for :windows : See http://msdn.microsoft.com/en-us/library/windows/desktop/aa366778%28v=vs.85%29.aspx
          # And "4GB-tuning' at http://msdn.microsoft.com/en-us/library/windows/desktop/bb613473%28v=vs.85%29.aspx
          # And "BCDEdit /set' at http://msdn.microsoft.com/en-us/library/ff542202.aspx
          # TODO: :windows : find a way to test if IMAGE_FILE_LARGE_ADDRESS_AWARE is set, whether os runs in PAE mode, and
          # what BCDEdit /set Increaseuserva (gigabytes-as-megabytes) was set to. (kernel_mode address space = 4GB-(2048MB-to-3072MB value of it))
          # on infamous /3GB switch in boot.ini : http://www.ditii.com/2007/04/14/memory-management-demystifying-3gb/
          # if @details[:processors][0][:address_sizes][:virtual_bits] == 32
          #   # :windows 32-bit : 2GB per process memory limit (non-contiguous-only)
          #   per_process_max = 2147483648
          # end
          # if @details[:processors][0][:address_sizes][:virtual_bits] == 64
          #   # :if IMAGE_FILE_LARGE_ADDRESS_AWARE is set on process image, then 8TB max per 64-bit process, except on Intel Itanium-based systems (7TB)
          #   # otherwise (if unset, and since we have no F'n way to tell within ruby):
          #   per_process_max = 2147483648
          # end
          # Review : Since I am only supporting 64-bit Windows (and don't know how to survey cpu info) -- skip prior tests
          per_process_max = 2147483648
        end
        #
        if system_memory[:total][:total] >= per_process_max
          @details[:memory_limits]={:process => ((per_process_max)..(system_memory[:total][:total]))}
        else
          @details[:memory_limits]={:process => ((system_memory[:total][:total])..(system_memory[:total][:total]))}
        end
        # stock setrlimit will ignore the 'hard-wired' limit reset to actual available memory (both kinds), but the overridden GxG::Engine::getrlimit(:AS) will respect it.
        # GxG::Engine::memory_available() is built around these limits to ensure you do not encounter an issue without some warning (no Exabyte delusions).
        # ::Process::setrlimit(:AS,@details[:memory_limits][:process].min,@details[:memory_limits][:process].max)
        #
        # ### Initial Buffer Sizes
        # TODO: find a clever way to determine the platform's maximum buffer size (after linux 2.6.14 (I think) buffers are now 16x4KiB).
        @details[:memory_limits][:buffers] = {:default => 4096, :terminal => 1024,:socket => {:ipc => {}}, :ipv4 => {:tcp => {}, :udp => {}}}
        # Attribution: http://www.psc.edu/networking/projects/tcptune/#detailed and
        # http://www.psc.edu/networking/projects/tcptune/#tutorial
        #
        case @details[:platform]
        when :linux
          # TODO: provide for better version comparisons: create >, <. etc methods that accept a string to interperet or a value instance.
          # See: http://www.pixelbeat.org/programming/stdio_buffering/
          platform_version = @details[:platform_version].value
          if platform_version[:major] > 2
            @details[:memory_limits][:buffers][:default] = 65536
          end
          if platform_version[:major] == 2
            if platform_version[:minor] >= 6
              if platform_version[:teeny] >= 14
                @details[:memory_limits][:buffers][:default] = 65536
              end
            end
          end
        end
        #
        # ### The Ruby runtime itself
        # Now defined in GxG::Engine as a chance to correct some 'free-form-jazz-ensemble-a-la-SpinalTap' stuff from the guys at Ruby Core! :)
        # 
        # ### Network stuff
        # node (or host) name:
        @details[:nodename] = ::Socket.gethostname
        @details[:network] = {}
        begin
          address = ::TCPSocket.getaddress(@details[:nodename])
        rescue Exception
          # raise Exception, "You need to edit your host file, and add an alias for this host."
          # exit 1
          address = nil
        end
        # netstat --interfaces --all --verbose --extend
        #
        @details[:network][:hostname] = @details[:nodename]
        # TODO: @gather localhost info: convert ip address info to std. ip_addr objects
        @details[:network][:address] = address
        @details[:network][:hosts] = []
        #        raw_list = Sys::Host.info
        #        raw_list.to_enum.each do |entry|
        #          new_entry = {}
        #          entry.each_pair do |key,item|
        #            # TODO: @gather hosts info: convert ip address info to std. ip_addr objects
        #            new_entry[(key.to_sym)] = item
        #          end
        #          @details[:network][:hosts] << new_entry
        #          #
        #        end
        #
        # TODO: inventory each network interface and host address of the system
        # then, attach active, kernel supported, protocols
        # then, use self["a/setting/path"] to set the data for each setting of each protocol of each nic that is supported and active.
        protocols = {
          :ipv4=>{:settings=>{:tcp => {}, :udp => {}}, :aliases=>["IP"], :proto=>0},
          :icmp=>{:settings=>{}, :aliases=>["ICMP"], :proto=>1},
          :igmp=>{:settings=>{}, :aliases=>["IGMP"], :proto=>2},
          :ggp=>{:settings=>{}, :aliases=>["GGP"], :proto=>3},
          :ipencap=>{:settings=>{}, :aliases=>["IP-ENCAP"], :proto=>4},
          :st=>{:settings=>{}, :aliases=>["ST"], :proto=>5},
          :tcp=>{:settings=>{}, :aliases=>["TCP"], :proto=>6},
          :egp=>{:settings=>{}, :aliases=>["EGP"], :proto=>8},
          :igp=>{:settings=>{}, :aliases=>["IGP"], :proto=>9},
          :pup=>{:settings=>{}, :aliases=>["PUP"], :proto=>12},
          :udp=>{:settings=>{}, :aliases=>["UDP"], :proto=>17},
          :hmp=>{:settings=>{}, :aliases=>["HMP"], :proto=>20},
          :"xns-idp"=>{:settings=>{}, :aliases=>["XNS-IDP"], :proto=>22},
          :rdp=>{:settings=>{}, :aliases=>["RDP"], :proto=>27},
          :"iso-tp4"=>{:settings=>{}, :aliases=>["ISO-TP4"], :proto=>29},
          :dccp=>{:settings=>{}, :aliases=>["DCCP"], :proto=>33},
          :xtp=>{:settings=>{}, :aliases=>["XTP"], :proto=>36},
          :ddp=>{:settings=>{}, :aliases=>["DDP"], :proto=>37},
          :"idpr-cmtp"=>{:settings=>{}, :aliases=>["IDPR-CMTP"], :proto=>38},
          :ipv6=>{:settings=>{:tcp=>{}, :udp=>{}}, :aliases=>["IPv6"], :proto=>41},
          :"ipv6-route"=>{:settings=>{}, :aliases=>["IPv6-Route"], :proto=>43},
          :"ipv6-frag"=>{:settings=>{}, :aliases=>["IPv6-Frag"], :proto=>44},
          :idrp=>{:settings=>{}, :aliases=>["IDRP"], :proto=>45},
          :rsvp=>{:settings=>{}, :aliases=>["RSVP"], :proto=>46},
          :gre=>{:settings=>{}, :aliases=>["GRE"], :proto=>47},
          :esp=>{:settings=>{}, :aliases=>["IPSEC-ESP"], :proto=>50},
          :ah=>{:settings=>{}, :aliases=>["IPSEC-AH"], :proto=>51},
          :skip=>{:settings=>{}, :aliases=>["SKIP"], :proto=>57},
          :"ipv6-icmp"=>{:settings=>{}, :aliases=>["IPv6-ICMP"], :proto=>58},
          :"ipv6-nonxt"=>{:settings=>{}, :aliases=>["IPv6-NoNxt"], :proto=>59},
          :"ipv6-opts"=>{:settings=>{}, :aliases=>["IPv6-Opts"], :proto=>60},
          :rspf=>{:settings=>{}, :aliases=>["RSPF", "CPHB"], :proto=>73},
          :vmtp=>{:settings=>{}, :aliases=>["VMTP"], :proto=>81},
          :eigrp=>{:settings=>{}, :aliases=>["EIGRP"], :proto=>88},
          :ospf=>{:settings=>{}, :aliases=>["OSPFIGP"], :proto=>89},
          :"ax.25"=>{:settings=>{}, :aliases=>["AX.25"], :proto=>93},
          :ipip=>{:settings=>{}, :aliases=>["IPIP"], :proto=>94},
          :etherip=>{:settings=>{}, :aliases=>["ETHERIP"], :proto=>97},
          :encap=>{:settings=>{}, :aliases=>["ENCAP"], :proto=>98},
          :pim=>{:settings=>{}, :aliases=>["PIM"], :proto=>103},
          :ipcomp=>{:settings=>{}, :aliases=>["IPCOMP"], :proto=>108},
          :vrrp=>{:settings=>{}, :aliases=>["VRRP"], :proto=>112},
          :l2tp=>{:settings=>{}, :aliases=>["L2TP"], :proto=>115},
          :isis=>{:settings=>{}, :aliases=>["ISIS"], :proto=>124},
          :sctp=>{:settings=>{}, :aliases=>["SCTP"], :proto=>132},
          :fc=>{:settings=>{}, :aliases=>["FC"], :proto=>133},
          :"mobility-header"=>{:settings=>{}, :aliases=>["Mobility-Header"], :proto=>135},
          :udplite=>{:settings=>{}, :aliases=>["UDPLite"], :proto=>136},
          :"mpls-in-ip"=>{:settings=>{}, :aliases=>["MPLS-in-IP"], :proto=>137},
          :manet=>{:settings=>{}, :aliases=>[], :proto=>138},
          :hip=>{:settings=>{}, :aliases=>["HIP"], :proto=>139},
          :shim6=>{:settings=>{}, :aliases=>["Shim6"], :proto=>140},
          :wesp=>{:settings=>{}, :aliases=>["WESP"], :proto=>141},
          :rohc=>{:settings=>{}, :aliases=>["ROHC"], :proto=>142}
          }
        #
        @details[:network][:protocols] = protocols
        #        if @details[:platform] == :windows
        #          # TODO: find suitable alternative to Net::Proto.getprotoent (breaks under rbx)
        #        else
        #          raw_list = Net::Proto.getprotoent
        #          raw_list.to_enum.each do |entry|
        #            new_entry = {:settings => {}}
        #            proto_name = :unknown
        #            entry.each_pair do |key,item|
        #              if key.to_s.to_sym == :name
        #                if item.to_s.to_sym == :ip
        #                  proto_name = :ipv4
        #                else
        #                  proto_name = item.to_s.to_sym
        #                end
        #              else
        #                new_entry[(key)] = item
        #              end
        #            end
        #            if [:ipv4,:ipv6].include?(proto_name)
        #              new_entry[:settings][:tcp] = {}
        #              new_entry[:settings][:udp] = {}
        #            end
        #            @details[:network][:protocols][(proto_name)] = new_entry
        #            #
        #          end
        #        end
        # Read in Sysctl-style keys and set @details data.
        get_system_data(detail_mapping())
        #
        #
        # File descriptor reservation and release support, reserving $stdin, $stdout, and $stderr, etc.
        # TODO: get a *complete* list of getconf variables *and their meanings* and incorporate them into sysctl-style path system.
        # See: http://www.lainoox.com/system-wide-config-getconf/
        # self["configuration.process.maximum_file_descriptors"]
        # LATER: add lsof to requirements list within installer.
        case @details[:platform]
        when :linux, :aix, :solaris, :bsd, :darwin
          # TODO: research -F option of lsof
          # See: http://geek00l.blogspot.com/2006/03/openbsd-fstat-vs-lsof.html
        end
        #
        case @details[:platform]
        when :bsd
          # See: fstat vs lsof : http://geek00l.blogspot.com/2006/03/openbsd-fstat-vs-lsof.html
          #
          # if EventMachine::kqueue?
            # ?
            # @details[:maximum_descriptors][:events] = 1000000
          # end
        when :linux
          # if EventMachine::epoll?
            # ?
            # @details[:maximum_descriptors][:events] = 1000000
          # end
        end
        # ###
        @valid_modes = {}
        # Internal Services to Port Usage mapping
        @details[:service_ports] = {
          :tcpmux=>{:aliases=>[], :clients=>[], :description=>"TCP port service multiplexer", :uses=>{:tcp=>[1]}},
          :echo=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[7], :udp=>[7], :ddp=>[4]}},
          :discard=>{:aliases=>["sink", "null"], :clients=>[], :description=>"", :uses=>{:tcp=>[9], :udp=>[9]}},
          :systat=>{:aliases=>["users"], :clients=>[], :description=>"", :uses=>{:tcp=>[11]}},
          :daytime=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[13], :udp=>[13]}},
          :netstat=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[15]}},
          :qotd=>{:aliases=>["quote"], :clients=>[], :description=>"", :uses=>{:tcp=>[17]}},
          :msp=>{:aliases=>[], :clients=>[], :description=>"message send protocol", :uses=>{:tcp=>[18], :udp=>[18]}},
          :chargen=>{:aliases=>["ttytst", "source"], :clients=>[], :description=>"", :uses=>{:tcp=>[19], :udp=>[19]}},
          :"ftp-data"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[20]}},
          :ftp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[21]}},
          :fsp=>{:aliases=>["fspd"], :clients=>[], :description=>"", :uses=>{:udp=>[21]}},
          :ssh=>{:aliases=>[], :clients=>[], :description=>"SSH Remote Login Protocol", :uses=>{:tcp=>[22], :udp=>[22]}},
          :telnet=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[23]}},
          :smtp=>{:aliases=>["mail"], :clients=>[], :description=>"", :uses=>{:tcp=>[25]}},
          :time=>{:aliases=>["timserver"], :clients=>[], :description=>"", :uses=>{:tcp=>[37], :udp=>[37]}},
          :rlp=>{:aliases=>["resource"], :clients=>[], :description=>"resource location", :uses=>{:udp=>[39]}},
          :nameserver=>{:aliases=>["name"], :clients=>[], :description=>"IEN 116", :uses=>{:tcp=>[42]}},
          :whois=>{:aliases=>["nicname"], :clients=>[], :description=>"", :uses=>{:tcp=>[43]}},
          :tacacs=>{:aliases=>[], :clients=>[], :description=>"Login Host Protocol (TACACS)", :uses=>{:tcp=>[49], :udp=>[49]}},
          :"re-mail-ck"=>{:aliases=>[], :clients=>[], :description=>"Remote Mail Checking Protocol", :uses=>{:tcp=>[50], :udp=>[50]}},
          :domain=>{:aliases=>[], :clients=>[], :description=>"name-domain server", :uses=>{:tcp=>[53], :udp=>[53]}},
          :mtp=>{:aliases=>[], :clients=>[], :description=>"deprecated", :uses=>{:tcp=>[57]}},
          :"tacacs-ds"=>{:aliases=>[], :clients=>[], :description=>"TACACS-Database Service", :uses=>{:tcp=>[65], :udp=>[65]}},
          :bootps=>{:aliases=>[], :clients=>[], :description=>"BOOTP server", :uses=>{:tcp=>[67], :udp=>[67]}},
          :bootpc=>{:aliases=>[], :clients=>[], :description=>"BOOTP client", :uses=>{:tcp=>[68], :udp=>[68]}},
          :tftp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:udp=>[69]}},
          :gopher=>{:aliases=>[], :clients=>[], :description=>"Internet Gopher", :uses=>{:tcp=>[70], :udp=>[70]}},
          :rje=>{:aliases=>["netrjs"], :clients=>[], :description=>"", :uses=>{:tcp=>[77]}},
          :finger=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[79]}},
          :www=>{:aliases=>["http"], :clients=>[], :description=>"WorldWideWeb HTTP", :uses=>{:tcp=>[80], :udp=>[80]}},
          :link=>{:aliases=>["ttylink"], :clients=>[], :description=>"", :uses=>{:tcp=>[87]}},
          :kerberos=>{:aliases=>["kerberos5", "krb5", "kerberos-sec"], :clients=>[], :description=>"Kerberos v5", :uses=>{:tcp=>[88], :udp=>[88]}},
          :supdup=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[95]}},
          :hostnames=>{:aliases=>["hostname"], :clients=>[], :description=>"usually from sri-nic", :uses=>{:tcp=>[101]}},
          :"iso-tsap"=>{:aliases=>["tsap"], :clients=>[], :description=>"part of ISODE", :uses=>{:tcp=>[102]}},
          :"acr-nema"=>{:aliases=>["dicom"], :clients=>[], :description=>"Digital Imag. & Comm. 300", :uses=>{:tcp=>[104], :udp=>[104]}},
          :"csnet-ns"=>{:aliases=>["cso-ns"], :clients=>[], :description=>"also used by CSO name server", :uses=>{:tcp=>[105], :udp=>[105]}},
          :rtelnet=>{:aliases=>[], :clients=>[], :description=>"Remote Telnet", :uses=>{:tcp=>[107], :udp=>[107]}},
          :pop2=>{:aliases=>["postoffice", "pop-2"], :clients=>[], :description=>"POP version 2", :uses=>{:tcp=>[109], :udp=>[109]}},
          :pop3=>{:aliases=>["pop-3"], :clients=>[], :description=>"POP version 3", :uses=>{:tcp=>[110], :udp=>[110]}},
          :sunrpc=>{:aliases=>["portmapper"], :clients=>[], :description=>"RPC 4.0 portmapper", :uses=>{:tcp=>[111], :udp=>[111]}},
          :auth=>{:aliases=>["authentication", "tap", "ident"], :clients=>[], :description=>"", :uses=>{:tcp=>[113]}},
          :sftp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[115]}},
          :"uucp-path"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[117]}},
          :nntp=>{:aliases=>["readnews", "untp"], :clients=>[], :description=>"USENET News Transfer Protocol", :uses=>{:tcp=>[119]}},
          :ntp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[123], :udp=>[123]}},
          :pwdgen=>{:aliases=>[], :clients=>[], :description=>"PWDGEN service", :uses=>{:tcp=>[129], :udp=>[129]}},
          :"loc-srv"=>{:aliases=>["epmap"], :clients=>[], :description=>"Location Service", :uses=>{:tcp=>[135], :udp=>[135]}},
          :"netbios-ns"=>{:aliases=>[], :clients=>[], :description=>"NETBIOS Name Service", :uses=>{:tcp=>[137], :udp=>[137]}},
          :"netbios-dgm"=>{:aliases=>[], :clients=>[], :description=>"NETBIOS Datagram Service", :uses=>{:tcp=>[138], :udp=>[138]}},
          :"netbios-ssn"=>{:aliases=>[], :clients=>[], :description=>"NETBIOS session service", :uses=>{:tcp=>[139], :udp=>[139]}},
          :imap2=>{:aliases=>["imap"], :clients=>[], :description=>"Interim Mail Access P 2 and 4", :uses=>{:tcp=>[143], :udp=>[143]}},
          :snmp=>{:aliases=>[], :clients=>[], :description=>"Simple Net Mgmt Protocol", :uses=>{:tcp=>[161], :udp=>[161]}},
          :"snmp-trap"=>{:aliases=>["snmptrap"], :clients=>[], :description=>"Traps for SNMP", :uses=>{:tcp=>[162], :udp=>[162]}},
          :"cmip-man"=>{:aliases=>[], :clients=>[], :description=>"ISO mgmt over IP (CMOT)", :uses=>{:tcp=>[163], :udp=>[163]}},
          :"cmip-agent"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[164], :udp=>[164]}},
          :mailq=>{:aliases=>[], :clients=>[], :description=>"Mailer transport queue for Zmailer", :uses=>{:tcp=>[174], :udp=>[174]}},
          :xdmcp=>{:aliases=>[], :clients=>[], :description=>"X Display Mgr. Control Proto", :uses=>{:tcp=>[177], :udp=>[177]}},
          :nextstep=>{:aliases=>["NeXTStep", "NextStep"], :clients=>[], :description=>"NeXTStep window", :uses=>{:tcp=>[178], :udp=>[178]}},
          :bgp=>{:aliases=>[], :clients=>[], :description=>"Border Gateway Protocol", :uses=>{:tcp=>[179], :udp=>[179]}},
          :prospero=>{:aliases=>[], :clients=>[], :description=>"Cliff Neuman's Prospero", :uses=>{:tcp=>[191], :udp=>[191]}},
          :irc=>{:aliases=>[], :clients=>[], :description=>"Internet Relay Chat", :uses=>{:tcp=>[194], :udp=>[194]}},
          :smux=>{:aliases=>[], :clients=>[], :description=>"SNMP Unix Multiplexer", :uses=>{:tcp=>[199], :udp=>[199]}},
          :"at-rtmp"=>{:aliases=>[], :clients=>[], :description=>"AppleTalk routing", :uses=>{:tcp=>[201], :udp=>[201]}},
          :"at-nbp"=>{:aliases=>[], :clients=>[], :description=>"AppleTalk name binding", :uses=>{:tcp=>[202], :udp=>[202]}},
          :"at-echo"=>{:aliases=>[], :clients=>[], :description=>"AppleTalk echo", :uses=>{:tcp=>[204], :udp=>[204]}},
          :"at-zis"=>{:aliases=>[], :clients=>[], :description=>"AppleTalk zone information", :uses=>{:tcp=>[206], :udp=>[206]}},
          :qmtp=>{:aliases=>[], :clients=>[], :description=>"Quick Mail Transfer Protocol", :uses=>{:tcp=>[209], :udp=>[209]}},
          :z3950=>{:aliases=>["wais"], :clients=>[], :description=>"NISO Z39.50 database", :uses=>{:tcp=>[210], :udp=>[210]}},
          :ipx=>{:aliases=>[], :clients=>[], :description=>"IPX", :uses=>{:tcp=>[213], :udp=>[213]}},
          :imap3=>{:aliases=>[], :clients=>[], :description=>"Interactive Mail Access", :uses=>{:tcp=>[220], :udp=>[220]}},
          :pawserv=>{:aliases=>[], :clients=>[], :description=>"Perf Analysis Workbench", :uses=>{:tcp=>[345], :udp=>[345]}},
          :zserv=>{:aliases=>[], :clients=>[], :description=>"Zebra server", :uses=>{:tcp=>[346], :udp=>[346]}},
          :fatserv=>{:aliases=>[], :clients=>[], :description=>"Fatmen Server", :uses=>{:tcp=>[347], :udp=>[347]}},
          :rpc2portmap=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[369], :udp=>[369]}},
          :codaauth2=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[370], :udp=>[370]}},
          :clearcase=>{:aliases=>["Clearcase"], :clients=>[], :description=>"", :uses=>{:tcp=>[371], :udp=>[371]}},
          :ulistserv=>{:aliases=>[], :clients=>[], :description=>"UNIX Listserv", :uses=>{:tcp=>[372], :udp=>[372]}},
          :ldap=>{:aliases=>[], :clients=>[], :description=>"Lightweight Directory Access Protocol", :uses=>{:tcp=>[389], :udp=>[389]}},
          :imsp=>{:aliases=>[], :clients=>[], :description=>"Interactive Mail Support Protocol", :uses=>{:tcp=>[406], :udp=>[406]}},
          :svrloc=>{:aliases=>[], :clients=>[], :description=>"Server Location", :uses=>{:tcp=>[427], :udp=>[427]}},
          :https=>{:aliases=>[], :clients=>[], :description=>"http protocol over TLS/SSL", :uses=>{:tcp=>[443], :udp=>[443]}},
          :snpp=>{:aliases=>[], :clients=>[], :description=>"Simple Network Paging Protocol", :uses=>{:tcp=>[444], :udp=>[444]}},
          :"microsoft-ds"=>{:aliases=>[], :clients=>[], :description=>"Microsoft Naked CIFS", :uses=>{:tcp=>[445], :udp=>[445]}},
          :kpasswd=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[464], :udp=>[464]}},
          :saft=>{:aliases=>[], :clients=>[], :description=>"Simple Asynchronous File Transfer", :uses=>{:tcp=>[487], :udp=>[487]}},
          :isakmp=>{:aliases=>[], :clients=>[], :description=>"IPsec - Internet Security Association", :uses=>{:tcp=>[500], :udp=>[500]}},
          :rtsp=>{:aliases=>[], :clients=>[], :description=>"Real Time Stream Control Protocol", :uses=>{:tcp=>[554], :udp=>[554]}},
          :nqs=>{:aliases=>[], :clients=>[], :description=>"Network Queuing system", :uses=>{:tcp=>[607], :udp=>[607]}},
          :"npmp-local"=>{:aliases=>["dqs313_qmaster"], :clients=>[], :description=>"npmp-local / DQS", :uses=>{:tcp=>[610], :udp=>[610]}},
          :"npmp-gui"=>{:aliases=>["dqs313_execd"], :clients=>[], :description=>"npmp-gui / DQS", :uses=>{:tcp=>[611], :udp=>[611]}},
          :"hmmp-ind"=>{:aliases=>["dqs313_intercell"], :clients=>[], :description=>"HMMP Indication / DQS", :uses=>{:tcp=>[612], :udp=>[612]}},
          :qmqp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[628], :udp=>[628]}},
          :ipp=>{:aliases=>[], :clients=>[], :description=>"Internet Printing Protocol", :uses=>{:tcp=>[631], :udp=>[631]}},
          :exec=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[512]}},
          :biff=>{:aliases=>["comsat"], :clients=>[], :description=>"", :uses=>{:udp=>[512]}},
          :login=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[513]}},
          :who=>{:aliases=>["whod"], :clients=>[], :description=>"", :uses=>{:udp=>[513]}},
          :shell=>{:aliases=>["cmd"], :clients=>[], :description=>"no passwords used", :uses=>{:tcp=>[514]}},
          :syslog=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:udp=>[514]}},
          :printer=>{:aliases=>["spooler"], :clients=>[], :description=>"line printer spooler", :uses=>{:tcp=>[515]}},
          :talk=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:udp=>[517]}},
          :ntalk=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:udp=>[518]}},
          :route=>{:aliases=>["router", "routed"], :clients=>[], :description=>"RIP", :uses=>{:udp=>[520]}},
          :timed=>{:aliases=>["timeserver"], :clients=>[], :description=>"", :uses=>{:udp=>[525]}},
          :tempo=>{:aliases=>["newdate"], :clients=>[], :description=>"", :uses=>{:tcp=>[526]}},
          :courier=>{:aliases=>["rpc"], :clients=>[], :description=>"", :uses=>{:tcp=>[530]}},
          :conference=>{:aliases=>["chat"], :clients=>[], :description=>"", :uses=>{:tcp=>[531]}},
          :netnews=>{:aliases=>["readnews"], :clients=>[], :description=>"", :uses=>{:tcp=>[532]}},
          :netwall=>{:aliases=>[], :clients=>[], :description=>"for emergency broadcasts", :uses=>{:udp=>[533]}},
          :gdomap=>{:aliases=>[], :clients=>[], :description=>"GNUstep distributed objects", :uses=>{:tcp=>[538], :udp=>[538]}},
          :uucp=>{:aliases=>["uucpd"], :clients=>[], :description=>"uucp daemon", :uses=>{:tcp=>[540]}},
          :klogin=>{:aliases=>[], :clients=>[], :description=>"Kerberized `rlogin' (v5)", :uses=>{:tcp=>[543]}},
          :kshell=>{:aliases=>["krcmd"], :clients=>[], :description=>"Kerberized `rsh' (v5)", :uses=>{:tcp=>[544]}},
          :"dhcpv6-client"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[546], :udp=>[546]}},
          :"dhcpv6-server"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[547], :udp=>[547]}},
          :afpovertcp=>{:aliases=>[], :clients=>[], :description=>"AFP over TCP", :uses=>{:tcp=>[548], :udp=>[548]}},
          :idfp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[549], :udp=>[549]}},
          :remotefs=>{:aliases=>["rfs_server", "rfs"], :clients=>[], :description=>"Brunhoff remote filesystem", :uses=>{:tcp=>[556]}},
          :nntps=>{:aliases=>["snntp"], :clients=>[], :description=>"NNTP over SSL", :uses=>{:tcp=>[563], :udp=>[563]}},
          :submission=>{:aliases=>[], :clients=>[], :description=>"Submission [RFC4409]", :uses=>{:tcp=>[587], :udp=>[587]}},
          :ldaps=>{:aliases=>[], :clients=>[], :description=>"LDAP over SSL", :uses=>{:tcp=>[636], :udp=>[636]}},
          :tinc=>{:aliases=>[], :clients=>[], :description=>"tinc control port", :uses=>{:tcp=>[655], :udp=>[655]}},
          :silc=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[706], :udp=>[706]}},
          :"kerberos-adm"=>{:aliases=>[], :clients=>[], :description=>"Kerberos `kadmin' (v5)", :uses=>{:tcp=>[749]}},
          :webster=>{:aliases=>[], :clients=>[], :description=>"Network dictionary", :uses=>{:tcp=>[765], :udp=>[765]}},
          :rsync=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[873], :udp=>[873]}},
          :"ftps-data"=>{:aliases=>[], :clients=>[], :description=>"FTP over SSL (data)", :uses=>{:tcp=>[989]}},
          :ftps=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[990]}},
          :telnets=>{:aliases=>[], :clients=>[], :description=>"Telnet over SSL", :uses=>{:tcp=>[992], :udp=>[992]}},
          :imaps=>{:aliases=>[], :clients=>[], :description=>"IMAP over SSL", :uses=>{:tcp=>[993], :udp=>[993]}},
          :ircs=>{:aliases=>[], :clients=>[], :description=>"IRC over SSL", :uses=>{:tcp=>[994], :udp=>[994]}},
          :pop3s=>{:aliases=>[], :clients=>[], :description=>"POP-3 over SSL", :uses=>{:tcp=>[995], :udp=>[995]}},
          :socks=>{:aliases=>[], :clients=>[], :description=>"socks proxy server", :uses=>{:tcp=>[1080], :udp=>[1080]}},
          :proofd=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1093], :udp=>[1093]}},
          :rootd=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1094], :udp=>[1094]}},
          :openvpn=>{:aliases=>["vpn"], :clients=>[], :description=>"", :uses=>{:tcp=>[1194], :udp=>[1194]}, :uses_preference => :udp},
          :rmiregistry=>{:aliases=>[], :clients=>[], :description=>"Java RMI Registry", :uses=>{:tcp=>[1099], :udp=>[1099]}},
          :kazaa=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1214], :udp=>[1214]}},
          :nessus=>{:aliases=>[], :clients=>[], :description=>"Nessus vulnerability", :uses=>{:tcp=>[1241], :udp=>[1241]}},
          :lotusnote=>{:aliases=>[], :clients=>[], :description=>"Lotus Note", :uses=>{:tcp=>[1352], :udp=>[1352]}},
          :"ms-sql-s"=>{:aliases=>[], :clients=>[], :description=>"Microsoft SQL Server", :uses=>{:tcp=>[1433], :udp=>[1433]}},
          :"ms-sql-m"=>{:aliases=>[], :clients=>[], :description=>"Microsoft SQL Monitor", :uses=>{:tcp=>[1434], :udp=>[1434]}},
          :ingreslock=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1524], :udp=>[1524]}},
          :"prospero-np"=>{:aliases=>[], :clients=>[], :description=>"Prospero non-privileged", :uses=>{:tcp=>[1525], :udp=>[1525]}},
          :datametrics=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1645], :udp=>[1645]}},
          :"sa-msg-port"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1646], :udp=>[1646]}},
          :kermit=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1649], :udp=>[1649]}},
          :l2f=>{:aliases=>["l2tp"], :clients=>[], :description=>"", :uses=>{:tcp=>[1701], :udp=>[1701]}},
          :radius=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[1812], :udp=>[1812]}},
          :"radius-acct"=>{:aliases=>[], :clients=>[], :description=>"Radius Accounting", :uses=>{:tcp=>[1813], :udp=>[1813]}},
          :msnp=>{:aliases=>[], :clients=>[], :description=>"MSN Messenger", :uses=>{:tcp=>[1863], :udp=>[1863]}},
          :"unix-status"=>{:aliases=>[], :clients=>[], :description=>"remstats unix-status server", :uses=>{:tcp=>[1957]}},
          :"log-server"=>{:aliases=>[], :clients=>[], :description=>"remstats log server", :uses=>{:tcp=>[1958]}},
          :remoteping=>{:aliases=>[], :clients=>[], :description=>"remstats remoteping server", :uses=>{:tcp=>[1959]}},
          :"cisco-sccp"=>{:aliases=>[], :clients=>[], :description=>"Cisco SCCP", :uses=>{:tcp=>[2000], :udp=>[2000]}},
          :search=>{:aliases=>["ndtp"], :clients=>[], :description=>"", :uses=>{:tcp=>[2010]}},
          :pipe_server=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[2010]}},
          :nfs=>{:aliases=>[], :clients=>[], :description=>"Network File System", :uses=>{:tcp=>[2049], :udp=>[2049]}},
          :gnunet=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[2086], :udp=>[2086]}},
          :"rtcm-sc104"=>{:aliases=>[], :clients=>[], :description=>"RTCM SC-104 IANA 1/29/99", :uses=>{:tcp=>[2101], :udp=>[2101]}},
          :gsigatekeeper=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[2119], :udp=>[2119]}},
          :gris=>{:aliases=>[], :clients=>[], :description=>"Grid Resource Information Server", :uses=>{:tcp=>[2135], :udp=>[2135]}},
          :cvspserver=>{:aliases=>[], :clients=>[], :description=>"CVS client/server operations", :uses=>{:tcp=>[2401], :udp=>[2401]}},
          :venus=>{:aliases=>[], :clients=>[], :description=>"codacon port", :uses=>{:tcp=>[2430], :udp=>[2430]}},
          :"venus-se"=>{:aliases=>[], :clients=>[], :description=>"tcp side effects", :uses=>{:tcp=>[2431], :udp=>[2431]}},
          :codasrv=>{:aliases=>[], :clients=>[], :description=>"not used", :uses=>{:tcp=>[2432], :udp=>[2432]}},
          :"codasrv-se"=>{:aliases=>[], :clients=>[], :description=>"tcp side effects", :uses=>{:tcp=>[2433], :udp=>[2433]}},
          :mon=>{:aliases=>[], :clients=>[], :description=>"MON traps", :uses=>{:tcp=>[2583], :udp=>[2583]}},
          :dict=>{:aliases=>[], :clients=>[], :description=>"Dictionary server", :uses=>{:tcp=>[2628], :udp=>[2628]}},
          :gsiftp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[2811], :udp=>[2811]}},
          :gpsd=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[2947], :udp=>[2947]}},
          :gds_db=>{:aliases=>[], :clients=>[], :description=>"InterBase server", :uses=>{:tcp=>[3050], :udp=>[3050]}},
          :icpv2=>{:aliases=>["icp"], :clients=>[], :description=>"Internet Cache Protocol", :uses=>{:tcp=>[3130], :udp=>[3130]}},
          :mysql=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[3306], :udp=>[3306]}},
          :nut=>{:aliases=>[], :clients=>[], :description=>"Network UPS Tools", :uses=>{:tcp=>[3493], :udp=>[3493]}},
          :distcc=>{:aliases=>[], :clients=>[], :description=>"distributed compiler", :uses=>{:tcp=>[3632], :udp=>[3632]}},
          :daap=>{:aliases=>[], :clients=>[], :description=>"Digital Audio Access Protocol", :uses=>{:tcp=>[3689], :udp=>[3689]}},
          :svn=>{:aliases=>["subversion"], :clients=>[], :description=>"Subversion protocol", :uses=>{:tcp=>[3690], :udp=>[3690]}},
          :suucp=>{:aliases=>[], :clients=>[], :description=>"UUCP over SSL", :uses=>{:tcp=>[4031], :udp=>[4031]}},
          :sysrqd=>{:aliases=>[], :clients=>[], :description=>"sysrq daemon", :uses=>{:tcp=>[4094], :udp=>[4094]}},
          :sieve=>{:aliases=>[], :clients=>[], :description=>"ManageSieve Protocol", :uses=>{:tcp=>[4190]}},
          :epmd=>{:aliases=>[], :clients=>[], :description=>"Erlang Port Mapper Daemon", :uses=>{:tcp=>[4369], :udp=>[4369]}},
          :remctl=>{:aliases=>[], :clients=>[], :description=>"Remote Authenticated Command Service", :uses=>{:tcp=>[4373], :udp=>[4373]}},
          :iax=>{:aliases=>[], :clients=>[], :description=>"Inter-Asterisk eXchange", :uses=>{:tcp=>[4569], :udp=>[4569]}},
          :mtn=>{:aliases=>[], :clients=>[], :description=>"monotone Netsync Protocol", :uses=>{:tcp=>[4691], :udp=>[4691]}},
          :"radmin-port"=>{:aliases=>[], :clients=>[], :description=>"RAdmin Port", :uses=>{:tcp=>[4899], :udp=>[4899]}},
          :rfe=>{:aliases=>[], :clients=>[], :description=>"Radio Free Ethernet", :uses=>{:udp=>[5002], :tcp=>[5002]}},
          :mmcc=>{:aliases=>[], :clients=>[], :description=>"multimedia conference control tool (Yahoo IM)", :uses=>{:tcp=>[5050], :udp=>[5050]}},
          :sip=>{:aliases=>[], :clients=>[], :description=>"Session Initiation Protocol", :uses=>{:tcp=>[5060], :udp=>[5060]}},
          :"sip-tls"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[5061], :udp=>[5061]}},
          :aol=>{:aliases=>[], :clients=>[], :description=>"AIM", :uses=>{:tcp=>[5190], :udp=>[5190]}},
          :"xmpp-client"=>{:aliases=>[], :clients=>[], :description=>"Jabber Client Connection", :uses=>{:tcp=>[5222], :udp=>[5222]}},
          :"xmpp-server"=>{:aliases=>[], :clients=>[], :description=>"Jabber Server Connection", :uses=>{:tcp=>[5269], :udp=>[5269]}},
          :cfengine=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[5308], :udp=>[5308]}},
          :mdns=>{:aliases=>[], :clients=>[], :description=>"Multicast DNS", :uses=>{:tcp=>[5353], :udp=>[5353]}},
          :postgresql=>{:aliases=>[], :clients=>[], :description=>"PostgreSQL Database", :uses=>{:tcp=>[5432], :udp=>[5432]}},
          :freeciv=>{:aliases=>["rptp"], :clients=>[], :description=>"Freeciv gameplay", :uses=>{:tcp=>[5556], :udp=>[5556]}},
          :amqp=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[5672], :udp=>[5672], :sctp=>[5672]}},
          :ggz=>{:aliases=>[], :clients=>[], :description=>"GGZ Gaming Zone", :uses=>{:tcp=>[5688], :udp=>[5688]}},
          :x11=>{:aliases=>["x11-0"], :clients=>[], :description=>"X Window System", :uses=>{:tcp=>[6000], :udp=>[6000]}},
          :"x11-1"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6001], :udp=>[6001]}},
          :"x11-2"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6002], :udp=>[6002]}},
          :"x11-3"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6003], :udp=>[6003]}},
          :"x11-4"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6004], :udp=>[6004]}},
          :"x11-5"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6005], :udp=>[6005]}},
          :"x11-6"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6006], :udp=>[6006]}},
          :"x11-7"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[6007], :udp=>[6007]}},
          :"gnutella-svc"=>{:aliases=>[], :clients=>[], :description=>"gnutella", :uses=>{:tcp=>[6346], :udp=>[6346]}},
          :"gnutella-rtr"=>{:aliases=>[], :clients=>[], :description=>"gnutella", :uses=>{:tcp=>[6347], :udp=>[6347]}},
          :sge_qmaster=>{:aliases=>[], :clients=>[], :description=>"Grid Engine Qmaster Service", :uses=>{:tcp=>[6444], :udp=>[6444]}},
          :sge_execd=>{:aliases=>[], :clients=>[], :description=>"Grid Engine Execution Service", :uses=>{:tcp=>[6445], :udp=>[6445]}},
          :"mysql-proxy"=>{:aliases=>[], :clients=>[], :description=>"MySQL Proxy", :uses=>{:tcp=>[6446], :udp=>[6446]}},
          :"afs3-fileserver" => {:aliases => ["bbs"], :clients => [], :description => "file server itself", :uses => {:tcp => [7000], :udp => [7000]}},
          :"afs3-callback"=>{:aliases=>[], :clients=>[], :description=>"callbacks to cache managers", :uses=>{:tcp=>[7001], :udp=>[7001]}},
          :"afs3-prserver"=>{:aliases=>[], :clients=>[], :description=>"users & groups database", :uses=>{:tcp=>[7002], :udp=>[7002]}},
          :"afs3-vlserver"=>{:aliases=>[], :clients=>[], :description=>"volume location database", :uses=>{:tcp=>[7003], :udp=>[7003]}},
          :"afs3-kaserver"=>{:aliases=>[], :clients=>[], :description=>"AFS/Kerberos authentication", :uses=>{:tcp=>[7004], :udp=>[7004]}},
          :"afs3-volser"=>{:aliases=>[], :clients=>[], :description=>"volume managment server", :uses=>{:tcp=>[7005], :udp=>[7005]}},
          :"afs3-errors"=>{:aliases=>[], :clients=>[], :description=>"error interpretation service", :uses=>{:tcp=>[7006], :udp=>[7006]}},
          :"afs3-bos"=>{:aliases=>[], :clients=>[], :description=>"basic overseer process", :uses=>{:tcp=>[7007], :udp=>[7007]}},
          :"afs3-update"=>{:aliases=>[], :clients=>[], :description=>"server-to-server updater", :uses=>{:tcp=>[7008], :udp=>[7008]}},
          :"afs3-rmtsys"=>{:aliases=>[], :clients=>[], :description=>"remote cache manager service", :uses=>{:tcp=>[7009], :udp=>[7009]}},
          :"font-service"=>{:aliases=>[], :clients=>[], :description=>"X Font Service", :uses=>{:tcp=>[7100], :udp=>[7100]}},
          :"http-alt"=>{:aliases=>[], :clients=>[], :description=>"WWW caching service", :uses=>{:tcp=>[8080], :udp=>[8080]}},
          :"bacula-dir"=>{:aliases=>[], :clients=>[], :description=>"Bacula Director", :uses=>{:tcp=>[9101], :udp=>[9101]}},
          :"bacula-fd"=>{:aliases=>[], :clients=>[], :description=>"Bacula File Daemon", :uses=>{:tcp=>[9102], :udp=>[9102]}},
          :"bacula-sd"=>{:aliases=>[], :clients=>[], :description=>"Bacula Storage Daemon", :uses=>{:tcp=>[9103], :udp=>[9103]}},
          :xmms2=>{:aliases=>[], :clients=>[], :description=>"Cross-platform Music Multiplexing System", :uses=>{:tcp=>[9667], :udp=>[9667]}},
          :nbd=>{:aliases=>[], :clients=>[], :description=>"Linux Network Block Device", :uses=>{:tcp=>[10809]}},
          :"zabbix-agent"=>{:aliases=>[], :clients=>[], :description=>"Zabbix Agent", :uses=>{:tcp=>[10050], :udp=>[10050]}},
          :"zabbix-trapper"=>{:aliases=>[], :clients=>[], :description=>"Zabbix Trapper", :uses=>{:tcp=>[10051], :udp=>[10051]}},
          :amanda=>{:aliases=>[], :clients=>[], :description=>"amanda backup services", :uses=>{:tcp=>[10080], :udp=>[10080]}},
          :hkp=>{:aliases=>[], :clients=>[], :description=>"OpenPGP HTTP Keyserver", :uses=>{:tcp=>[11371], :udp=>[11371]}},
          :bprd=>{:aliases=>[], :clients=>[], :description=>"VERITAS NetBackup", :uses=>{:tcp=>[13720], :udp=>[13720]}},
          :bpdbm=>{:aliases=>[], :clients=>[], :description=>"VERITAS NetBackup", :uses=>{:tcp=>[13721], :udp=>[13721]}},
          :"bpjava-msvc"=>{:aliases=>[], :clients=>[], :description=>"BP Java MSVC Protocol", :uses=>{:tcp=>[13722], :udp=>[13722]}},
          :vnetd=>{:aliases=>[], :clients=>[], :description=>"Veritas Network Utility", :uses=>{:tcp=>[13724], :udp=>[13724]}},
          :bpcd=>{:aliases=>[], :clients=>[], :description=>"VERITAS NetBackup", :uses=>{:tcp=>[13782], :udp=>[13782]}},
          :vopied=>{:aliases=>[], :clients=>[], :description=>"VERITAS NetBackup", :uses=>{:tcp=>[13783], :udp=>[13783]}},
          :dcap=>{:aliases=>[], :clients=>[], :description=>"dCache Access Protocol", :uses=>{:tcp=>[22125]}},
          :gsidcap=>{:aliases=>[], :clients=>[], :description=>"GSI dCache Access Protocol", :uses=>{:tcp=>[22128]}},
          :wnn6=>{:aliases=>[], :clients=>[], :description=>"wnn6", :uses=>{:tcp=>[22273], :udp=>[22273]}},
          :rtmp=>{:aliases=>[], :clients=>[], :description=>"Routing Table Maintenance Protocol", :uses=>{:ddp=>[1]}},
          :nbp=>{:aliases=>[], :clients=>[], :description=>"Name Binding Protocol", :uses=>{:ddp=>[2]}},
          :zip=>{:aliases=>[], :clients=>[], :description=>"Zone Information Protocol", :uses=>{:ddp=>[6]}},
          :kerberos4=>{:aliases=>["kerberos-iv", "kdc"], :clients=>[], :description=>"Kerberos (server)", :uses=>{:udp=>[750], :tcp=>[750]}},
          :kerberos_master=>{:aliases=>[], :clients=>[], :description=>"Kerberos authentication", :uses=>{:udp=>[751], :tcp=>[751]}},
          :passwd_server=>{:aliases=>[], :clients=>[], :description=>"Kerberos passwd server", :uses=>{:udp=>[752]}},
          :krb_prop=>{:aliases=>["krb5_prop", "hprop"], :clients=>[], :description=>"Kerberos slave propagation", :uses=>{:tcp=>[754]}},
          :krbupdate=>{:aliases=>["kreg"], :clients=>[], :description=>"Kerberos registration", :uses=>{:tcp=>[760]}},
          :swat=>{:aliases=>[], :clients=>[], :description=>"swat", :uses=>{:tcp=>[901]}},
          :kpop=>{:aliases=>[], :clients=>[], :description=>"Pop with Kerberos", :uses=>{:tcp=>[1109]}},
          :knetd=>{:aliases=>[], :clients=>[], :description=>"Kerberos de-multiplexor", :uses=>{:tcp=>[2053]}},
          :"zephyr-srv"=>{:aliases=>[], :clients=>[], :description=>"Zephyr server", :uses=>{:udp=>[2102]}},
          :"zephyr-clt"=>{:aliases=>[], :clients=>[], :description=>"Zephyr serv-hm connection", :uses=>{:udp=>[2103]}},
          :"zephyr-hm"=>{:aliases=>[], :clients=>[], :description=>"Zephyr hostmanager", :uses=>{:udp=>[2104]}},
          :eklogin=>{:aliases=>[], :clients=>[], :description=>"Kerberos encrypted rlogin", :uses=>{:tcp=>[2105]}},
          :kx=>{:aliases=>[], :clients=>[], :description=>"X over Kerberos", :uses=>{:tcp=>[2111]}},
          :iprop=>{:aliases=>[], :clients=>[], :description=>"incremental propagation", :uses=>{:tcp=>[2121]}},
          :supfilesrv=>{:aliases=>[], :clients=>[], :description=>"SUP server", :uses=>{:tcp=>[871]}},
          :supfiledbg=>{:aliases=>[], :clients=>[], :description=>"SUP debugging", :uses=>{:tcp=>[1127]}},
          :linuxconf=>{:aliases=>[], :clients=>[], :description=>"LinuxConf", :uses=>{:tcp=>[98]}},
          :poppassd=>{:aliases=>[], :clients=>[], :description=>"Eudora", :uses=>{:tcp=>[106], :udp=>[106]}},
          :ssmtp=>{:aliases=>["smtps"], :clients=>[], :description=>"SMTP over SSL", :uses=>{:tcp=>[465]}},
          :moira_db=>{:aliases=>[], :clients=>[], :description=>"Moira database", :uses=>{:tcp=>[775]}},
          :moira_update=>{:aliases=>[], :clients=>[], :description=>"Moira update protocol", :uses=>{:tcp=>[777]}},
          :moira_ureg=>{:aliases=>[], :clients=>[], :description=>"Moira user registration", :uses=>{:udp=>[779]}},
          :spamd=>{:aliases=>[], :clients=>[], :description=>"spamassassin daemon", :uses=>{:tcp=>[783]}},
          :omirr=>{:aliases=>["omirrd"], :clients=>[], :description=>"online mirror", :uses=>{:tcp=>[808], :udp=>[808]}},
          :customs=>{:aliases=>[], :clients=>[], :description=>"pmake customs server", :uses=>{:tcp=>[1001], :udp=>[1001]}},
          :skkserv=>{:aliases=>[], :clients=>[], :description=>"skk jisho server port", :uses=>{:tcp=>[1178]}},
          :predict=>{:aliases=>[], :clients=>[], :description=>"predict -- satellite tracking", :uses=>{:udp=>[1210]}},
          :rmtcfg=>{:aliases=>[], :clients=>[], :description=>"Gracilis Packeten remote config server", :uses=>{:tcp=>[1236]}},
          :wipld=>{:aliases=>[], :clients=>[], :description=>"Wipl network monitor", :uses=>{:tcp=>[1300]}},
          :xtel=>{:aliases=>[], :clients=>[], :description=>"french minitel", :uses=>{:tcp=>[1313]}},
          :xtelw=>{:aliases=>[], :clients=>[], :description=>"french minitel", :uses=>{:tcp=>[1314]}},
          :support=>{:aliases=>[], :clients=>[], :description=>"GNATS", :uses=>{:tcp=>[1529]}},
          :cfinger=>{:aliases=>[], :clients=>[], :description=>"GNU Finger", :uses=>{:tcp=>[2003]}},
          :frox=>{:aliases=>[], :clients=>[], :description=>"frox: caching ftp proxy", :uses=>{:tcp=>[2121]}},
          :ninstall=>{:aliases=>[], :clients=>[], :description=>"ninstall service", :uses=>{:tcp=>[2150], :udp=>[2150]}},
          :zebrasrv=>{:aliases=>[], :clients=>[], :description=>"zebra service", :uses=>{:tcp=>[2600]}},
          :zebra=>{:aliases=>[], :clients=>[], :description=>"zebra vty", :uses=>{:tcp=>[2601]}},
          :ripd=>{:aliases=>[], :clients=>[], :description=>"ripd vty (zebra)", :uses=>{:tcp=>[2602]}},
          :ripngd=>{:aliases=>[], :clients=>[], :description=>"ripngd vty (zebra)", :uses=>{:tcp=>[2603]}},
          :ospfd=>{:aliases=>[], :clients=>[], :description=>"ospfd vty (zebra)", :uses=>{:tcp=>[2604]}},
          :bgpd=>{:aliases=>[], :clients=>[], :description=>"bgpd vty (zebra)", :uses=>{:tcp=>[2605]}},
          :ospf6d=>{:aliases=>[], :clients=>[], :description=>"ospf6d vty (zebra)", :uses=>{:tcp=>[2606]}},
          :ospfapi=>{:aliases=>[], :clients=>[], :description=>"OSPF-API", :uses=>{:tcp=>[2607]}},
          :isisd=>{:aliases=>[], :clients=>[], :description=>"ISISd vty (zebra)", :uses=>{:tcp=>[2608]}},
          :afbackup=>{:aliases=>[], :clients=>[], :description=>"Afbackup system", :uses=>{:tcp=>[2988], :udp=>[2988]}},
          :afmbackup=>{:aliases=>[], :clients=>[], :description=>"Afmbackup system", :uses=>{:tcp=>[2989], :udp=>[2989]}},
          :xtell=>{:aliases=>[], :clients=>[], :description=>"xtell server", :uses=>{:tcp=>[4224]}},
          :fax=>{:aliases=>[], :clients=>[], :description=>"FAX transmission service (old)", :uses=>{:tcp=>[4557]}},
          :hylafax=>{:aliases=>[], :clients=>[], :description=>"HylaFAX client-server protocol (new)", :uses=>{:tcp=>[4559]}},
          :distmp3=>{:aliases=>[], :clients=>[], :description=>"distmp3host daemon", :uses=>{:tcp=>[4600]}},
          :munin=>{:aliases=>["lrrd"], :clients=>[], :description=>"Munin", :uses=>{:tcp=>[4949]}},
          :"enbd-cstatd"=>{:aliases=>[], :clients=>[], :description=>"ENBD client statd", :uses=>{:tcp=>[5051]}},
          :"enbd-sstatd"=>{:aliases=>[], :clients=>[], :description=>"ENBD server statd", :uses=>{:tcp=>[5052]}},
          :pcrd=>{:aliases=>[], :clients=>[], :description=>"PCR-1000 Daemon", :uses=>{:tcp=>[5151]}},
          :noclog=>{:aliases=>[], :clients=>[], :description=>"noclogd with TCP (nocol)", :uses=>{:tcp=>[5354], :udp=>[5354]}},
          :hostmon=>{:aliases=>[], :clients=>[], :description=>"hostmon uses TCP (nocol)", :uses=>{:tcp=>[5355], :udp=>[5355]}},
          :rplay=>{:aliases=>[], :clients=>[], :description=>"RPlay audio service", :uses=>{:udp=>[5555]}},
          :nrpe=>{:aliases=>[], :clients=>[], :description=>"Nagios Remote Plugin Executor", :uses=>{:tcp=>[5666]}},
          :nsca=>{:aliases=>[], :clients=>[], :description=>"Nagios Agent - NSCA", :uses=>{:tcp=>[5667]}},
          :mrtd=>{:aliases=>[], :clients=>[], :description=>"MRT Routing Daemon", :uses=>{:tcp=>[5674]}},
          :bgpsim=>{:aliases=>[], :clients=>[], :description=>"MRT Routing Simulator", :uses=>{:tcp=>[5675]}},
          :canna=>{:aliases=>[], :clients=>[], :description=>"cannaserver", :uses=>{:tcp=>[5680]}},
          :"sane-port"=>{:aliases=>[], :clients=>[], :description=>"SANE network scanner daemon", :uses=>{:tcp=>[6566]}},
          :ircd=>{:aliases=>[], :clients=>[], :description=>"Internet Relay Chat", :uses=>{:tcp=>[6667]}},
          :"zope-ftp"=>{:aliases=>[], :clients=>[], :description=>"zope management by ftp", :uses=>{:tcp=>[8021]}},
          :tproxy=>{:aliases=>[], :clients=>[], :description=>"Transparent Proxy", :uses=>{:tcp=>[8081]}},
          :omniorb=>{:aliases=>[], :clients=>[], :description=>"OmniORB", :uses=>{:tcp=>[8088], :udp=>[8088]}},
          :xinetd=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[9098]}},
          :mandelspawn=>{:aliases=>[], :clients=>[], :description=>"network mandelbrot", :uses=>{:udp=>[9359]}},
          :git=>{:aliases=>[], :clients=>[], :description=>"Git Version Control System", :uses=>{:tcp=>[9418]}},
          :zope=>{:aliases=>[], :clients=>[], :description=>"zope server", :uses=>{:tcp=>[9673]}},
          :webmin=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:tcp=>[10000]}},
          :kamanda=>{:aliases=>[], :clients=>[], :description=>"amanda backup services (Kerberos)", :uses=>{:tcp=>[10081], :udp=>[10081]}},
          :amandaidx=>{:aliases=>[], :clients=>[], :description=>"amanda backup services", :uses=>{:tcp=>[10082]}},
          :amidxtape=>{:aliases=>[], :clients=>[], :description=>"amanda backup services", :uses=>{:tcp=>[10083]}},
          :smsqp=>{:aliases=>[], :clients=>[], :description=>"Alamin SMS gateway", :uses=>{:tcp=>[11201], :udp=>[11201]}},
          :xpilot=>{:aliases=>[], :clients=>[], :description=>"XPilot Contact Port", :uses=>{:tcp=>[15345], :udp=>[15345]}},
          :"sgi-cmsd"=>{:aliases=>[], :clients=>[], :description=>"Cluster membership services daemon", :uses=>{:udp=>[17001]}},
          :"sgi-crsd"=>{:aliases=>[], :clients=>[], :description=>"", :uses=>{:udp=>[17002]}},
          :"sgi-gcd"=>{:aliases=>[], :clients=>[], :description=>"SGI Group membership daemon", :uses=>{:udp=>[17003]}},
          :"sgi-cad"=>{:aliases=>[], :clients=>[], :description=>"Cluster Admin daemon", :uses=>{:tcp=>[17004]}},
          :isdnlog=>{:aliases=>[], :clients=>[], :description=>"isdn logging system", :uses=>{:tcp=>[20011], :udp=>[20011]}},
          :vboxd=>{:aliases=>[], :clients=>[], :description=>"voice box system", :uses=>{:tcp=>[20012], :udp=>[20012]}},
          :binkp=>{:aliases=>[], :clients=>[], :description=>"binkp fidonet protocol", :uses=>{:tcp=>[24554]}},
          :asp=>{:aliases=>[], :clients=>[], :description=>"Address Search Protocol", :uses=>{:tcp=>[27374], :udp=>[27374]}},
          :csync2=>{:aliases=>[], :clients=>[], :description=>"cluster synchronization tool", :uses=>{:tcp=>[30865]}},
          :dircproxy=>{:aliases=>[], :clients=>[], :description=>"Detachable IRC Proxy", :uses=>{:tcp=>[57000]}},
          :tfido=>{:aliases=>[], :clients=>[], :description=>"fidonet EMSI over telnet", :uses=>{:tcp=>[60177]}},
          :fido=>{:aliases=>[], :clients=>[], :description=>"fidonet EMSI over TCP", :uses=>{:tcp=>[60179]}}
        }
        #
        #
        # ### end of SYSTEM detail initialization
      end
      #
      def gxg_root()
        @thread_safety.synchronize { @details[:gxg_root].to_s }
      end
      #
      def gxg_root=(the_path=nil)
        if the_path.is_a?(::String)
          @thread_safety.synchronize { @details[:gxg_root] = the_path }
        end
      end
      #
      def server_paths()
        result = {}
        # Define Server directories
        gxg_root_dir = ::GxG::SYSTEM.gxg_root()
        public_dir = File.expand_path("./Public",gxg_root_dir)
        services_dir = File.expand_path("./Services",gxg_root_dir)
        app_dir = File.expand_path("./Applications",gxg_root_dir)
        system_dir = File.expand_path("./System",gxg_root_dir)
        sys_config_dir = "#{system_dir}/Configuration"
        sys_db_dir = "#{system_dir}/Databases"
        sys_ext_dir = "#{system_dir}/Extensions"
        sys_gem_dir = "#{system_dir}/Gems"
        sys_lib_dir = "#{system_dir}/Libraries"
        tmp_dir = "#{system_dir}/Temporary"
        log_dir = "#{system_dir}/Logs"
        result = {:root => gxg_root_dir, :system => system_dir, :services => services_dir, :temporary => tmp_dir, :logs => log_dir, :applications => app_dir, :users => nil, :public => public_dir,  :configuration => sys_config_dir, :databases => sys_db_dir, :extensions => sys_ext_dir, :gems => sys_gem_dir, :libraries => sys_lib_dir}
        result
      end
      #
      def application_paths(application_name=nil)
        result = {}
        if application_name.is_a?(::String)
          result = {:file_system => "/", :user => ::ENV['HOME']}
          case GxG::SYSTEM.platform[:platform]
          when :windows
            result[:file_system] = (ENV["HOMEDRIVE"] + "/")
            result[:user] = File.join(ENV["HOME"].split("\\"))
            result[:shared] = File.join(ENV["PUBLIC"].split("\\"))
            result[:temporary] = File.join(ENV["TEMP"].split("\\"))
            result[:application_data] = (File.join(ENV["LOCALAPPDATA"].split("\\")) + "/GxG/" + application_name)
            result[:preferences] = (result[:application_data] + "/Preferences")
            result[:logs] = (result[:application_data] + "/Logs")
            result[:projects] = (result[:user] + "/GxG")
            result[:fonts] = (result[:projects] + "/Fonts")
            result[:desktop] = (result[:user] + "/Desktop")
            result[:documents] = (result[:user] + "/Documents")
            result[:downloads] = (result[:user] + "/Downloads")
            result[:audio] = (result[:user] + "/Music")
            result[:images] = (result[:user] + "/Pictures")
            result[:video] = (result[:user] + "/Videos")
          when :linux
            case GxG::SYSTEM.environment[:environment]
            when :ubuntu
              result[:user] = ENV['HOME']
              result[:shared] = "/tmp"
              result[:temporary] = "/tmp"
              result[:application_data] = (result[:user] + "/.local/share/GxG/" + application_name)
              result[:preferences] = (result[:user] + "/.config/GxG/" + application_name)
              result[:logs] = (result[:application_data] + "/Logs")
              result[:projects] = (result[:user] + "/GxG")
              result[:fonts] = (result[:user] + "/.fonts")
              result[:desktop] = (result[:user] + "/Desktop")
              result[:documents] = (result[:user] + "/Documents")
              result[:downloads] = (result[:user] + "/Downloads")
              result[:audio] = (result[:user] + "/Music")
              result[:images] = (result[:user] + "/Pictures")
              result[:video] = (result[:user] + "/Videos")
            when :redhat
            end
          when :darwin
            case GxG::SYSTEM.environment[:environment]
            when :darwin
            when :macos
              result[:user] = ENV['HOME']
              result[:shared] = "/Users/Shared"
              result[:temporary] = "/tmp"
              result[:application_data] = (result[:user] + "/Library/Application Support/GxG/" + application_name)
              result[:preferences] = (result[:user] + "/Library/Preferences/GxG/" + application_name)
              result[:logs] = (result[:user] + "/Library/Logs/GxG/" + application_name)
              result[:projects] = (result[:user] + "/GxG")
              result[:fonts] = (result[:user] + "/Library/Fonts")
              result[:desktop] = (result[:user] + "/Desktop")
              result[:documents] = (result[:user] + "/Documents")
              result[:downloads] = (result[:user] + "/Downloads")
              result[:audio] = (result[:user] + "/Music")
              result[:images] = (result[:user] + "/Pictures")
              result[:video] = (result[:user] + "/Movies")
            end
          end
        end
        result
      end
      #
      def gxg_cpu_add(cpu_record=nil)
        # Review : part of a monkey-patch solution to extremely long data-fetch times for using wmic for cpu data
        if cpu_record.is_a?(::Hash)
          @thread_safety.synchronize { @details[:processors] << cpu_record }
        end
      end
      #
      def detail_mapping()
        # Maps universal system data keys to @details hash paths (cached data from system)
        # TCP tuning: http://www.psc.edu/networking/projects/tcptune/#tutorial
        #
        result = []
        #
        @thread_safety.synchronize {
          if @details[:network][:protocols][:ipv4]
            result << {:key => "net.ipv4.tcp.autotune", :path => "/:network/:protocols/:ipv4/:settings/:tcp/:autotune"}
            result << {:key => "net.ipv4.tcp.timestamps", :path => "/:network/:protocols/:ipv4/:settings/:tcp/:timestamps"}
            result << {:key => "net.ipv4.tcp.window_scaling", :path => "/:network/:protocols/:ipv4/:settings/:tcp/:window_scaling"}
            result << {:key => "net.ipv4.tcp.selective_ack", :path => "/:network/:protocols/:ipv4/:settings/:tcp/:selective_ack"}
          end
        }
        result << {:key => "net.ipv4.tcp.read", :path => "/:memory_limits/:buffers/:ipv4/:tcp/:read"}
        result << {:key => "net.ipv4.tcp.write", :path => "/:memory_limits/:buffers/:ipv4/:tcp/:write"}
        result << {:key => "net.socket.ipc.read", :path => "/:memory_limits/:buffers/:socket/:ipc/:read"}
        result << {:key => "net.socket.ipc.write", :path => "/:memory_limits/:buffers/:socket/:ipc/:write"}
        result << {:key => "net.ipv4.udp.read", :path => "/:memory_limits/:buffers/:ipv4/:udp/:read"}
        result << {:key => "net.ipv4.udp.write", :path => "/:memory_limits/:buffers/:ipv4/:udp/:write"}
        result << {:key => "configuration.process.maximum_file_descriptors", :path => "/:platform_configuration/:process/:maximum_file_descriptors"}
        #
        result
      end
      private :detail_mapping
      #
      def system_data_keys(other_platform=nil)
        # Lists known techniques per-universal-key for gathering system data (not necessarily cached)
        # Linux getconf : http://publib.boulder.ibm.com/infocenter/iseries/v7r1m0/index.jsp?topic=%2Frzahz%2Frzahzgetconf.htm
        # Linux configuration files : http://www.ibm.com/developerworks/linux/library/l-config/index.html
        #
        result = []
        data = []
        #
        data << {:key => "net.ipv4.tcp.autotune", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_moderate_rcvbuf", :format => :zerofalse}}
        # RFC1323 extensions support
        data << {:key => "net.ipv4.tcp.timestamps", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_timestamps", :format => :zerofalse}}
        data << {:key => "net.ipv4.tcp.window_scaling", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_window_scaling", :format => :zerofalse}}
        # RFC2108 extension support
        data << {:key => "net.ipv4.tcp.selective_ack", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_sack", :format => :zerofalse}}
        data << {:key => "net.ipv4.tcp.read", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_rmem", :format => :valid_with_initial}}
        data << {:key => "net.ipv4.tcp.write", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_wmem", :format => :valid_with_initial}}
        # net.ipv4.tcp.(rmem/wmem) sets the buffer sizing for unix domains and non-tcp sockets
        data << {:key => "net.socket.ipc.read", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_rmem", :format => :valid_with_initial}}
        data << {:key => "net.socket.ipc.write", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.tcp_wmem", :format => :valid_with_initial}}
        # LATER: confirm udp read and write mem is symmetric.
        data << {:key => "net.ipv4.udp.read", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.udp_mem", :format => :valid_with_initial}}
        data << {:key => "net.ipv4.udp.write", :platforms => [:linux], :operation => {:sysctl => "net.ipv4.udp_mem", :format => :valid_with_initial}}
        # TODO: Research sysctl keys for Path MTU Discovery (RFC1191, RFC1981, RFC4821)
        # System-wide maximum threads available on this system: (per-process on Windows)
        data << {:key => "kernel.threads_max", :platforms => [:windows], :operation => {:literal => "2000", :format => :to_int}}
        data << {:key => "kernel.threads_max", :platforms => [:linux], :operation => {:sysctl => "kernel.threads-max", :format => :to_int}}
        # Review : FORNOW using kern.maxproc but that's not right --> research actual method.
        data << {:key => "kernel.threads_max", :platforms => [:bsd, :darwin], :operation => {:sysctl => "kern.maxproc", :format => :to_int}}
        # #
        # getconf variable meanings:
        # Attribution: http://www.lainoox.com/system-wide-config-getconf/
        #ARG_MAX 	Maximum length, in bytes, of the arguments for one of the exec subroutines, including environment data.
        #CHAR_BIT 	Number of bits in a type character.
        #CHAR_MAX 	Maximum value of a type character.
        #CHAR_MIN 	Minimum value of a type character.
        #CHILD_MAX 	Maximum number of simultaneous processes for each real user ID.
        #CLK_TCK 	Number of clock ticks per second returned by the time subroutine.
        #INT_MAX 	Maximum value of a type int.
        #INT_MIN 	Minimum value of a type int.
        #LONG_BIT 	Number of bits in a type long int.
        #LONG_MAX 	Maximum value of a type long int.
        #LONG_MIN 	Minimum value of a type long int.
        #MB_LEN_MAX 	Maximum number of bytes in a character for any supported locale.
        #NGROUPS_MAX 	Maximum number of simultaneous supplementary group IDs for each process.
        #NL_ARGMAX 	Maximum value of digit in calls to the printf and scanf subroutines.
        #NL_LANGMAX 	Maximum number of bytes in a LANG name.
        #NL_MSGMAX 	Maximum message number.
        #NL_NMAX 	Maximum number of bytes in an N-to-1 collation mapping.
        #NL_SETMAX 	Maximum set number.
        #NL_TEXTMAX 	Maximum number of bytes in a message string.
        #NZERO 	Default process priority.
        #OPEN_MAX 	Maximum number of files that one process can have open at one time.
        #SCHAR_MAX 	Maximum value of a type signed char.
        #SCHAR_MIN 	Minimum value of a type signed char.
        #SHRT_MAX 	Maximum value of a type short.
        #SHRT_MIN 	Minimum value of a type short.
        #SSIZE_MAX 	Maximum value of an object of type ssize_t.
        #TZNAME_MAX 	Maximum number of bytes supported for the name of a time zone (not the length of the TZ environment variable).
        #UCHAR_MAX 	Maximum value of a type unsigned char.
        #UINT_MAX 	Maximum value of a type unsigned int.
        #ULONG_MAX 	Maximum value of a type unsigned long int.
        #USHRT_MAX 	Maximum value of a type unsigned short int.
        #WORD_BIT 	Number of bits in a word or type int.
        data << {:key => "configuration.process.maximum_file_descriptors", :platforms => [:linux], :operation => {:getconf => "OPEN_MAX", :format => :to_int}}
        # TODO: Research maximum limit under epoll/kqueue:  See: http://news.ycombinator.com/item?id=1740823
        # Also : http://stackoverflow.com/questions/651665/how-many-socket-connections-possible
        # inventory the various platform variables that affect what threshold of max_socket_count a given system would end up with.
        # See: http://www.metabrew.com/article/a-million-user-comet-application-with-mochiweb-part-3
        # Sysctl tuning: http://www.metabrew.com/article/a-million-user-comet-application-with-mochiweb-part-1
        # LATER: develop a series of formulas for calculating approx. how many clients one can support under one 'cluster' controller (session manager).
        data.to_enum.each do |entry|
          if entry[:platforms].include?((other_platform || @details[:platform]))
            result << entry
          end
        end
        #
        result
      end
      private :system_data_keys
      #
      def get_system_data(keys=[])
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
        #
        reference = system_data_keys()
        #
        fetch_data = Proc.new do |the_key|
          data = nil
          reference.to_enum.each do |entry|
            if entry[:key] == the_key
              case entry[:operation][:format]
              when :zerofalse
                the_formatter = format_zerofalse
              when :to_int
                the_formatter = format_to_int
              when :to_float
                the_formatter = format_to_float
              when :valid_with_initial
                the_formatter = format_valid_with_initial
              end
              begin
                if entry[:operation][:sysctl]
                  data = sysctl_read.call(entry[:operation][:sysctl],the_formatter)
                else
                  if entry[:operation][:getconf]
                    data = getconf_read.call(entry[:operation][:getconf],the_formatter)
                  else
                    if entry[:operation][:literal]
                      data = the_formatter.call(entry[:operation][:literal])
                    end
                  end
                end
              rescue Exception
                #
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
                  @thread_safety.synchronize {
                    @details.set_at_path(specifier[:path],result[(specifier[:key])])
                  }
                end
              else
                # {ukey => hash_path}
                subkeys = specifier.keys
                subkeys.to_enum.each do |a_key|
                  result[(a_key)] = fetch_data.call(a_key)
                  @thread_safety.synchronize {
                    @details.set_at_path(specifier[(a_key)],result[(a_key)])
                  }
                end
              end
            end
          end
        end
        #
        result
      end
      private :get_system_data
      #
      def set_system_data(keys=[])
        # LATER: when you figure out system(sudo) authentication - use this for ops that require elevated privs to set system parameters.
        # Define a set of universal_keys that affect what other keys; upon setting any one, unique-list a set of keys to read back in w/ hash paths.
        result = nil
        if nil
          get_system_data(nil,nil)
          # compare hash value to the_value; return true if successful
        end
        result
      end
      private :set_system_data
      #
      def keys()
        result = []
        reference = detail_mapping()
        reference.to_enum.each do |mapping|
          result << mapping[:key]
        end
        result
      end
      #
      def [](the_path="")
        # Public interface for accessing system keyed values.
        # access cached or system-read values on /proc (sysctl-style) keys. (frankly missing from BSD, etc)
        result = nil
        reference = detail_mapping()
        #
        reference.to_enum.each do |mapping|
          if mapping[:key] == the_path
            @thread_safety.synchronize {
              result = @details.get_at_path(mapping[:path]).clone
            }
            break
          end
        end
        unless result
          # attempt to fetch the data from the system somehow.
          result = get_system_data(the_path)
          unless result.keys.size > 0
            result = nil
          end
        end
        #
        result
      end
      #
      def architecture()
        @thread_safety.synchronize {
          {:architecture => @details[:architecture], :processors => @details[:processors]}.clone
        }
      end
      #
      def platform()
        @thread_safety.synchronize {
          {:platform => @details[:platform], :version => @details[:platform_version], :configuration => @details[:platform_configuration]}.clone
        }
      end
      #
      def environment()
        @thread_safety.synchronize {
          {:environment => @details[:environment], :version => @details[:environment_version], :variant => @details[:environment_variant]}.clone
        }
      end
      #
      def engine()
        # ??? just info ??? GxG::Engine::profile()
        ::GxG::Engine
      end
      #
      def network()
        @thread_safety.synchronize {
          @details[:network].clone
        }
      end
      #
      def load_average()
        # this or cpuload ??
        this_platform = @details[:platform]
        case this_platform
        when :linux
          result = (`uptime`.split(":")[-1].chomp.split(","))
          result.to_enum(:each_index).each do |indexer|
            result[(indexer)] = result[(indexer)].to_f
          end
        else
          result = []
        end
        result
      end
      #
      def cpuload
        # this or load_average ??
        average = Sys::CPU.load_avg
        { :minute1 => average[0], :minute5 => average[1], :minute15 => average[2] }
      end
      #
      def valid_modes()
        result = {}
        result.merge(GxG::IO::IO::valid_modes())
        @thread_safety.synchronize {
          result.merge(@valid_modes)
        }
        result
      end
      def memory_limits()
        # See: http://linux-mm.org/LinuxMM
        # http://linux.die.net/man/2/mlock
        # https://answers.launchpad.net/graphite/+question/191807
        #
        @thread_safety.synchronize {
          @details[:memory_limits].clone
        }
      end
      def maximum_buffer_size()
        self.memory_limits()[:buffers]
      end
      #
      def memory()
        result = {}
        this_platform = nil
        @thread_safety.synchronize { this_platform = @details[:platform] }
        case this_platform
          # TODO: GxG::SYSTEM.memory : research free mem discovery for Winderz and BSD
        when :windows
          # No known way to get this info. MEM is dosbox only style memory counting. :P
          # Might have to bind to a C or C++ lib for this kind of data (PITA)
          # FORNOW: just pretend upper theoretical limit on a process is all you have (sucks)
          # mem_limit = ::GxG::SYSTEM.memory_limits()[:process].max
          #           Total Physical Memory:     8,192 MB
          # Available Physical Memory: 5,053 MB
          # Virtual Memory: Max Size:  9,472 MB
          # Virtual Memory: Available: 4,932 MB
          # Virtual Memory: In Use:    4,540 MB
          raw_system_info = `systeminfo /FO LIST`
          data = {:mem_limit => nil, :mem_free => nil, :vmem_limit => nil, :vmem_used => nil, :vmem_free => nil}
          raw_system_info.each_line do |the_line|
            if the_line.include?("Total Physical Memory")
              data[:mem_limit] = the_line.gsub(",","").numeric_values()[:byte]
            end
            if the_line.include?("Available Physical Memory")
              data[:mem_free] = the_line.gsub(",","").numeric_values()[:byte]
            end
            if the_line.include?("Virtual Memory: Max Size")
              data[:vmem_limit] = the_line.gsub(",","").numeric_values()[:byte]
            end
            if the_line.include?("Virtual Memory: In Use")
              data[:vmem_used] = the_line.gsub(",","").numeric_values()[:byte]
            end
            if the_line.include?("Virtual Memory: Available")
              data[:vmem_free] = the_line.gsub(",","").numeric_values()[:byte]
            end
          end
          result[:actual] = {:total => data[:mem_limit].to_i, :used => (data[:mem_limit].to_i - data[:mem_free].to_i), :free => data[:mem_free].to_i, :shared => 0, :buffers => 0, :cached => 0}
          result[:buffers] = {:used => 0, :free => 0}
          result[:virtual] = {:total => data[:vmem_limit].to_i, :used => data[:vmem_used].to_i, :free => data[:vmem_free].to_i}
        when :bsd, :darwin, :macos
          # Inspired by: http://www.cyberciti.biz/faq/freebsd-command-to-get-ram-information/ by Ralf S. Engelschall
          # ported to Ruby:
          env = self.environment()
          case env[:environment]
          when :freebsd, :dragonfly, :pcbsd
            # TODO: GxG::SYSTEM.memory() : test under freebsd, dragonfly and pcbsd
            page_size = (`sysctl hw.pagesize`.to_s.split(":")[1].numeric_values()[:integer] || 0)
            mem_phys = (`sysctl hw.physmem`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_all = (`sysctl vm.stats.vm.v_page_count`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_wire = (`sysctl vm.stats.vm.v_wire_count`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_active = (`sysctl vm.stats.vm.v_active_count`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_inactive = (`sysctl vm.stats.vm.v_inactive_count`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_cache = (`sysctl vm.stats.vm.v_cache_count`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_free = (`sysctl vm.stats.vm.v_free_count`.to_s.split(":")[1].numeric_values()[:integer] || 0) * page_size
            mem_vm_total = (`sysctl vm.swap_total`.to_s.split(":")[1].numeric_values()[:integer] || 0)
            mem_vm_used = (`pstat -s`.to_s.split(" ")[2].numeric_values()[:integer] || 0)
          when :netbsd
            # TODO: GxG::SYSTEM.memory() : test under netbsd
            page_size = 0
            mem_phys = 0
            mem_all = 0
            mem_wire = 0
            mem_active = 0
            mem_inactive = 0
            mem_cache = 0
            mem_free = 0
            mem_vm_total = 0
            mem_vm_used = 0
            #
            raw_data = `vmstat -s`
            raw_data.to_enum(:each_line).each do |the_line|
              if the_line.include?("bytes per page")
                page_size = (the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0)
                break
              end
            end
            if page_size > 0
              raw_data.to_enum(:each_line).each do |the_line|
                if the_line.include?("pages managed")
                  mem_phys = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                  mem_all = mem_phys
                end
                if the_line.include?("pages wired")
                  mem_wire = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                end
                if the_line.include?("pages active")
                  mem_active = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                end
                if the_line.include?("pages inactive")
                  mem_inactive = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                end
                if the_line.include?("pages free")
                  mem_free = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                end
                if the_line.include?("swap pages in use")
                  mem_vm_used = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                end
                if the_line.split(" ")[(1..-1)].join(" ") == "swap pages"
                  mem_vm_total = ((the_line.split(" ")[0].to_s.numeric_values()[:integer] || 0) * page_size)
                end
              end
            end
          when :darwin, :macos
            # TODO: GxG::SYSTEM.memory() : test under darwin
            raw_data = `top -l 1`
            page_size = (`sysctl hw.pagesize`.to_s.split(":")[1].numeric_values()[:integer] || 0)
            # gives a byte-count, not a page count : hw.physmem
            mem_phys = (`sysctl hw.physmem`.to_s.split(":")[1].numeric_values()[:integer] || 0)
            mem_all = mem_phys
            # virtual memory usage:
            raw_data = (`sysctl vm.swapusage`.to_s.split(":")[1].split(" "))
            mem_vm_total = ((raw_data[5].to_s.numeric_values()[:float] || 0.0) * (1024**2)).to_i
            mem_vm_used = ((raw_data[2].to_s.numeric_values()[:float] || 0.0) * (1024**2)).to_i
            #SharedLibs: num =  146, resident = 22.9M code, 3.40M data, 8.36M LinkEdit
            #MemRegions: num =  7213, resident =  344M + 4.92M private, 22.5M shared
            #PhysMem:  59.1M wired,  285M active,  138M inactive,  483M used, 28.3M free
            raw_data.to_enum(:each_line).each do |the_line|
              if the_line.include?("PhysMem:")
                data = the_line.split(":")[1].to_s.split(",")
                data.to_enum(:each).each do |the_param|
                  numeric_string = the_param.split(" ")[0]
                  if numeric_string.include?(".")
                    numeric_string.gsub!("M","")
                  else
                    numeric_string.gsub!("M",".0")
                  end
                  case the_param.split(" ")[1]
                  when /wired/
                    mem_wire = ((numeric_string.numeric_values()[:float] || 0.0) * (1024**2)).to_i
                  when /active/
                    mem_active = ((numeric_string.numeric_values()[:float] || 0.0) * (1024**2)).to_i
                  when /inactive/
                    mem_inactive = ((numeric_string.numeric_values()[:float] || 0.0) * (1024**2)).to_i
                  when /free/
                    mem_free = ((numeric_string.numeric_values()[:float] || 0.0) * (1024**2)).to_i
                  end
                end
                break
              end
            end
          else
            # default BSD behavior ???  Seems like everyone does their own special thing.
          end
          # 
          chip_size = 1
          chip_guess = ((mem_phys / 8) - 1)
          while (chip_guess != 0)
            chip_guess >>= 1
            chip_size <<= 1
          end
          mem_hw = (((mem_phys / chip_size).to_i + 1) * chip_size)
          #
          mem_gap_vm = (mem_all - (mem_wire + mem_active + mem_inactive + mem_cache + mem_free))
          mem_gap_sys = (mem_phys - mem_all)
          mem_gap_hw = (mem_hw - mem_phys)
          #
          mem_available = (mem_inactive + mem_cache + mem_free)
          mem_used = (mem_hw - mem_available)
          # format result:
          result[:actual] = {:total => mem_hw, :used => mem_used, :free => mem_available, :shared => 0, :buffers => 0, :cached => 0}
          result[:buffers] = {:used => 0, :free => 0}
          result[:virtual] = {:total => mem_vm_total, :used => mem_vm_used, :free => (mem_vm_total - mem_vm_used)}
          #
        when :linux, :solaris
          # total       used       free     shared    buffers     cached
          raw_text = `free -b`
          raw_text.to_enum(:each_line).each do |text_line|
            if text_line.include?("Mem:")
              stats = text_line.split(" ")
              result[:actual] = {:total => stats[1].to_i, :used => stats[2].to_i, :free => stats[3].to_i, :shared => stats[4].to_i, :buffers => stats[5].to_i, :cached => stats[6].to_i}
            end
            if text_line.include?("-/+ buffers/cache:")
              stats = text_line.split(" ")
              result[:buffers] = {:used => stats[2].to_i, :free => stats[3].to_i}
            end
            if text_line.include?("Swap:")
              stats = text_line.split(" ")
              result[:virtual] = {:total => stats[1].to_i, :used => stats[2].to_i, :free => stats[3].to_i}
            end
          end
        end
        result.process! do |entry,selector,container|
          if entry.is_a?(::String)
            item = entry.numeric_values()
            if item.is_a?(::Hash)
              if item[:integer]
                container[(selector)] = item[:integer].to_i
              end
              if item[:float]
                container[(selector)] = item[:float].to_f
              end
            end
            if item.is_a?(::Array)
              item.each do |the_data|
                if the_data.is_a?(::Hash)
                  if the_data[:integer]
                    container[(selector)] = the_data[:integer].to_i
                  end
                  if the_data[:float]
                    container[(selector)] = the_data[:float].to_f
                  end
                end
                if the_data.is_a?(::Array)
                  data = the_data[0]
                  if data.is_a?(::Hash)
                    if data[:integer]
                      container[(selector)] = data[:integer].to_i
                    end
                    if data[:float]
                      container[(selector)] = data[:float].to_f
                    end
                    break
                  end
                end
              end
            end
          end
          nil
        end
        result[:total] = {:total => (result[:actual][:total].to_i + result[:virtual][:total].to_i), :used => (result[:actual][:used].to_i + result[:virtual][:used].to_i), :free => (result[:actual][:free].to_i + result[:virtual][:free].to_i)}
        result
      end
      #
      def processes(params={})
        results = []
        columns = [:cmdline, :cwd, :environ, :exe, :fd, :root, :pid, :comm, :state, :ppid, :pgrp, :session, :tty_nr, :tpgid,
          :flags, :minflt, :cminflt, :majflt, :cmajflt, :utime, :stime, :cutime, :cstime, :priority, :nice, :itrealvalue, :starttime,
          :vsize, :rss, :rlim, :startcode, :endcode, :startstack, :kstkesp, :kstkeip, :signal, :blocked, :sigignore, :sigcatch, :wchan,
          :nswap, :cnswap, :exit_signal, :processor, :rt_priority, :policy, :name, :uid, :euid, :gid, :egid, :pctcpu, :pctmem]
        include_columns = []
        if params[:columns].respond_to?(:each)
          params[:columns].to_enum.each do |entry|
            if columns.include?(entry.to_s.to_sym)
              include_columns << entry.to_s.to_sym
            end
          end
        else
          include_columns = columns
        end
        params.delete(:columns)
        #
        search_for = {}
        if params.respond_to?(:each_pair)
          params.each_pair do |key,entry|
            if columns.include?(key.to_s.to_sym)
              search_for[(key.to_s.to_sym)] = entry
            end
          end
        end
        #
        if (params[:pid])
          raw_data = (Sys::ProcTable.ps(params[:pid]) || [])
        else
          raw_data = (Sys::ProcTable.ps() || [])
        end
        raw_data.to_enum.each do |entry|
          new_entry = {}
          process = true
          if search_for.keys.size > 0
            search_for.each_pair do |search_key,search_value|
              unless (entry[(search_key)] == search_value)
                process = false
              end
            end
          end
          if process
            entry.each_pair do |key,item|
              if include_columns.include?(key.to_s.to_sym)
                new_entry[(key.to_sym)] = item
              end
            end
          end
          if new_entry.keys.size > 0
            results << new_entry
          end
        end
        #
        results
      end
      #
      def current_user()
        ::ENV["USER"]
      end
      #
      def network_status()
        # LATER: find out how to get the PID for AF_UNIX output of bsd-netstat -f unix
        # goal: lsof given a path, find the PID associated
        # lsof -Rt -t path (have to have read permissions)
        # OK, I give up (F-U bsd guys for not having a PID field in netstat unix output :P )
        # no unix socket info until I can figure a hooley-hoop set to jump through on this -- F'n Dorks!
        data = []
        local_data = []
        case ::GxG::SYSTEM.platform()[:platform]
        when :bsd
          predata = []
          raw_data = `netstat -an`
          raw_data.to_enum(:each_line).each do |the_line|
            ["tcp4 ", "tcp6 ", "udp4 ", "udp6 "].to_enum(:each).each do |entry|
              if the_line.include?(entry)
                predata << the_line.split(" ")
                break
              end
            end
            #
          end
          predata.to_enum(:each).each do |the_entry|
            new_entry = {}
            addressing = nil
            case the_entry[0].downcase
            when "tcp4", "tcp"
              addressing = {:family => ::Socket::AF_INET, :protocol => :tcp}
            when "tcp6"
              addressing = {:family => ::Socket::AF_INET6, :protocol => :tcp6}
            when "udp4", "udp"
              addressing = {:family => ::Socket::AF_INET, :protocol => :udp}
            when "udp6"
              addressing = {:family => ::Socket::AF_INET6, :protocol => :udp6}
            end
            if addressing
              new_entry[:protocol] = addressing[:protocol]
              if addressing[:family] == ::Socket::AF_INET6
                chunks = the_entry[3].split(".")
                unless chunks[1] == "*"
                  chunks[1] = chunks[1].to_i
                end
              else
                if the_entry[3].include?("*")
                  chunks = the_entry[3].split(".")
                  if chunks[0] == "*"
                    chunks = ["0.0.0.0",(the_entry[3].split(".").last)]
                  else
                    chunks = [(the_entry[3].split(".")[0..3].join(".")),(the_entry[3].split(".")[4])]
                  end
                  unless chunks[1] == "*"
                    chunks[1] = chunks[1].to_i
                  end
                else
                  chunks = [(the_entry[3].split(".")[0..3].join(".")),(the_entry[3].split(".")[4].to_i)]
                end
              end
              # bug fix:
              if chunks[1] == "*"
                chunks[1] = 0
              end
              # ##
              if addressing[:protocol] == :udp || addressing[:protocol] == :udp6
                new_entry[:local_address] = Addrinfo.udp(chunks[0],chunks[1])
              else
                new_entry[:local_address] = Addrinfo.tcp(chunks[0],chunks[1])
              end
              #
              if addressing[:family] == ::Socket::AF_INET6
                chunks = the_entry[4].split(".")
                unless chunks[1] == "*"
                  chunks[1] = chunks[1].to_i
                end
              else
                if the_entry[4].include?("*")
                  chunks = the_entry[4].split(".")
                  if chunks[0] == "*"
                    chunks = ["0.0.0.0",(the_entry[4].split(".").last)]
                  else
                    chunks = [(the_entry[4].split(".")[0..3].join(".")),(the_entry[4].split(".")[4])]
                  end
                  unless chunks[1] == "*"
                    chunks[1] = chunks[1].to_i
                  end
                else
                  chunks = [(the_entry[4].split(".")[0..3].join(".")),(the_entry[4].split(".")[4].to_i)]
                end
              end
              # bug fix:
              if chunks[1] == "*"
                chunks[1] = 0
              end
              # ##
              if addressing[:protocol] == :udp || addressing[:protocol] == :udp6
                new_entry[:foreign_address] = Addrinfo.udp(chunks[0],chunks[1])
              else
                new_entry[:foreign_address] = Addrinfo.tcp(chunks[0],chunks[1])
              end
              #
              if the_entry[5].to_s.size > 0
                new_entry[:status] = the_entry[5].to_sym
              else
                new_entry[:status] = nil
              end
              #
              data << new_entry
            end
            #
          end
        when :linux
          predata = []
          raw_data = `netstat -an`
          raw_data.to_enum(:each_line).each do |the_line|
            ["tcp ", "tcp6 ", "udp ", "udp6 "].to_enum(:each).each do |entry|
              if the_line.include?(entry)
                predata << the_line.split(" ")
                break
              end
            end
            #
          end
          predata.to_enum(:each).each do |the_entry|
            the_error = nil
            new_entry = {}
            addressing = nil
            case the_entry[0].downcase
            when "tcp"
              addressing = {:family => ::Socket::AF_INET, :protocol => :tcp}
            when "tcp6"
              addressing = {:family => ::Socket::AF_INET6, :protocol => :tcp6}
            when "udp"
              addressing = {:family => ::Socket::AF_INET, :protocol => :udp}
            when "udp6"
              addressing = {:family => ::Socket::AF_INET6, :protocol => :udp6}
            end
            if addressing
              new_entry[:protocol] = addressing[:protocol]
              if addressing[:family] == ::Socket::AF_INET6
                chunks = the_entry[3].split(":")
                unless chunks[-1] == "*"
                  chunks[-1] = chunks[-1].to_i
                end
                chunks = [(chunks[0..-2]).join(":"),(chunks.last)]
              else
                # Odd bug work-around
                addr = the_entry[3].split(":")[0]
                port = the_entry[3].split(":")[1]
                unless port == "*"
                  port = port.to_i
                end
                chunks = [(addr.split(":")[0]),(port)]
              end
              # bug fix:
              if chunks[1] == "*"
                chunks[1] = 0
              end
              #
              begin
                if addressing[:protocol] == :udp || addressing[:protocol] == :udp6
                  new_entry[:local_address] = Addrinfo.udp(chunks[0],chunks[1])
                else
                  new_entry[:local_address] = Addrinfo.tcp(chunks[0],chunks[1])
                end
              rescue Exception => the_error
              end
              # ##
              if addressing[:family] == ::Socket::AF_INET6
                # IPV6
                chunks = the_entry[4].split(":")
                unless chunks[-1] == "*"
                  chunks[-1] = chunks[-1].to_i
                end
                chunks = [(chunks[0..-2]).join(":"),(chunks.last)]
              else
                # IPV4
                # Odd bug work-around
                addr = the_entry[4].split(":")[0]
                port = the_entry[4].split(":")[1]
                unless port == "*"
                  port = port.to_i
                end
                chunks = [(addr.split(":")[0]),(port)]
                # puts "Got: #{chunks.inspect}"
              end
              #              if chunks[1].is_a?(::String)
              #                if chunks[1].numeric_values(:integer)
              #                  chunks[1] = chunks[1].numeric_values(:integer)[:integer]
              #                end
              #              end
              # bug fix:
              if chunks[1] == "*"
                chunks[1] = 0
              end
              #
              begin
                if addressing[:protocol] == :udp || addressing[:protocol] == :udp6
                  new_entry[:foreign_address] = Addrinfo.udp(chunks[0],chunks[1])
                else
                  new_entry[:foreign_address] = Addrinfo.tcp(chunks[0],chunks[1])
                end
              rescue Exception => the_error
              end
              # ##
              if the_entry[5].to_s.size > 0
                new_entry[:status] = the_entry[5].to_sym
              else
                new_entry[:status] = nil
              end
              #
              unless the_error
                data << new_entry
              end
              #
            end
          end
          #
        when :windows
          predata = []
          raw_data = `netstat /a`
          raw_data.to_enum(:each_line).each do |the_line|
            ["TCP ", "UDP "].to_enum(:each).each do |entry|
              if the_line.include?(entry)
                item = the_line.split(" ")
                if item[0] == "TCP"
                  # ["tcp6", "0", "0", "::1:631", ":::*", "LISTEN"]
                  if item[1].include?("[") && item[1].include?("]")
                    item = ["tcp6", "0", "0", item[1], item[2], (item[3] || "")]
                  else
                    item = ["tcp", "0", "0", item[1], item[2], (item[3] || "")]
                  end
                end
                if item[0] == "UDP"
                  # ["udp", "0", "0", "224.0.0.251:5353", "0.0.0.0:*"]
                  if item[1].include?("[") && item[1].include?("]")
                    item = ["udp6", "0", "0", item[1], item[2]]
                  else
                    item = ["udp", "0", "0", item[1], item[2]]
                  end
                end
                predata << item
                break
              end
            end
            #
          end
          predata.to_enum(:each).each do |the_entry|
            the_error = nil
            new_entry = {}
            addressing = nil
            case the_entry[0].downcase
            when "tcp"
              addressing = {:family => ::Socket::AF_INET, :protocol => :tcp}
            when "tcp6"
              addressing = {:family => ::Socket::AF_INET6, :protocol => :tcp6}
            when "udp"
              addressing = {:family => ::Socket::AF_INET, :protocol => :udp}
            when "udp6"
              addressing = {:family => ::Socket::AF_INET6, :protocol => :udp6}
            end
            if addressing
              new_entry[:protocol] = addressing[:protocol]
              if addressing[:family] == ::Socket::AF_INET6
                chunks = the_entry[3].split(":")
                unless chunks[-1] == "*"
                  chunks[-1] = chunks[-1].to_i
                end
                chunks = [(chunks[0..-2]).join(":"),(chunks.last)]
              else
                # Odd bug work-around
                addr = the_entry[3].split(":")[0]
                port = the_entry[3].split(":")[1]
                unless port == "*"
                  port = port.to_i
                end
                chunks = [(addr.split(":")[0]),(port)]
              end
              # bug fix:
              if chunks[1] == "*"
                chunks[1] = 0
              end
              #
              begin
                if addressing[:protocol] == :udp || addressing[:protocol] == :udp6
                  new_entry[:local_address] = Addrinfo.udp(chunks[0],chunks[1])
                else
                  new_entry[:local_address] = Addrinfo.tcp(chunks[0],chunks[1])
                end
              rescue Exception => the_error
              end
              # ##
              if addressing[:family] == ::Socket::AF_INET6
                # IPV6
                chunks = the_entry[4].split(":")
                unless chunks[-1] == "*"
                  chunks[-1] = chunks[-1].to_i
                end
                chunks = [(chunks[0..-2]).join(":"),(chunks.last)]
              else
                # IPV4
                # Odd bug work-around
                addr = the_entry[4].split(":")[0]
                port = the_entry[4].split(":")[1]
                unless port == "*"
                  port = port.to_i
                end
                chunks = [(addr.split(":")[0]),(port)]
                # puts "Got: #{chunks.inspect}"
              end
              #              if chunks[1].is_a?(::String)
              #                if chunks[1].numeric_values(:integer)
              #                  chunks[1] = chunks[1].numeric_values(:integer)[:integer]
              #                end
              #              end
              # bug fix:
              if chunks[1] == "*"
                chunks[1] = 0
              end
              #
              begin
                if addressing[:protocol] == :udp || addressing[:protocol] == :udp6
                  new_entry[:foreign_address] = Addrinfo.udp(chunks[0],chunks[1])
                else
                  new_entry[:foreign_address] = Addrinfo.tcp(chunks[0],chunks[1])
                end
              rescue Exception => the_error
              end
              # ##
              if the_entry[5].to_s.size > 0
                new_entry[:status] = the_entry[5].to_sym
              else
                new_entry[:status] = nil
              end
              #
              unless the_error
                data << new_entry
              end
              #
            end
          end
        end
        {:internet => data, :local => local_data}
      end
      #
      def network_port_used?(the_port=0, the_address="0.0.0.0")
        if the_port.is_a?(::Addrinfo)
          the_address = the_port.ip_address()
          the_port = the_port.ip_port()
        end
        if the_address == "*" || the_address == nil
          the_address = "0.0.0.0"
        end
        unless the_address.is_a?(::String)
          raise ArgumentError, "address needs to be specified as a String, you provided #{the_address.class}"
        end
        if the_port == "*" || the_port == nil
          the_port = 0
        else
          if the_port.is_any?(::String, ::Numeric)
            the_port = the_port.to_i
          else
            raise ArgumentError, "port needs to be specified by an Integer or a String of an Integer or asterisk character, you provided #{the_port.class}"
          end
        end
        current = {:internet => [], :local => []}
        if the_port == 0
          found = true
        else
          found = false
          current = self.network_status()
        end
        #
        unless found
          current[:internet].to_enum(:each).each do |entry|
            if ((entry[:local_address].ip_address() == the_address && entry[:local_address].ip_port() == the_port) || (entry[:foreign_address].ip_address() == the_address && entry[:foreign_address].ip_port() == the_port))
              found = true
              break
            end
          end
        end
        unless found
          current[:local].to_enum(:each).each do |entry|
            # pending further Research and hefty work-arounds within self.network_status().
          end
        end
        #
        found
      end
      #
      def network_next_port(the_address="0.0.0.0", honor_conventions=true)
        # finds next available port on given interface, by default respecting common port usage conventions.
        if the_address.is_a?(::Addrinfo)
          the_address = the_address.ip_address()
        end
        if the_address == "*" || the_address == nil
          the_address = "0.0.0.0"
        end
        unless the_address.is_a?(::String)
          raise ArgumentError, "address needs to be specified as a String, you provided #{the_address.class}"
        end
        #
        if honor_conventions
          commonly_available = (49152..65535)
        else
          commonly_available = (1..65535)
        end
        #
        found = nil
        currently_used_ports = []
        current = self.network_status()
        current[:internet].to_enum(:each).each do |entry|
          if entry[:local_address].ip_address() == the_address
            currently_used_ports << entry[:local_address].ip_port()
          end
          if entry[:foreign_address].ip_address() == the_address
            currently_used_ports << entry[:foreign_address].ip_port()
          end
        end
        #
        commonly_available.to_enum(:each).each do |the_port|
          unless currently_used_ports.include?(the_port)
            found = the_port
            break
          end
        end
        #
        found
      end
      # ## Services general port usage reference data
      def service_ports()
        @details[:service_ports]
      end
      #
      def service_ports_register_alias(service,alias_name)
        result = false
        if @details[:service_ports][(service.to_sym)]
          if alias_name.to_s.size > 0
            unless @details[:service_ports][(service.to_sym)][:aliases].include?(alias_name.to_s)
              @details[:service_ports][(service.to_sym)][:aliases] << alias_name.to_s
              result = true
            end
          end
        end
        result
      end
      #
      def service_ports_remove_alias(service,alias_name)
        result = false
        if @details[:service_ports][(service.to_sym)]
          if @details[:service_ports][(service.to_sym)][:aliases].include?(alias_name.to_s)
            position = @details[:service_ports][(service.to_sym)][:aliases].index(alias_name.to_s)
            if position
              @details[:service_ports][(service.to_sym)][:aliases].delete_at(position)
              result = true
            end
          end
        end
        result
      end
      #
      def service_ports_register_client(service,client_scheme)
        result = false
        if @details[:service_ports][(service.to_sym)]
          if client_scheme.to_s.size > 0
            unless @details[:service_ports][(service.to_sym)][:clients].include?(client_scheme)
              @details[:service_ports][(service.to_sym)][:clients] << client_scheme.to_s
              result = true
            end
          end
        end
        result
      end
      #
      def service_ports_remove_client(service,client_scheme)
        result = false
        if @details[:service_ports][(service.to_sym)]
          if @details[:service_ports][(service.to_sym)][:clients].include?(client_scheme.to_s)
            position = @details[:service_ports][(service.to_sym)][:clients].index(client_scheme.to_s)
            if position
              @details[:service_ports][(service.to_sym)][:clients].delete_at(position)
              result = true
            end
          end
        end
        result
      end
      #
      def service_ports_usage_preference(service,preference=nil)
        result = false
        if @details[:service_ports][(service.to_sym)]
          if preference
            if [:tcp, :udp, :icmp, :snmp].include?(preference)
              if @details[:service_ports][(service.to_sym)][:uses][(preference)]
                @details[:service_ports][(service.to_sym)][:uses_preference] = preference
                result = true
              end
            end
          else
            @details[:service_ports][(service.to_sym)].delete(:uses_preference)
            result = true
          end
        end
        result
      end
      #
      def service_ports_register_usage(service,the_protocol,the_entry_port)
        # the_entry_port can be an Integer or a Range
        result = false
        if @details[:service_ports][(service.to_sym)]
          if @details[:service_ports][(service)][:uses].keys.include?(the_protocol)
            included = false
            @details[:service_ports][(service)][:uses][(the_protocol)].to_enum(:each).each do |the_result_port|
              if the_entry_port.is_a?(::Range)
                if the_result_port.is_a?(::Range)
                  if (the_result_port.include?(the_entry_port.first) && the_result_port.include?(the_entry_port.last))
                    included = true
                    break
                  end
                else
                  if the_entry_port.include?(the_result_port)
                    included = true
                    break
                  end
                end
              else
                if the_result_port.is_a?(::Range)
                  if the_result_port.include?(the_entry_port)
                    included = true
                    break
                  end
                else
                  if the_result_port == the_entry_port
                    included = true
                    break
                  end
                end
              end
            end
            unless included
              @details[:service_ports][(service)][:uses][(the_protocol)] << the_entry_port
            end
          else
            @details[:service_ports][(service)][:uses][(the_protocol)] = the_entry_port
          end
          result = true
          # 
        end
        result
      end
      #
      def service_ports_register(service, entry={})
        unless service.to_s.size > 0
          raise ArgumentError, "you must specify a service symbol (i.e. :www ...), you provided #{service.inspect}"
        end
        unless service.is_a?(::Symbol)
          service = service.to_s.to_sym
        end
        unless entry.is_a?(::Hash)
          entry = {}
        end
        unless entry[:aliases].is_a?(::Array)
          entry[:aliases] = []
        end
        unless entry[:clients].is_a?(::Array)
          entry[:clients] = []
        end
        unless entry[:description].is_a?(::String)
          entry[:description] = ""
        end
        unless entry[:uses].is_a?(::Hash)
          entry[:uses] = {}
        end
        result = false
        #
        if @details[:service_ports][(service)]
          entry[:aliases].to_enum(:each).each do |the_alias|
            unless @details[:service_ports][(service)][:aliases].include?(the_alias)
              @details[:service_ports][(service)][:aliases] << the_alias.to_s
            end
          end
          entry[:clients].to_enum(:each).each do |the_client|
            unless @details[:service_ports][(service)][:clients].include?(the_client.to_s)
              @details[:service_ports][(service)][:clients] << the_client.to_s
            end
          end
          entry[:uses].keys.to_enum(:each).each do |the_protocol|
            if @details[:service_ports][(service)][:uses].keys.include?(the_protocol)
              entry[:uses][(the_protocol)].to_enum(:each).each do |the_entry_port|
                included = false
                @details[:service_ports][(service)][:uses][(the_protocol)].each do |the_result_port|
                  if the_entry_port.is_a?(::Range)
                    if the_result_port.is_a?(::Range)
                      if (the_result_port.include?(the_entry_port.first) && the_result_port.include?(the_entry_port.last))
                        included = true
                        break
                      end
                    else
                      if the_entry_port.include?(the_result_port)
                        included = true
                        break
                      end
                    end
                  else
                    if the_result_port.is_a?(::Range)
                      if the_result_port.include?(the_entry_port)
                        included = true
                        break
                      end
                    else
                      if the_result_port == the_entry_port
                        included = true
                        break
                      end
                    end
                  end
                end
                unless included
                  @details[:service_ports][(service)][:uses][(the_protocol)] << the_entry_port
                end
              end
            else
              @details[:service_ports][(service)][:uses][(the_protocol)] = entry[:uses][(the_protocol)]
            end
            #
          end
          #
        else
          @details[:service_ports][(service.to_sym)] = entry
          result = true
        end
        #
        result
      end
      #
      def service_ports_search(criteria={})
        # search by client-scheme, and/or protocol and port-number/range.
        result = {}
        #
        @details[:service_ports].keys.to_enum(:each).each do |service|
          if (criteria[:scheme].to_s.to_sym == service || (@details[:service_ports][(service)][:aliases].include?(criteria[:scheme].to_s)) || (@details[:service_ports][(service)][:clients].include?(criteria[:scheme].to_s)))
            result[(service)] = @details[:service_ports][(service)].clone
          end
          unless result[(service)]
            the_protocol = criteria[:protocol]
            the_entry_port = criteria[:port]
            if (the_entry_port.is_any?(::Numeric, ::Range) && [:tcp, :udp, :icmp, :snmp].include?(the_protocol))
              if @details[:service_ports][(service)][:uses][(the_protocol)].is_a?(::Array)
                included = false
                @details[:service_ports][(service)][:uses][(the_protocol)].to_enum(:each).each do |the_result_port|
                  if the_entry_port.is_a?(::Range)
                    if the_result_port.is_a?(::Range)
                      if (the_result_port.include?(the_entry_port.first) && the_result_port.include?(the_entry_port.last))
                        included = true
                        break
                      end
                    else
                      if the_entry_port.include?(the_result_port)
                        included = true
                        break
                      end
                    end
                  else
                    if the_result_port.is_a?(::Range)
                      if the_result_port.include?(the_entry_port)
                        included = true
                        break
                      end
                    else
                      if the_result_port == the_entry_port
                        included = true
                        break
                      end
                    end
                  end
                end
                if included
                  result[(service)] = @details[:service_ports][(service)].clone
                end
                #
              end
            end
          end
        end
        #
        result
      end
      #
    end
    #
    class RemoteSystem
      #
    end
    #
  end # end-GxG::Entity
end
module GxG
  # setup constants, dispose of BOOTSTRAP data.
  if const_defined?(:BOOTSTRAP)
    SYSTEM = GxG::Entity::LocalSystem.new(BOOTSTRAP)
    SYSTEM.freeze
    remove_const(:BOOTSTRAP)
  end
end
#