#!/usr/bin/env ruby
require "rubygems"
# determine the arch, platform with version, and ruby implementation with version
# store this in GxG::BOOTSTRAP
module GxG
  if $GXGROOT
    details = {:gxg_root => $GXGROOT}
  else
    details = {}
  end
  details[:architecture] = RUBY_PLATFORM.split("-")[0].downcase
  details[:platform_version] = {}
  # ### determine platform and environment details
  if RUBY_PLATFORM == "java" || RUBY_PLATFORM == "java_64"
    platform = nil
    #
    unless platform
      raw_data = `uname -a`.downcase
      # Attempt to determine the distro and version
      [:freebsd, :openbsd, :netbsd, :dragonfly, :pcbsd].to_enum.each do |entry|
        if raw_data.include?(entry.to_s)
          platform = "bsd"
          break
        end
      end
    end
    #
    unless platform
      if `uname -a`.downcase.include?("darwin")
        platform = "darwin"
      end
    end
    #
    unless platform
      if `uname -a`.downcase.include?("aix")
        platform = "aix"
      end
    end
    #
    unless platform
      if `uname -a`.downcase.include?("solaris")
        platform = "solaris"
      end
    end
    #
    unless platform
      raw_data = `uname -a`.downcase
      # Attempt to determine the distro and version
      [:debian, :redhat, :gentoo, :ubuntu, :linuxmint, :angstrom, :gobolinux, :caldera,
        :suse, :mandrake, :fedora, :slackware, :united, :yellowdog, :sun, :puppy, :linux].to_enum.each do |entry|
        if raw_data.include?(entry.to_s)
          platform = "linux"
          break
        end
      end
    end
    #
    unless platform
      raw_data = `ver`.to_s.gsub!("[","").to_s.gsub!("]","").to_s.split(" ")
      if raw_data.include?("Windows")
        if ([ -1 ].pack('l!').length == 8)
          platform = "mswin64"
        else
          platform = "mswin32"
        end
      end
    end
    #
    unless platform
      platform = "unknown"
    end
    #
  else
    #
    unless platform
      raw_data = `uname -a`.downcase
      # Attempt to determine the distro and version
      [:debian, :redhat, :gentoo, :ubuntu, :linuxmint, :angstrom, :gobolinux, :caldera,
        :suse, :mandrake, :fedora, :slackware, :united, :yellowdog, :sun, :puppy, :linux].to_enum.each do |entry|
        if raw_data.include?(entry.to_s)
          platform = "linux"
          break
        end
      end
    end
    unless platform
      if RUBY_PLATFORM.split("-")[1] == "unknown"
        platform = RUBY_PLATFORM.split("-")[2]
      else
        if RUBY_ENGINE = "rbx"
          platform = RUBY_PLATFORM.split("-")[2]
        else
          platform = RUBY_PLATFORM.split("-")[1]
        end
      end
    end
  end
  case platform
  # SOMEDAY: look into the legal aspects of solutions published in the public space.
  # Attribution: http://www.unix.com/slackware/23652-determine-linux-version.html
  # and: http://www.novell.com/coolsolutions/feature/11251.html
  when /mswin32/
    details[:platform] = :windows
    details[:environment] = :mswin32
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /mswin64/
    details[:platform] = :windows
    details[:environment] = :mswin64
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /mingw32/
    details[:platform] = :windows
    details[:environment] = :mingw32
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /bccwin32/
    details[:platform] = :windows
    details[:environment] = :bccwin32
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /cygwin/
    details[:platform] = :windows
    # TODO: find out how deep cygwin goes (looks like a linux kernel??)
    # using the kernel version as the platform version
    details[:platform_version] = {:interpret => `uname -r`}
    details[:environment] = :cygwin
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /solaris|sunos/
    details[:platform] = :solaris
    details[:environment] = :solaris
    details[:environment_variant] = :standard
    details[:environment_version] = nil
    raw_text = `more /etc/release`
    unless raw_text.downcase.include?("no such file")
      details[:environment_version] = {:interpret => raw_text}
    end
  when /bsd/, /dragonfly/
    details[:platform] = :bsd
    # using the kernel version as the platform version
    details[:platform_version] = {:interpret => `uname -r`}
    details[:environment] = :bsd
    temp_env = `uname -a`.downcase
    # Attempt to determine the distro and version
    [:freebsd, :openbsd, :netbsd, :dragonfly, :pcbsd].to_enum.each do |entry|
      if temp_env.include?(entry.to_s)
        details[:environment] = entry
        break
      end
    end
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /darwin|mac os|macos/
    details[:platform] = :darwin
    # using the kernel version as the platform version
    details[:platform_version] = {:interpret => `uname -r`}
    if (::File.exists?("/System") && ::File.exists?("/Library") && ::File.exists?("/Volumes") && ::File.exists?("/Users"))
      details[:environment] = :macos
    else
      details[:environment] = :darwin
    end
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  when /linux/
    # ###
    details[:platform] = :linux
    # using the kernel version as the platform version
    details[:platform_version] = {:interpret => `uname -r`}
    details[:environment] = :linux
    temp_env = `uname -a`.downcase
    # Attempt to determine the distro and version
    [:debian, :redhat, :gentoo, :ubuntu, :linuxmint, :angstrom, :gobolinux, :caldera,
      :suse, :mandrake, :fedora, :slackware, :united, :yellowdog, :sun, :puppy].to_enum.each do |entry|
      if temp_env.include?(entry.to_s)
        details[:environment] = entry
        break
      end
    end
    details[:environment_variant] = :standard
    details[:environment_version] = nil
    raw_text = ""
    raw_version = {}
    case details[:environment]
    when :debian
      raw_text = `more /etc/debian_version`
      if raw_text.downcase.include?("no such file")
        raw_text = `more /etc/debian_release`
      end
    when :ubuntu
      raw_text = `more /etc/lsb-release | grep 'DISTRIB_RELEASE' | sed  -e 's#[^0-9.]##g'`
      # LATER: @determine :environment_variant : attempt to determine if :desktop or :server or :what?
      # unless raw_text.downcase.include?("no such file")
      #  temp_text = `more /etc/lsb-release | grep 'DISTRIB_CODENAME' | sed  -e 's#[^a-zA-Z=]##g'`.split("=")[1]
      #  details[:environment_variant] = temp_text.downcase.to_sym
      #end
    when :suse
      raw_text = `more /etc/SuSE-version | grep 'VERSION' | sed  -e 's#[^0-9.]##g'`
      if raw_text.downcase.include?("no such file")
        raw_text = `more /etc/SUSE-version | grep 'VERSION' | sed  -e 's#[^0-9.]##g'`
      end
    when :united
      raw_text = `more /etc/UnitedLinux-release`
    when :slackware
      raw_text = `more /etc/slackware-release`
      if raw_text.downcase.include?("no such file")
        raw_text = `more /etc/slackware-version`
      end
    when :redhat
      the_file = "redhat-release"
      temp_text = `more /etc/#{the_file}`
      if temp_text.downcase.include?("no such file")
        the_file = "redhat_version"
        temp_text = `more /etc/#{the_file}`
      end
      unless temp_text.downcase.include?("no such file")
        if temp_text.downcase.include?("scientific")
          details[:environment_variant] = :scientific
          raw_text = `more /etc/#{the_file} | sed -e 's#[^0-9.]##g' | cut -c1`
        else
          if temp_text.downcase.include?("enterprise")
            details[:environment_variant] = :enterprise
          else
            if temp_text.downcase.include?("cern")
              details[:environment_variant] = :cern
            end
          end
          raw_text = `more /etc/#{the_file} | sed -e 's#[^0-9.]##g' -e 's#7[0-2.]#73.#'`
        end
      end
      #
    else
      raw_text = `more /etc/#{details[:environment].to_s}-release`
    end
    #
    if (raw_text.downcase.include?("no such file") && raw_text.size == 0)
      if raw_version.keys.size > 0
        details[:environment_version] = raw_version
      end
    else
      details[:environment_version] = {:interpret => raw_text}.merge(raw_version)
    end
    #
  when /aix/
    details[:platform] = :aix
    details[:environment] = :aix
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  else
    # unknown (unsupported) platform
    details[:platform] = RUBY_PLATFORM.split("-")[1].to_s.downcase.to_sym
    details[:environment] = details[:platform]
    details[:environment_variant] = :standard
    details[:environment_version] = nil
  end
  # Arch detail determination:  Special thanks to Jari Bakken (Jarib) at https://github.com/jarib/childprocess/blob/master/lib/childprocess.rb
  if details[:architecture] == "java"
    # TODO: get arch via other means
    case details[:platform]
    when :windows
      if ([ -1 ].pack('l!').length == 8)
        details[:architecture] = "x86_64"
      else
        details[:architecture] = "i686"
      end
    when :linux, :bsd, :darwin, :aix, :solaris
      raw_data = `uname -a`.downcase
      [:i686, :i586, :i486, :i386, :amd64, :x86_64, :ppc, :powerpc, :arm, :mips].to_enum(:each).each do |the_arch|
        if raw_data.include?(the_arch.to_s)
          details[:architecture] = the_arch.to_s
          break
        end
      end
    end
  end
  #
  case details[:architecture]
  when /i[3456]86/
    if (details[:platform] == :darwin && ([ -1 ].pack('l!').length == 8))
      details[:architecture] = :x86_64
    else
      # details[:architecture] = :i386
      # Jarib's solution does not help folks deal with the differences between the 32bit arch flavors.  I'll be more specific
      details[:architecture] = details[:architecture].to_sym
    end
  when /amd64|x86_64/
    details[:architecture] = :x86_64
  when /ppc|powerpc/
    if [ -1 ].pack('l!').length == 8
      details[:architecture] = :powerpc_64
    else
      details[:architecture] = :powerpc
    end
  else
    if [ -1 ].pack('l!').length == 8
      details[:architecture] = (details[:architecture] + "_64").to_sym
    else
      details[:architecture] = details[:architecture].to_sym
    end
  end
  #
  # ### propose private gem and library paths for standalone support:
  details[:common_gems] = "common"
  details[:native_gems] = "#{details[:architecture].to_s}-#{details[:platform].to_s}-#{RUBY_ENGINE.to_s.downcase}-#{RUBY_VERSION.to_s.downcase}"
  details[:native_libraries] = details[:native_gems]
  # ### Gather CPU data by platform
  # I would really prefer that ALL architectures use the *same* detail format for profiling a given CPU.
  details[:processors] = []
  case details[:platform]
  when :windows
    # Review : working with wmic on windows takes Sooooo long that I had to put this block in a thread at startup. (not pretty but it works)
    # Review : waiting upon a bug fix for JRUBY under Windows --> Null pointer exception thrown.
    # Review : See - https://github.com/jruby/jruby/issues/6440
    # Sys::CPU.processors()
  when :bsd
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
  when :linux
    # for now: work around for unworkable Struct behavioral variation in Sys::CPU :P
    # Gather CPU(n) data
    cpu_entry = {}
    lastcpu = 0
    parse_cpu_info = Proc.new do |raw_line|
      line = raw_line.split(":")
      if line[0].to_s.size > 1
        key = line[0].to_s.downcase.strip.gsub(/\s+/,"_")
        value = line[1].to_s.strip
        #
        if value.to_s.size > 0
          if value.to_s.include?("yes")
            value = true
          end
          if value.to_s.include?("no")
            value = false
          end
          #
        else
          value = nil
        end
        cpu_entry[(key)] = value
      else
        if cpu_entry.keys.size > 0
          details[:processors] << cpu_entry
          cpu_entry = {}
        end
        next
      end
      #
    end
    ::IO::foreach("/proc/cpuinfo").each {|line| parse_cpu_info.call(line)}
    if cpu_entry.keys.size > 0
      details[:processors] << cpu_entry
    end
    #
  end
  # cleanup
  # 
  # return final result
  BOOTSTRAP=details
  # for testing innards
  # puts details.inspect()
end
# reset rubygems paths if in stand-alone mode
