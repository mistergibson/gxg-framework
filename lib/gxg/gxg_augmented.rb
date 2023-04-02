# To overcome load-order issues:
module GxG
  module Database
    class Database
      #
    end
    class PersistedHash
      #
    end
    class PersistedArray
      #
    end
  end
end
# ---------------------------------------------------------------------------------------------------------------------
# Additional alternations to Standard element classes: expanded functionality
# (Tier 1 Augmentation)
# 
# Class extensions:
#
class Class
  # Attribution : http://stackoverflow.com/questions/2393697/look-up-all-descendants-of-a-class-in-ruby
  def descendants
    result = []
    ObjectSpace.each_object(::Class) do |the_class|
      if the_class < self
        result << the_class
      end
    end
    result
  end
  #
end
# require facet classes here (prior to overrides), and ensure smooth integration with overrides.
# 
# ### dup and clone support for Fixnum, Integer, Float, (and BigDecimal at some point) : don't even bother to tell me I gain nothing -- I've heard this before.
class NilClass
  public
  def initialize_clone
    nil
  end
  alias :initialize_dup :initialize_clone
  alias :dup :initialize_clone
  def clone()
    initialize_clone
  end
end
#
#class FalseClass
#  public
#  def initialize_clone
#    false
#  end
#  alias :initialize_dup :initialize_clone
#  alias :dup :initialize_clone
#  def clone()
#    initialize_clone
#  end
#end
#
#class TrueClass
#  public
#  def initialize_clone
#    true
#  end
#  alias :initialize_dup :initialize_clone
#  alias :dup :initialize_clone
#  def clone()
#    initialize_clone
#  end
#end
#
class Float
  public
  def initialize_clone
    (self + 0.0)
  end
  alias :initialize_dup :initialize_clone
  alias :dup :initialize_clone
  def clone()
    initialize_clone
  end
  def to_d()
    ::BigDecimal.new(self.to_s)
  end
end
#
class Symbol
  def initialize_clone
    (self.to_s.dup.to_sym)
  end
  alias :initialize_dup :initialize_clone
  alias :dup :initialize_clone
  def clone()
    initialize_clone
  end
end
#
class DateTime
  def to_d()
    self.to_time.to_d
  end
end
#
class Time
  def to_datetime()
    ::DateTime::parse(self.to_s)
  end
  def to_d()
    self.to_f.to_d
  end
end
# IO/StringIO/File alterations
# Fill in missing constants according to platform.
# ### win32 stuff
#006 #define F_SETFL         1
#007 #define F_SETFD         2
#008 #define F_GETFL         3
#009
#010 #define _O_RDONLY       0x0000  /* open for reading only */
#011 #define _O_WRONLY       0x0001  /* open for writing only */
#012 #define _O_RDWR         0x0002  /* open for reading and writing */
#013
#014 #define _O_NONBLOCK     0x0004
#015
#016 #define _O_APPEND       0x0008  /* writes done at eof */
#017 #define _O_CREAT        0x0100  /* create and open file */
#018 #define _O_TRUNC        0x0200  /* open and truncate */
#019 #define _O_EXCL         0x0400  /* open only if file doesn't already exist */
#020 #define _O_TEXT         0x4000  /* file mode is text (translated) */
#021 #define _O_BINARY       0x8000  /* file mode is binary (untranslated) */
#022 #define _O_ACCMODE      0x10000
#023
#024 #define _O_NOINHERIT    0
#025 #define O_NOINHERIT     _O_NOINHERIT
#026
#027 #define O_RDONLY        _O_RDONLY
#028 #define O_WRONLY        _O_WRONLY
#029 #define O_RDWR          _O_RDWR
#030
#031 #define O_NONBLOCK      _O_NONBLOCK
#032
#033 #define O_APPEND        _O_APPEND
#034 #define O_CREAT         _O_CREAT
#035 #define O_TRUNC         _O_TRUNC
#036 #define O_EXCL          _O_EXCL
#037 #define O_TEXT          _O_TEXT
#038 #define O_BINARY        _O_BINARY
#039 #define O_ACCMODE       _O_ACCMODE
# ### end win32 stuff
#      @@valid_modes[:flags][:io][:tty] = 0x00000010
#      @@valid_modes[:flags][:io][:noctty] = ::IO::NOCTTY
#      @@valid_modes[:flags][:io][:duplex] = 0x00000020
#      @@valid_modes[:flags][:io][:append] = ::IO::APPEND
#      @@valid_modes[:flags][:io][:create] = ::IO::CREAT
#      @@valid_modes[:flags][:io][:exclusive] = ::IO::EXCL
#      @@valid_modes[:flags][:io][:wsplit] = 0x00000200
#      @@valid_modes[:flags][:io][:wsplit_initialized] = 0x00000400
#      @@valid_modes[:flags][:io][:trunc] = ::IO::TRUNC
#      @@valid_modes[:flags][:io][:text] = ::IO::TEXT
#      @@valid_modes[:flags][:io][:setenc_by_bom] = 0x00100000
# See : http://boop.ankhcraft.com/library/ruby-api/dc/dac/io_8h.html
# Also : http://boop.ankhcraft.com/library/ruby-api/d2/d4d/file_8h.html
# also : http://boop.ankhcraft.com/library/ruby-api/d6/d13/file_8c.html
#
class IO
  ## TRACK: io.h
  #define 	FMODE_READABLE   0x00000001
  #@@valid_modes[:flags][:io][:read] = 0x00000001
  #define 	FMODE_WRITABLE   0x00000002
  #@@valid_modes[:flags][:io][:write] = 0x00000002
  #define 	FMODE_READWRITE   (FMODE_READABLE|FMODE_WRITABLE)
  #@@valid_modes[:flags][:io][:readwrite] = (@@valid_modes[:flags][:io][:read] | @@valid_modes[:flags][:io][:write])
  #define 	FMODE_BINMODE   0x00000004
  #@@valid_modes[:flags][:io][:binary] = 0x00000004
  #define 	FMODE_SYNC   0x00000008
  #@@valid_modes[:flags][:io][:sync] = 0x00000008
  #define 	FMODE_TTY   0x00000010
  #@@valid_modes[:flags][:io][:tty] = 0x00000010
  #define 	FMODE_DUPLEX   0x00000020
  #@@valid_modes[:flags][:io][:duplex] = 0x00000020
  #define 	FMODE_APPEND   0x00000040
  #@@valid_modes[:flags][:io][:append] = 0x00000040
  #define 	FMODE_CREATE   0x00000080
  #@@valid_modes[:flags][:io][:create] = 0x00000080
  #define 	FMODE_WSPLIT   0x00000200
  # related to io object's buffer management (position offsets and buffer lengths)
  #@@valid_modes[:flags][:io][:wsplit] = 0x00000200
  #define 	FMODE_WSPLIT_INITIALIZED   0x00000400
  #@@valid_modes[:flags][:io][:wsplit_initialized] = 0x00000400
  #define 	FMODE_TRUNC   0x00000800
  #@@valid_modes[:flags][:io][:trunc] = 0x00000800
  #define 	FMODE_TEXTMODE   0x00001000
  #@@valid_modes[:flags][:io][:text] = 0x00001000
  #define 	FMODE_SETENC_BY_BOM   0x00100000
  #@@valid_modes[:flags][:io][:setenc_by_bom] = 0x00100000
  # [:SEEK_SET, :SEEK_CUR, :SEEK_END, :LOCK_SH, :LOCK_EX, :LOCK_UN, :LOCK_NB, :RDONLY, :WRONLY, :RDWR, :APPEND, :CREAT, :EXCL, :NONBLOCK, :TRUNC, :NOCTTY, :BINARY, :SYNC, :DSYNC, :RSYNC, :NOFOLLOW, :NOATIME, :FNM_NOESCAPE, :FNM_PATHNAME, :FNM_DOTMATCH, :FNM_CASEFOLD, :FNM_SYSCASE]
  unless defined?(TTY)
    # Note: need to verify this int value before using:
    TTY = 0x00000010
  end
  unless defined?(DUPLEX)
    # Note: need to verify this int value before using:
    DUPLEX = 0x00000020
  end
  unless defined?(WSPLIT)
    # Note: need to verify this int value before using:
    WSPLIT = 0x00000200
  end
  # Not included in jruby
  unless defined?(DSYNC)
    # Note: need to verify this int value before using:
    DSYNC = 4096
  end
  unless defined?(RSYNC)
    # Note: need to verify this int value before using:
    RSYNC = 1052672
  end
  unless defined?(NOATIME)
    # Note: need to verify this int value before using:
    NOATIME = 262144
  end
  #
  # Not included in rbx
  unless defined?(NOFOLLOW)
    # Note: need to verify this int value before using:
    NOFOLLOW = 131072
  end
  #
  unless defined?(WSPLIT_INITIALIZED)
    # Note: need to verify this int value before using:
    WSPLIT_INITIALIZED = 0x00000400
  end
  unless defined?(TEXT)
    # What is the flag value under Win32?
    TEXT = 0
  end
  unless defined?(SETENC_BY_BOM)
    # Note: need to verify this int value before using:
    #SETENC_BY_BOM = 0x00100000
    SETENC_BY_BOM = 0
  end
  #
  def write_latency()
    unless self.instance_variable_defined?(:@write_latency)
      @write_latency= {:low => nil, :last => nil, :high => nil}
    end
    @write_latency.clone
  end
  #
  def read_latency()
    unless self.instance_variable_defined?(:@read_latency)
      @read_latency= {:low => nil, :last => nil, :high => nil}
    end
    @read_latency.clone
  end
  #
  def latency_reading(old_reading=nil,&block)
    unless old_reading.is_a?(::Hash)
      old_reading = {:low => nil, :last => nil, :high => nil}
    end
    new_reading = {:low => nil, :last => nil, :high => nil}
    reading = millisecond_latency(&block)
    if old_reading[:low]
      if reading[:milliseconds] < old_reading[:low]
        new_reading[:low] = reading[:milliseconds].dup
      else
        new_reading[:low] = old_reading[:low]
      end
    else
      new_reading[:low] = reading[:milliseconds].dup
    end
    new_reading[:last] = reading[:milliseconds].dup
    if old_reading[:high]
      if reading[:milliseconds] > old_reading[:high]
        new_reading[:high] = reading[:milliseconds].dup
      else
        new_reading[:high] = old_reading[:high]
      end
    else
      new_reading[:high] = reading[:milliseconds].dup
    end
    #
    {:result => reading[:result], :reading => new_reading}
  end
  #
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
    flags[:readwrite] = ::Fcntl::O_RDWR
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
    flags[:nofollow] = ::File::NOFOLLOW # Do not follow symlinks.
    flags[:noaccesstime] = ::File::NOATIME # Do not update the access time (atime) of the file.
    flags[:match_noescape] = ::File::FNM_NOESCAPE #
    flags[:match_pathname] = ::File::FNM_PATHNAME #
    flags[:match_dotmatch] = ::File::FNM_DOTMATCH #
    flags[:match_casefold] = ::File::FNM_CASEFOLD #
    flags[:match_systemcase] = ::File::FNM_SYSCASE #
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
  def profile(params={:follow_symlinks => true})
    platform_details = GxG::SYSTEM.platform()
    result = {}
    #
    if params[:follow_symlinks]
      raw_stat = self.to_io.stat
    else
      raw_stat = self.to_io.lstat
    end
    raw_mode = raw_stat.mode.to_s(base=8)
    if raw_mode.size < 7
      raw_mode = ("0" << raw_mode)
    end
    set_user_id = false
    set_group_id = false
    set_sticky_bit = false
    if (raw_mode[3].to_i & 4) == 4
      set_user_id = true
    end
    if (raw_mode[3].to_i & 2) == 2
      set_group_id = true
    end
    if (raw_mode[3].to_i & 1) ==  1
      set_sticky_bit = true
    end
    #
    #
    raw_permission = { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }
    #
    file_handle = nil
    GxG::Engine::file_descriptors.to_enum.each do |the_handle|
      if self.fileno == the_handle.fileno
        file_handle = the_handle
        break
      end
    end
    # LATER: GxG::IO::IO.profile : patch into file/stream type recognition engine.
    case raw_stat.ftype.to_s.downcase.to_sym
    when :link
      # are .lnk files handled properly on win32 for this?
      result[:type] =  :symlink
    when :file
      if file_handle
        if self.tty?
          result[:type] =  :tty
        else
          the_extension = ::File::basename(file_handle.to_path).split(".")[-1].to_s.downcase
          if the_extension == "lnk"
            result[:type] =  :symlink
          else
            if ["so","la","a","dylib","dll","class"].include?(the_extension)
              result[:type] =  :library
            else
              if (["out","exe","misc","java","jar", "sh", "rb", "py", "pyc"].include?(the_extension) || raw_stat.executable_real?)
                result[:type] =  :application
              else
                result[:type] = :file
              end
            end
          end
        end
      end
    when :fifo
      result[:type] =  :fifo
    when :characterspecial
      result[:type] =  :character_device
    when :blockspecial
      result[:type] =  :block_device
    when :socket
      result[:type] =  :socket
    when :directory
      result[:type] =  :directory
    when :unknown
      result[:type] =  :unknown
      if raw_stat.pipe?
        result[:type] =  :pipe
      end
    else
      if raw_stat.pipe?
        result[:type] =  :pipe
      end
    end
    result[:owner_type] = result[:type]
    result[:on_device] = raw_stat.dev.to_s(base=10).to_i
    if result[:on_device]
      result[:on_device_major] = raw_stat.dev_major
      result[:on_device_minor] = raw_stat.dev_minor
    end
    result[:is_device] = raw_stat.rdev
    if result[:is_device]
      result[:is_device_major] = raw_stat.rdev_major
      result[:is_device_minor] = raw_stat.rdev_minor
    end
    result[:inode] = raw_stat.ino.to_i
    #
    result[:flags] = self.flags()
    #
    if file_handle
      # man fstat : mode decoder-ring table:
      #
      #           S_IFMT     0170000   bit mask for the file type bit fields
      #           S_IFSOCK   0140000   socket
      #           S_IFLNK    0120000   symbolic link
      #           S_IFREG    0100000   regular file
      #           S_IFBLK    0060000   block device
      #           S_IFDIR    0040000   directory
      #           S_IFCHR    0020000   character device
      #           S_IFIFO    0010000   FIFO
      #
      #           S_ISUID    0004000   set UID bit
      #           S_ISGID    0002000   set-group-ID bit (see below)
      #           S_ISVTX    0001000   sticky bit (see below)
      #
      #           S_IRWXU    00700     mask for file owner permissions
      #           S_IRUSR    00400     owner has read permission
      #           S_IWUSR    00200     owner has write permission
      #           S_IXUSR    00100     owner has execute permission
      #
      #           S_IRWXG    00070     mask for group permissions
      #           S_IRGRP    00040     group has read permission
      #           S_IWGRP    00020     group has write permission
      #           S_IXGRP    00010     group has execute permission
      #
      #           S_IRWXO    00007     mask for permissions for others (not in group)
      #           S_IROTH    00004     others have read permission
      #           S_IWOTH    00002     others have write permission
      #           S_IXOTH    00001     others have execute permission
      #
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
      result[:hardlinks_to] = raw_stat.nlink.to_i
      result[:user_id] = raw_stat.uid.to_i
      result[:group_id] = raw_stat.gid.to_i
      result[:size] = raw_stat.size
      result[:block_size] = raw_stat.blksize
      result[:blocks] = raw_stat.blocks
      result[:accessed] = DateTime::parse(raw_stat.atime.to_s)
      result[:modified] = DateTime::parse(raw_stat.mtime.to_s)
      result[:status_modified] = DateTime::parse(raw_stat.ctime.to_s)
      # File permissions work in an ACL style, even if based only upon Unix-style permissions.
      #
      result[:permissions] = {:effective => raw_permission.clone, :owner => raw_permission.clone, :group => raw_permission.clone, :other => raw_permission.clone}
      if set_user_id
        result[:flags] << :user_id_on_execute
      end
      if set_group_id
        result[:flags] << :group_id_on_execute
      end
      if set_sticky_bit
        result[:flags] << :sticky_bit
      end
      # owner permissions
      if (raw_mode[4].to_i & 4) == 4
        result[:permissions][:owner][:read] = true
      end
      if (raw_mode[4].to_i & 2) == 2
        result[:permissions][:owner][:write] = true
        if platform_details[:platform] == :windows
          # :windows way of reading :rename, :move, and :destroy permission for file/directory.
        else
          result[:permissions][:owner][:rename] = true
          result[:permissions][:owner][:move] = true
          result[:permissions][:owner][:destroy] = true
          result[:permissions][:owner][:create] = true
        end
      end
      if (raw_mode[4].to_i & 1) == 1
        result[:permissions][:owner][:execute] = true
      end
      # group permissions
      if (raw_mode[5].to_i & 4) == 4
        result[:permissions][:owner][:read] = true
      end
      if (raw_mode[5].to_i & 2) == 2
        result[:permissions][:group][:write] = true
        if platform_details[:platform] == :windows
          # :windows way of reading :rename, :move, and :destroy permission for file/directory.
        else
          result[:permissions][:group][:rename] = true
          result[:permissions][:group][:move] = true
          result[:permissions][:group][:destroy] = true
          result[:permissions][:group][:create] = true
        end
      end
      if (raw_mode[5].to_i & 1) == 1
        result[:permissions][:group][:execute] = true
      end
      # other permissions
      if (raw_mode[6].to_i & 4) == 4
        result[:permissions][:other][:read] = true
      end
      if (raw_mode[6].to_i & 2) == 2
        result[:permissions][:other][:write] = true
        if platform_details[:platform] == :windows
          # :windows way of reading :rename, :move, and :destroy permission for file/directory.
        else
          result[:permissions][:other][:rename] = true
          result[:permissions][:other][:move] = true
          result[:permissions][:other][:destroy] = true
          result[:permissions][:other][:create] = true
        end
      end
      if (raw_mode[6].to_i & 1) == 1
        result[:permissions][:other][:execute] = true
      end
      # effective (this user) permissions (while opened, supercedes normal effective file system permissions)
      if result[:flags].index(:read)
        result[:permissions][:effective][:read] = true
        #
      end
      if result[:flags].index(:write)
        result[:permissions][:effective][:write] = true
        if platform_details[:platform] == :windows
          # :windows way of reading :rename, :move, and :destroy permission for file/directory.
        else
          result[:permissions][:effective][:rename] = true
          result[:permissions][:effective][:move] = true
          result[:permissions][:effective][:destroy] = true
          result[:permissions][:effective][:create] = true
        end
      end
      if raw_stat.executable?
        result[:permissions][:effective][:execute] = true
      end
      #
    else
      # in-memory object - no fs involvement
      # ok ... why? Well, I want objects to be able to pass through my unwritten system stuff : experimental, w/o special handling.
      result[:permissions] = {:effective => raw_permission.clone, :owner => raw_permission.clone, :group => raw_permission.clone, :other => raw_permission.clone}
      #
      if result[:flags].index(:read)
        result[:permissions][:effective][:read] = true
        result[:permissions][:owner][:read] = true
        result[:permissions][:group][:read] = true
        result[:permissions][:other][:read] = true
        #
      end
      #
      if result[:flags].index(:write)
        result[:permissions][:effective][:write] = true
        result[:permissions][:owner][:write] = true
        result[:permissions][:group][:write] = true
        result[:permissions][:other][:write] = true
      end
      #
    end
    #
    result[:mode] = {}
    #
    result
  end
  #
  def as_segments(segment_size=65536, as_bytearrays=false, &block)
    result = []
    unless self.closed?
      if segment_size.is_any?(::TrueClass, ::FalseClass, NilClass)
        as_bytearrays = segment_size
        segment_size = 65536
      end
      saved_position = self.pos
      self.seek(0, :END)
      current_size = self.pos + 1
      #
      self.rewind
      if block.respond_to?(:call)
        GxG::apportioned_ranges(current_size, segment_size).each do |portion_range|
          self.seek(portion_range.first)
          if as_bytearrays
            block.call(bytes self.read(portion_range.size))
          else
            block.call(self.read(portion_range.size))
          end
        end
      else
        GxG::apportioned_ranges(current_size, segment_size).each do |portion_range|
          self.seek(portion_range.first)
          if as_bytearrays
            result << bytes self.read(portion_range.size)
          else
            result << self.read(portion_range.size)
          end
        end
      end
      #
      self.pos = saved_position
    end
    result
  end
end
#
class StringIO
  #
  public
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
    # Question: ok, so the cosmetics are that it is in binmode ... but what will be its actual behavior??
    if self.binmode?()
      self
    else
      self.set_encoding(::Encoding::ASCII_8BIT)
    end
  end
  #
  def write_latency()
    # Just in StringIO for interface compatibility.
    unless self.instance_variable_defined?(:@write_latency)
      @write_latency= {:low => nil, :last => nil, :high => nil}
    end
    @write_latency.clone
  end
  #
  def read_latency()
    # Just in StringIO for interface compatibility.
    unless self.instance_variable_defined?(:@read_latency)
      @read_latency= {:low => nil, :last => nil, :high => nil}
    end
    @read_latency.clone
  end
  #
  def latency_reading(old_reading=nil,&block)
    # Just in StringIO for interface compatibility.
    unless old_reading.is_a?(::Hash)
      old_reading = {:low => nil, :last => nil, :high => nil}
    end
    new_reading = {:low => nil, :last => nil, :high => nil}
    reading = millisecond_latency(&block)
    if old_reading[:low]
      if reading[:milliseconds] < old_reading[:low]
        new_reading[:low] = reading[:milliseconds].dup
      else
        new_reading[:low] = old_reading[:low]
      end
    else
      new_reading[:low] = reading[:milliseconds].dup
    end
    new_reading[:last] = reading[:milliseconds].dup
    if old_reading[:high]
      if reading[:milliseconds] > old_reading[:high]
        new_reading[:high] = reading[:milliseconds].dup
      else
        new_reading[:high] = old_reading[:high]
      end
    else
      new_reading[:high] = reading[:milliseconds].dup
    end
    #
    {:result => reading[:result], :reading => new_reading}
  end
  #
  def fcntl(*args)
    if args[0] == ::Fcntl::F_GETFL
      current = ::Fcntl::O_NONBLOCK
      if self.closed_read?()
        unless self.closed_write?()
          current = (current | ::Fcntl::O_WRONLY)
        end
      else
        if self.closed_write?()
          current = (current | ::Fcntl::O_RDONLY)
        else
          current = (current | ::Fcntl::O_RDWR)
        end
      end
      current
    else
      0
    end
  end
  #
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
    flags[:readwrite] = ::Fcntl::O_RDWR
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
    # these do not apply to in-memory IO-like things at all:
    #    flags[:nofollow] = ::File::NOFOLLOW # Do not follow symlinks.
    #    flags[:noaccesstime] = ::File::NOATIME # Do not update the access time (atime) of the file.
    #    flags[:match_noescape] = ::File::FNM_NOESCAPE #
    #    flags[:match_pathname] = ::File::FNM_PATHNAME #
    #    flags[:match_dotmatch] = ::File::FNM_DOTMATCH #
    #    flags[:match_casefold] = ::File::FNM_CASEFOLD #
    #    flags[:match_systemcase] = ::File::FNM_SYSCASE #
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
  def stat(*args)
    nil
  end
  alias :lstat :stat
  #
  def profile()
    current = self.flags()
    result = {:type => :memory, :flags => current, :permissions => {:effective=>{:execute=>false, :rename=>false, :move=>false, :destroy=>false, :create=>false, :write=>false, :read=>false}}}
    #
    if current.include?(:read)
      result[:permissions][:effective][:read] = true
    end
    if current.include?(:write)
      result[:permissions][:effective][:write] = true
      result[:permissions][:effective][:destroy] = true
      result[:permissions][:effective][:create] = true
    end
    #
    result
  end
  #
end
#
class File
  # [:SEPARATOR, :ALT_SEPARATOR, :PATH_SEPARATOR, :Stat,, :SEEK_SET, :SEEK_CUR, :SEEK_END, :LOCK_SH, :LOCK_EX, :LOCK_UN, :LOCK_NB, :RDONLY, :WRONLY, :RDWR, :APPEND, :CREAT, :EXCL, :NONBLOCK, :TRUNC, :NOCTTY, :BINARY, :SYNC, :DSYNC, :RSYNC, :NOFOLLOW, :NOATIME, :FNM_NOESCAPE, :FNM_PATHNAME, :FNM_DOTMATCH, :FNM_CASEFOLD, :FNM_SYSCASE]
  unless defined?(TTY)
    TTY = ::IO::TTY
  end
  unless defined?(DUPLEX)
    DUPLEX = ::IO::DUPLEX
  end
  unless defined?(WSPLIT)
    WSPLIT = ::IO::WSPLIT
  end
  unless defined?(WSPLIT_INITIALIZED)
    WSPLIT_INITIALIZED = ::IO::WSPLIT_INITIALIZED
  end
  unless defined?(TEXT)
    # What is the flag value under Win32?
    TEXT = 0
  end
  unless defined?(SETENC_BY_BOM)
    # Note: need to verify ::IO::SETENC_BY_BOM value before using:
    SETENC_BY_BOM = ::IO::SETENC_BY_BOM
  end
  #
  def self.find_file_mimetype(the_file=nil)
    if the_file.is_a?(::String)
      if (/.*(?:\\|\/)(.+)$/.match(the_file.to_s) || the_file.to_s.split("/").size > 0 || the_file == "/")
        if ::File.directory?(the_file)
          raise ArgumentError, "You tried to look at a directory, not a File. (#{the_file.inspect})."
        else
          the_file = ::File.open(the_file, "r")
        end
      else
        raise ArgumentError, "You MUST provide a valid File path."
      end
    end
    if the_file.is_a?(::File)
      the_file.file_type()
    else
      raise ArgumentError, "You MUST provide a valid File object."
    end
  end
  #
  def self.mode_permission_to_gxg(the_mode=0)
    result = {}
    if the_mode.is_a?(::Numeric)
      raw_mode = the_mode.to_s(base=8)
      set_user_id = false
      set_group_id = false
      set_sticky_bit = false
      while raw_mode.size < 4
        raw_mode = ("0" << raw_mode)
      end
      if raw_mode.size > 4
        raw_mode = raw_mode[((raw_mode.size - 4)..-1)].to_s
      end
      #
      if (raw_mode[0].to_i & 4) == 4
        set_user_id = true
      end
      if (raw_mode[0].to_i & 2) == 2
        set_group_id = true
      end
      if (raw_mode[0].to_i & 1) ==  1
        set_sticky_bit = true
      end
      raw_permission = { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }
      result = {:effective => nil, :owner => raw_permission.clone, :group => raw_permission.clone, :other => raw_permission.clone}
      #
      # puts "using: #{raw_mode.inspect}"
      # owner permissions
      if (raw_mode[1].to_i & 4) == 4
        result[:owner][:read] = true
      end
      if (raw_mode[1].to_i & 2) == 2
        result[:owner][:write] = true
        result[:owner][:rename] = true
        result[:owner][:move] = true
        result[:owner][:destroy] = true
        result[:owner][:create] = true
      end
      if (raw_mode[1].to_i & 1) == 1
        result[:owner][:execute] = true
      end
      # group permissions
      if (raw_mode[2].to_i & 4) == 4
        result[:group][:read] = true
      end
      if (raw_mode[2].to_i & 2) == 2
        result[:group][:write] = true
        result[:group][:rename] = true
        result[:group][:move] = true
        result[:group][:destroy] = true
        result[:group][:create] = true
      end
      if (raw_mode[2].to_i & 1) == 1
        result[:group][:execute] = true
      end
      # other permissions
      if (raw_mode[3].to_i & 4) == 4
        result[:other][:read] = true
      end
      if (raw_mode[3].to_i & 2) == 2
        result[:other][:write] = true
        result[:other][:rename] = true
        result[:other][:move] = true
        result[:other][:destroy] = true
        result[:other][:create] = true
      end
      if (raw_mode[3].to_i & 1) == 1
        result[:other][:execute] = true
      end
    else
      raise ArgumentError, "You MUST provide an Integer"
    end
    result
  end
  #
  def self.mode_permission_to_unix(the_mode=0, type = :file)
    result = "----------"
    if the_mode.is_a?(::Numeric)
      accumulator = ""
      raw_mode = the_mode.to_s(base=8)
      if raw_mode.size < 7
        raw_mode = ("0" << raw_mode)
      end
      set_user_id = false
      set_group_id = false
      set_sticky_bit = false
      if (raw_mode[3].to_i & 4) == 4
        set_user_id = true
      end
      if (raw_mode[3].to_i & 2) == 2
        set_group_id = true
      end
      if (raw_mode[3].to_i & 1) ==  1
        set_sticky_bit = true
      end
      #
      case type.to_s.to_sym
      when :directory
        accumulator << "d"
      when :symlink
        accumulator << "l"
      when :file
        accumulator << "-"
      else
        raise ArgumentError, "You MUST provide a valid file system entity type: :file, :directory or :symlink."
      end
      # owner permissions
      if (raw_mode[1].to_i & 4) == 4
        accumulator << "r"
      else
        accumulator << "-"
      end
      if (raw_mode[1].to_i & 2) == 2
        accumulator << "w"
      else
        accumulator << "-"
      end
      if (raw_mode[1].to_i & 1) == 1
        accumulator << "x"
      else
        accumulator << "-"
      end
      # group permissions
      if (raw_mode[2].to_i & 4) == 4
        accumulator << "r"
      else
        accumulator << "-"
      end
      if (raw_mode[2].to_i & 2) == 2
        accumulator << "w"
      else
        accumulator << "-"
      end
      if (raw_mode[2].to_i & 1) == 1
        accumulator << "x"
      else
        accumulator << "-"
      end
      # other permissions
      if (raw_mode[3].to_i & 4) == 4
        accumulator << "r"
      else
        accumulator << "-"
      end
      if (raw_mode[3].to_i & 2) == 2
        accumulator << "w"
      else
        accumulator << "-"
      end
      if (raw_mode[3].to_i & 1) == 1
        accumulator << "x"
      else
        accumulator << "-"
      end
      result = accumulator
    else
      raise ArgumentError, "You MUST provide an Integer"
    end
    result
  end
  #
  def self.gxg_permissions_to_unix(permissions={:owner => { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }, :group => { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }, :other => { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }}, type = :file)
    result = "----------"
    if permissions.is_a?(::Hash)
      accumulator = ""
      raw_data = "----------"
      write_permissions = [:write, :create, :destroy, :rename, :move]
      case type
      when :directory
        accumulator << "d"
      when :symlink
        accumulator << "l"
      when :file
        accumulator << "-"
      else
        raise ArgumentError, "You MUST provide a valid file system entity type: :file, :directory or :symlink."
      end
      raw_data.each_char_with_index do |character, index|
        case index
        when 1
          if permissions[:owner][:read]
            accumulator << "r"
          else
            accumulator << character
          end
        when 2
          write_permissions.each do |the_perm|
            if permissions[:owner][(the_perm)]
              accumulator << "w"
              break
            end
          end
          if accumulator[-1] != "w"
            accumulator << character
          end
        when 3
          if permissions[:owner][:execute]
            accumulator << "x"
          else
            accumulator << character
          end
        when 4
          if permissions[:group][:read]
            accumulator << "r"
          else
            accumulator << character
          end
        when 5
          write_permissions.each do |the_perm|
            if permissions[:group][(the_perm)]
              accumulator << "w"
              break
            end
          end
          if accumulator[-1] != "w"
            accumulator << character
          end
        when 6
          if permissions[:group][:execute]
            accumulator << "x"
          else
            accumulator << character
          end
        when 7
          if permissions[:other][:read]
            accumulator << "r"
          else
            accumulator << character
          end
        when 8
          write_permissions.each do |the_perm|
            if permissions[:other][(the_perm)]
              accumulator << "w"
              break
            end
          end
          if accumulator[-1] != "w"
            accumulator << character
          end
        when 9
          if permissions[:other][:execute]
            accumulator << "x"
          else
            accumulator << character
          end
        end
      end
      result = accumulator
    else
      raise ArgumentError, "You MUST provide a Hash with :owner, :group, and :other permission sub-hashes of true/false flags"
    end
    result
  end
  #
  def self.gxg_permissions_to_mode(permissions={:owner => { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }, :group => { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }, :other => { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }}, type = :file)
    result = 0
    if permissions.is_a?(::Hash)
      octet = 0
      octet_string = "0"
      unix_permissions = ::File.gxg_permissions_to_unix(permissions,type)
      #
      unix_permissions.each_char_with_index do |character, index|
        #
        if (1..3).include?(index)
          case index
          when 1
            unless character == "-"
              octet += 4
            end
          when 2
            unless character == "-"
              octet += 2
            end
          when 3
            unless character == "-"
              octet += 1
            end
          end
          if index == 3
            octet_string << octet.to_s
            octet = 0
          end
        end
        #
        if (4..6).include?(index)
          case index
          when 4
            unless character == "-"
              octet += 4
            end
          when 5
            unless character == "-"
              octet += 2
            end
          when 6
            unless character == "-"
              octet += 1
            end
          end
          if index == 6
            octet_string << octet.to_s
            octet = 0
          end
        end
        #
        if (7..9).include?(index)
          case index
          when 7
            unless character == "-"
              octet += 4
            end
          when 8
            unless character == "-"
              octet += 2
            end
          when 9
            unless character == "-"
              octet += 1
            end
          end
          if index == 9
            octet_string << octet.to_s
            octet = 0
          end
        end
        #
        result = octet_string.to_i(base=8)
      end
      #
    else
      raise ArgumentError, "You MUST provide a Hash with :owner, :group, and :other permission sub-hashes of true/false flags"
    end
    result
  end
  #
  def self.unix_permissions_to_gxg(permission_string="")
    raw_permission = { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }
    blank_permissions = {:effective => nil, :owner => raw_permission.clone, :group => raw_permission.clone, :other => raw_permission.clone}
    permission_record = blank_permissions.clone
    #
    if permission_string.is_a?(::String)
      permission_string.each_char_with_index do |character, index|
        #
        case index
        when 1
          if character == "r"
            permission_record[:owner][:read] = true
          end
        when 2
          if character == "w"
            permission_record[:owner][:write] = true
            permission_record[:owner][:rename] = true
            permission_record[:owner][:move] = true
            permission_record[:owner][:destroy] = true
            permission_record[:owner][:create] = true
          end
        when 3
          if character == "x"
            permission_record[:owner][:execute] = true
          end
        when 4
          if character == "r"
            permission_record[:group][:read] = true
          end
        when 5
          if character == "w"
            permission_record[:group][:write] = true
            permission_record[:group][:rename] = true
            permission_record[:group][:move] = true
            permission_record[:group][:destroy] = true
            permission_record[:group][:create] = true
          end
        when 6
          if character == "x"
            permission_record[:group][:execute] = true
          end
        when 7
          if character == "r"
            permission_record[:other][:read] = true
          end
        when 8
          if character == "w"
            permission_record[:other][:write] = true
            permission_record[:other][:rename] = true
            permission_record[:other][:move] = true
            permission_record[:other][:destroy] = true
            permission_record[:other][:create] = true
          end
        when 9
          if character == "x"
            permission_record[:other][:execute] = true
          end
        end
        # No way to calculate Effective Permissions - it will be nil consequently.
        #
      end
      result = permission_record
    else
      result = nil
      raise ArgumentError, "You MUST supply a valid unix permission String"
    end
    result
  end
  #
  def file_type()
    # TODO: return GxG-UFS value as well.
    type = ::MimeMagic.by_path(self.path)
    {:mime_type => type.type(), :subtype => type.subtype(), :mediatype => type.mediatype(), :extensions => type.extensions(), :comment => type.comment(), :ufs => nil}
  end
  #
end
#
module Fcntl
  # [:F_DUPFD, :F_GETFD, :F_GETLK, :F_SETFD, :F_GETFL, :F_SETFL, :F_SETLK, :F_SETLKW, :FD_CLOEXEC, :F_RDLCK, :F_UNLCK, :F_WRLCK, :O_CREAT, :O_EXCL, :O_NOCTTY, :O_TRUNC, :O_APPEND, :O_NONBLOCK, :O_NDELAY, :O_RDONLY, :O_RDWR, :O_WRONLY, :O_ACCMODE]
  unless const_defined?(:O_TEXT)
    O_TEXT = ::File::TEXT
  end
  unless const_defined?(:O_BINARY)
    O_BINARY = ::File::BINARY
  end
end
# ### URI alterations
# module URI
#   #
#   def self.parse(*args)
#     #::URI::Generic.new(*(::URI::split(*args)))
#     ::URI::Generic::parse(*args)
#   end
#   #
# 	class Generic
#     #
# 		def set_scheme(v)
# 			if v.is_a?(String)
#         @scheme = v
# 			end
#       v
# 		end
		
# 		def scheme=(scheme="")
# 			set_scheme(scheme)
# 			scheme
# 		end
		
# 		def scheme()
#       @scheme
# 		end
		
# 		def set_userinfo(user, password = nil)
# 			unless password 
# 				user, password = split_userinfo(user)
# 			end
# 			if user.is_a?(String)
# 				@user     = URI::escape(user)
# 			else
# 				@user = user
# 			end
# 			if password.is_a?(String)
# 				@password = URI::escape(password)
# 			else
# 				@password = password
# 			end
# 			result = []
# 			if @user.is_a?(String)
# 				result << URI::unescape(@user)
# 			else
# 				result << @user
# 			end
# 			if @password.is_a?(String)
# 				result << URI::unescape(@password)
# 			else
# 				result << @password
# 			end
# 			result
# 		end
		
# 		def userinfo
# 			if @user.nil?
# 				nil
# 			elsif @password.nil?
# 				URI::unescape(@user)
# 			else
# 				URI::unescape(@user) + ':' + URI::unescape(@password)
# 			end
# 		end
		
# 		def user=(user)
# 			if user.is_a?(String)
# 				user = (URI::escape(user))
# 			end
# 			set_user(user)
# 			self.user
# 			# returns user
# 		end
		
# 		def user
# 			if @user.is_a?(String)
# 				URI::unescape(@user)
# 			else
# 				@user
# 			end
# 		end
		
# 		def set_password(v)
# 			if v.is_a?(String)
# 				@password = URI::escape(v)
# 			end
# 			if @password.is_a?(String)
# 				URI::unescape(@password)
# 			else
# 				@password
# 			end
# 		end
		
# 		def password=(password)
# 			if password.is_a?(String)
# 				password = (URI::escape(password))
# 			end
# 			set_password(password)
# 			# returns password
# 		end
		
# 		def password
# 			if @password.is_a?(String)
# 				URI::unescape(@password)
# 			else
# 				@password
# 			end
# 		end
		
# 		def set_host(v)
# 			if v.is_a?(String)
# 				@host = URI::escape(v)
# 			else
# 				@host = v
# 			end
# 		end
# 		#
# 		def host=(v)
# 			if v.is_a?(String)
# 				v = (URI::escape(v))
# 			end
# 			set_host(v)
# 			self.host
# 		end
# 		#
# 		def host()
# 			if @host.is_a?(String)
# 				URI::unescape(@host)
# 			else
# 				@host
# 			end
# 		end
#     #
#     def hostname()
#       if @host.to_s.size > 0
#         self.host().to_s.dup.gsub("[","").gsub("]","")
#       else
#         nil
#       end
#     end
#     #
#     def hostname=(v)
#       if (v.to_s.include?(":") || (v.to_s.include?("[") && v.to_s.include?("]")))
#         # ipv6 ??
#         if v.to_s.include?("[") && v.to_s.include?("]")
#           self.host = v.to_s
#         else
#           self.host = "[" << v.to_s << "]"
#         end
#       else
#         self.host = v.to_s
#       end
#       self.host()
#     end
# 		#
# 		# def set_registry(v)
# 		# 	if v.is_a?(String)
# 		# 		@registry = URI::escape(v)
# 		# 	else
# 		# 		@registry = v
# 		# 	end
# 		# end
#     # #
# 		# def registry=(v)
# 		# 	if v.is_a?(String)
# 		# 		v = (URI::escape(v))
# 		# 	end
# 		# 	set_registry(v)
# 		# 	self.registry
# 		# end
		
# 		# def registry
# 		# 	if @registry.is_a?(String)
# 		# 		URI::unescape(@registry)
# 		# 	else
# 		# 		@registry
# 		# 	end
# 		# end
		
# 		# def set_path(v)
# 		# 	if v.is_a?(String)
# 		# 		@path = URI::escape(v)
# 		# 	else
# 		# 		@path = v
# 		# 	end
# 		# end

# 		# def path=(v)
# 		# 	if v.is_a?(String)
# 		# 		v = (URI::escape(v))
# 		# 	end
# 		# 	set_path(v)
# 		# 	self.path
# 		# end
		
# 		# def path
# 		# 	if @path.is_a?(String)
# 		# 		URI::unescape(@path)
# 		# 	else
# 		# 		@path
# 		# 	end
# 		# end
		
# 		# def set_opaque(v)
# 		# 	if v.is_a?(String)
# 		# 		@opaque = URI::escape(v)
# 		# 	else
# 		# 		@opaque = v
# 		# 	end
# 		# end

# 		# def opaque=(v)
# 		# 	if v.is_a?(String)
# 		# 		v = (URI::escape(v))
# 		# 	end
# 		# 	set_opaque(v)
# 		# 	self.opaque
# 		# end
		
# 		# def opaque
# 		# 	if @opaque.is_a?(String)
# 		# 		URI::unescape(@opaque)
# 		# 	else
# 		# 		@opaque
# 		# 	end
# 		# end
# 		# Review - query modifications bugger MatrixClient logins.
# 		# def set_query(v)
# 		# 	if v.is_a?(String)
# 		# 		@query = URI::escape(v)
# 		# 	else
# 		# 		@query = v
# 		# 	end
# 		# end
		
# 		# def query=(v)
# 		# 	if v.is_a?(String)
# 		# 		v = (URI::escape(v))
# 		# 	end
# 		# 	set_query(v)
# 		# 	self.query
# 		# end
		
# 		# def query
# 		# 	if @query.is_a?(String)
# 		# 		URI::unescape(@query)
# 		# 	else
# 		# 		@query
# 		# 	end
# 		# end
		
# 		# def set_fragment(v)
# 		# 	if v.is_a?(String)
# 		# 		@fragment = URI::escape(v)
# 		# 	else
# 		# 		@fragment = v
# 		# 	end
# 		# end

# 		# def fragment=(v)
# 		# 	if v.is_a?(String)
# 		# 		v = (URI::escape(v))
# 		# 	end
# 		# 	set_fragment(v)
# 		# 	self.fragment
# 		# end
		
# 		# def fragment
# 		# 	if @fragment.is_a?(String)
# 		# 		URI::unescape(@fragment)
# 		# 	else
# 		# 		@fragment
# 		# 	end
# 		# end
# 		#
# 		# def to_s
# 		# 	str = ''
# 		# 	if @scheme
# 		# 		str << @scheme
# 		# 		str << ':'
# 		# 	end
# 		# 	if @opaque
# 		# 		str << @opaque
# 		# 	else
# 		# 		if @registry
# 		# 			str << @registry
# 		# 		else
#     #       if @host
#     #         str << '//'
#     #       end
#     #       if self.userinfo
#     #         str << self.userinfo
#     #         str << '@'
#     #       end
#     #       if @host
#     #         str << @host
#     #       end
#     #       if @port && @port != self.default_port
#     #         str << ':'
#     #         str << @port.to_s
#     #       end
# 		# 		end
#     #     str << @path
#     #     if @query
#     #       str << '?'
#     #       str << @query
#     #     end
# 		# 	end
# 		# 	if @fragment
# 		# 		str << '#'
# 		# 		str << @fragment
# 		# 	end
# 		# 	URI::escape(str)
# 		# end
#     #
#     def from_hash(the_hash={})
# 			if the_hash[:scheme]
#         self.scheme = the_hash[:scheme]
#       else
#         @scheme = nil
# 			end
# 			if the_hash[:opaque]
#         self.opaque = the_hash[:opaque]
#         @registry = nil
#         @user = nil
#         @password = nil
#         @host = nil
#         @port = nil
#         @path = nil
#         @query = nil
# 			else
#         @opaque = nil
# 				if the_hash[:registry]
#           self.registry = the_hash[:registry]
#           @user = nil
#           @password = nil
#           @host = nil
#           @port = nil
# 				else
#           @registry = nil
#           if the_hash[:user]
#             self.user = the_hash[:user]
#           else
#             @user = nil
#           end
#           if the_hash[:password]
#             self.password = the_hash[:password]
#           else
#             @password = nil
#           end
#           if the_hash[:host]
#             self.host = the_hash[:host]
#           else
#             @host = nil
#           end
#           if the_hash[:port] && the_hash[:port] != self.default_port
#             self.port = the_hash[:port].to_i
#           else
#             @port = nil
#           end
# 				end
#         if the_hash[:path]
#           self.path = the_hash[:path]
#         else
#           @path = nil
#         end
#         if the_hash[:query]
#           self.query = the_hash[:query]
#         else
#           @query = nil
#         end
# 			end
#       if the_hash[:fragment]
#         self.fragment = the_hash[:fragment]
#       else
#         @fragment = nil
#       end
#       self
#     end
#     #
# 		def to_hash()
# 			result = {}
# 			if @scheme
# 				result[:scheme] = @scheme
# 			end
# 			if @opaque
# 				result[:opaque] = URI::unescape(@opaque)
# 			else
# 				if @registry
#           result[:registry] = URI::unescape(@registry)
# 				else
#           if @user
#             result[:user] = URI::unescape(@user)
#           end
#           if @password
#             result[:password] = URI::unescape(@password)
#           end
#           if @host
#             result[:host] = URI::unescape(@host)
#           end
#           if @port && @port != self.default_port
#             result[:port] = URI::unescape(@port).to_i
#           end
# 				end
#         if @path
#           result[:path] = URI::unescape(@path)
#         end
#         if @query
#           result[:query] = URI::unescape(@query)
#         end
# 			end
#       if @fragment
#         result[:fragment] = URI::unescape(@fragment)
#       end
#       result
# 		end
#     #
#     def address_info()
#       ::Addrinfo::parse(self)
#     end
#     #
#     def resolve_host()
#       case @scheme
#       when "inproc"
#         # no-op
#       when "ipc", "unix"
#         # no-op
#       when "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"
#         self.hostname = ::TCPSocket.getaddress(self.hostname)
#       end
#     end
#     #
# 	end
	
# 	def self.parse(uri)
# 		# Alterations:
# 		# leading/trailing whitespace removal - intended to reduce false exception conditions (missing regexp bits)
# 		# I think first reported in 2007, but still not fixed.  dunno why not.
# 		while uri[0] == 32
# 			uri[0] = ""
# 		end
# 		if uri.size > 0
# 			while uri[-1] == 32
# 				uri[-1] = ""
# 			end
# 		end
# 		# attempt to escape all strings going INTO the URI object?
# 		uri = URI::escape(uri)
# 		# End Alterations
# 		scheme, userinfo, host, port, 
# 		registry, path, opaque, query, fragment = self.split(uri)

# 		if scheme && @@schemes.include?(scheme.upcase)
# 		@@schemes[scheme.upcase].new(scheme, userinfo, host, port, 
# 					   registry, path, opaque, query, 
# 					   fragment)
# 		else
# 		Generic.new(scheme, userinfo, host, port, 
# 			  registry, path, opaque, query, 
# 			  fragment)
# 		end
# 	end
# end
#
class Addrinfo
  #
  def self.parse(*args)
    # Attempts to create an address object for the given URI/URL
    address = nil
    if args[0].is_a?(::URI::Generic)
      raw_uri = args[0]
    else
      raw_uri = ::URI::parse(*args)
    end
    #
    the_protocol = nil
    the_port = nil
    service_details = ::GxG::SYSTEM.service_ports_search({:scheme => raw_uri.scheme()})
    if service_details.keys().size > 0
      service_details = service_details[(service_details.keys()[0])]
      if service_details[:usage_preference]
        if service_details[:usage][(service_details[:usage_preference])].is_a?(::Array)
          the_port = service_details[:usage][(service_details[:usage_preference])][0]
          if the_port.is_a?(::Range)
            the_protocol = (service_details[:usage_preference])
            the_port = the_port.first
          end
        end
      else
        if service_details[:usage][(service_details[:usage].keys()[0])].is_a?(::Array)
          the_port = service_details[:usage][(service_details[:usage].keys()[0])][0]
          if the_port.is_a?(::Range)
            the_protocol = (service_details[:usage].keys()[0])
            the_port = the_port.first
          end
        end
      end
    end
    unless the_protocol
      the_protocol = raw_uri.scheme().to_sym
    end
    #
    case the_protocol
    when :inproc
      #
    when :ipc
      # LATER: Anything to be done for IPC stuff here??? (Not available on winderz)
    when :pgm
      #
    when :epgm
      #
    when :unix, :socket
      if (raw_uri.hostname().to_s.size == 0)
        # Unix socket
        address = ::Addrinfo.unix(raw_uri.path())
      else
        # tcp used by default for ipc
        if raw_uri.hostname().to_s.size > 0
          address = ::Addrinfo.tcp(raw_uri.hostname(), (raw_uri.port() || raw_uri.default_port() || the_port || "*"))
        else
          address = ::Addrinfo.tcp("0.0.0.0", (raw_uri.port() || raw_uri.default_port() || the_port || "*"))
        end
      end
    when :tcp, :tcp4, :tcp6
      if raw_uri.hostname().to_s.size > 0
        address = ::Addrinfo.tcp(raw_uri.hostname(), (raw_uri.port() || raw_uri.default_port() || the_port || "*"))
      else
        address = ::Addrinfo.tcp("0.0.0.0", (raw_uri.port() || raw_uri.default_port() || the_port || "*"))
      end
    when :udp, :udp4, :udp6
      if raw_uri.hostname().to_s.size > 0
        address = ::Addrinfo.udp(raw_uri.hostname(), (raw_uri.port() || raw_uri.default_port() || the_port || "*"))
      else
        address = ::Addrinfo.udp("0.0.0.0", (raw_uri.port() || raw_uri.default_port() || the_port || "*"))
      end
    end
    #
    address
  end
  #
  def uri_info()
    result = nil
    if self.ip?()
      case self.protocol
      when ::Socket::IPPROTO_TCP
        result = ::URI::parse("tcp://#{self.ip_address()}:#{(self.ip_port() || '*')}")
      when ::Socket::IPPROTO_UDP
        result = ::URI::parse("udp://#{self.ip_address()}:#{(self.ip_port() || '*')}")
      end
    else
      if self.unix?()
        result = ::URI::parse("unix://#{self.unix_path()}")
      else
        # not sure what to do here
      end
    end
    result
  end
end
#
# Alteration to <string> class
class String
  # :macos text handling notes: http://hints.macworld.com/article.php?story=20060825071728278
  # Also, research UTF8_MAC <-> UTF8_HFS <-> UTF8 normalization conversions.
  def self.transcode_options(destination_encoding, source_encoding, options={})
    # TODO: ::String::transcode_options : complete transcoding back-end supports.
    # select a default encoding_option set given the two encodings, then merge options over that and return.  Explore Hash deep-merge ideas.
    #
    new_options = {}
    # fallback set/method or replace char
    if options[:fallback]
      # Note: I *confirmed* (thanks VGoff) that :invalid/:undef/:replace and :fallback are exclusive - So maybe this is really an optimized :fallback thing?
      #    Sets the replacement string by the given object for undefined character. The object should be a Hash, a Proc, a Method,
      #    or an object which has [] method. Its key is an undefined character encoded in the source encoding of current transcoder.
      #    Its value can be any encoding until it can be converted into the destination encoding of the transcoder.
      if (options[:fallback].is_any?(::Hash, ::Struct, ::Proc, ::Method) || options[:fallback].respond_to?(:[]))
        # if :fallback will not process an Array as mentioned above ... remove :[] respond_to? condition.
        new_options[:fallback] = options[:fallback].dup
      end
    else
      #
      if options[:invalid] == :replace
        #    If the value is :replace, encode replaces invalid byte sequences in str with the replacement character. The default is to
        #    raise the Encoding::InvalidByteSequenceError exception
        new_options[:invalid] = :replace
      end
      #
      if options[:undef] == :replace
        #    If the value is :replace, encode replaces characters which are undefined in the destination encoding with the replacement character.
        #    The default is to raise the Encoding::UndefinedConversionError.
        new_options[:undef] = :replace
      end
      #
      if options[:replace]
        #    Sets the replacement string to the given value. The default replacement string is “uFFFD” for Unicode encoding forms, and “?” otherwise.
        new_options[:replace] = options[:replace].dup
      end
      #
    end
    # xml
    if options[:xml]
      #    The value must be :text or :attr. If the value is :text encode replaces undefined characters with their (upper-case hexadecimal) numeric character
      #    references. ‘&’, ‘<’, and ‘>’ are converted to “&amp;”, “&lt;”, and “&gt;”, respectively. If the value is :attr, encode also quotes the replacement
      #    result (using ‘“’), and replaces ‘”’ with “&quot;”.
      if [:text, :attr].include?(options[:xml])
        new_options[:xml] = options[:xml].dup
      end
    end
    #
    if options[:universal_newline]
      #    Replaces CRLF (“rn”) and CR (“r”) with LF (“n”) if value is true.
      unless (new_options[:cr_newline] || new_options[:crlf_newline])
        if options[:universal_newline] == true
          new_options[:universal_newline] = true
        end
      end
    else
      if options[:crlf_newline]
        #    Replaces LF (“n”) with CRLF (“rn”) if value is true.
        unless (new_options[:cr_newline] || new_options[:universal_newline])
          if options[:crlf_newline] == true
            new_options[:crlf_newline] = true
          end
        end
      else
        if options[:cr_newline]
          #    Replaces LF (“n”) with CR (“r”) if value is true.
          unless (new_options[:crlf_newline] || new_options[:universal_newline])
            if options[:cr_newline] == true
              new_options[:cr_newline] = true
            end
          end
        else
          # default
        end
      end
    end
    #
    default_options = {}
    # find the default conversion options given the destination and source encodings
    # then ...
    new_options
    # deep-merge new_options into a provided default_options
    # then return default_options
    # default_options
  end
  #
  def transcode(*args)
    destination_encoding = nil
    conversion_options = nil
    if args.size > 0
      if args[0].is_a?(::Hash)
        conversion_options = args[0]
        if args[1].is_a?(::Encoding)
          destination_encoding = args[1]
        else
          destination_encoding = ::Encoding.default_external
        end
      else
        #
        if args[0].is_a?(::Encoding)
          destination_encoding = args[0]
          if args[1].is_a?(::Hash)
            conversion_options = args[1]
          else
            conversion_options = {}
          end
        end
      end
      args = nil
    end
    #
    unless destination_encoding.is_a?(::Encoding)
      raise ArgumentError, "You must provide a valid Encoding, instead you provided #{destination_encoding.class}"
    end
    unless conversion_options.is_a?(::Hash)
      raise ArgumentError, "You must provide a Hash for conversion options, instead you provided #{conversion_options.class}"
    end
    in_options = {}
    out_options = {}
    #
    if (conversion_options[:invalid] || conversion_options[:undef] || conversion_options[:replace])
      # Note: I *confirmed* (thanks VGoff) that :invalid/:undef/:replace and :fallback are exclusive. 
      # 
      # If the value is :replace, encode replaces invalid byte sequences in str with the replacement character. The default is to
      #    raise the Encoding::InvalidByteSequenceError exception
      if conversion_options[:invalid] == :replace
        in_options[:invalid] = :replace
        out_options[:invalid] = :replace
      end
      #    If the value is :replace, encode replaces characters which are undefined in the destination encoding with the replacement character.
      #    The default is to raise the Encoding::UndefinedConversionError.
      if conversion_options[:undef] == :replace
        in_options[:undef] = :replace
        out_options[:undef] = :replace
      end
      #
      #    Sets the replacement string to the given value. The default replacement string is “uFFFD” for Unicode encoding forms, and “?” otherwise.
      if conversion_options[:replace].is_a?(::String)
        in_options[:replace] = conversion_options[:replace]
        out_options[:replace] = conversion_options[:replace]
      end
      #
    else
      #    Sets the replacement string by the given object for undefined character. The object should be a Hash, a Proc, a Method,
      #    or an object which has [] method. Its key is an undefined character encoded in the source encoding of current transcoder.
      #    Its value can be any encoding until it can be converted into the destination encoding of the transcoder.
      if (conversion_options[:fallback].is_any?(::Hash, ::Struct, ::Proc, ::Method) || conversion_options[:fallback].respond_to?(:[]))
        # if :fallback will not process an Array as mentioned above ... remove :[] respond_to? condition.
        if conversion_options[:fallback].is_any?(::Proc, ::Method)
          # TODO: study arguments and output expected, and construct one in and one out proc as wrapper.
          # FIX: Odd Bug : MRI 1.9.3 will attempt to convert a Proc into a Hash directly and raise exception, instead of calling the proc.
          # Also, when a method is supplied: it does call it, but passes no data and I don't think even collects a response.  (wtf?) what is the point then??
          # So ... as a work around (FORNOW) I will simply construct a Hash and use that resultant Hash as fallback.
          # LATER: I think I'd like to add the above comparison to simply check for a .respond_to?(:call) on action objects.
          in_fallback = {}
          out_fallback = {}
          self.each_char do |the_char|
            dst_defined_char = conversion_options[:fallback].call(the_char).to_s.chars.first
            if (dst_defined_char.size > 0 && the_char != dst_defined_char)
              utf_bridge = the_char.encode(::Encoding::UTF_8)
              in_fallback[(the_char)] = utf_bridge
              out_fallback[(utf_bridge)] = dst_defined_char
            end
          end
          in_options[:fallback] = in_fallback
          out_options[:fallback] = out_fallback
        else
          if conversion_options[:fallback].is_any?(::Hash, ::Struct)
            #
            in_fallback = {}
            out_fallback = {}
            #
            conversion_options[:fallback].to_enum(:each_pair).each do |src_undefined_char,dst_defined_char|
              utf_bridge = src_undefined_char.encode(::Encoding::UTF_8)
              in_fallback[(src_undefined_char)] = utf_bridge
              out_fallback[(utf_bridge)] = dst_defined_char
            end
            #
            in_options[:fallback] = in_fallback
            out_options[:fallback] = out_fallback
          else
            if (conversion_options[:fallback].respond_to?(:[]) && conversion_options[:fallback].respond_to?(:to_a))
              in_fallback = {}
              out_fallback = {}
              the_data = conversion_options[:fallback].to_a.flatten
              the_size = the_data.size
              if (the_size.even? && the_size > 0)
                (0..(the_size)).step(2) do |index|
                  src_undefined_char = the_data[(index)]
                  dst_defined_char = the_data[(index + 1)]
                  utf_bridge = src_undefined_char.encode(::Encoding::UTF_8)
                  in_fallback[(src_undefined_char)] = utf_bridge
                  out_fallback[(utf_bridge)] = dst_defined_char
                end
              else
                # raise error?  this really requires matched pairs of things
              end
              in_options[:fallback] = in_fallback
              out_options[:fallback] = out_fallback
            end
          end
        end
      end
    end
    #
    #    The value must be :text or :attr. If the value is :text encode replaces undefined characters with their (upper-case hexadecimal) numeric character
    #    references. ‘&’, ‘<’, and ‘>’ are converted to “&amp;”, “&lt;”, and “&gt;”, respectively. If the value is :attr, encode also quotes the replacement
    #    result (using ‘“’), and replaces ‘”’ with “&quot;”.
    if [:text, :attr].include?(conversion_options[:xml])
      in_options[:xml] = conversion_options[:xml]
      out_options[:xml] = conversion_options[:xml]
    end
    #
    #    Replaces LF (“n”) with CR (“r”) if value is true.
    unless (conversion_options[:crlf_newline] || conversion_options[:universal_newline])
      if conversion_options[:cr_newline] == true
        in_options[:cr_newline] = true
        out_options[:cr_newline] = true
      end
    end
    #
    #    Replaces LF (“n”) with CRLF (“rn”) if value is true.
    unless (conversion_options[:cr_newline] || conversion_options[:universal_newline])
      if conversion_options[:crlf_newline] == true
        in_options[:crlf_newline] = true
        out_options[:crlf_newline] = true
      end
    end
    #
    #    Replaces CRLF (“rn”) and CR (“r”) with LF (“n”) if value is true.
    unless (conversion_options[:cr_newline] || conversion_options[:crlf_newline])
      if conversion_options[:universal_newline] == true
        in_options[:universal_newline] = true
        out_options[:universal_newline] = true
      end
    end
    # ###
    # the_string = self.encode(::Encoding::UTF_8,self.external_encoding,in_options)
    # the_string.encode!(destination_encoding,::Encoding::UTF_8,out_options)
    # --or--
    if self.encoding == ::Encoding::UTF_8
      the_string = self.dup
    else
      the_string = self.encode(::Encoding::UTF_8,self.encoding,in_options)
    end
    if destination_encoding != ::Encoding::UTF_8
      the_string.encode!(destination_encoding,::Encoding::UTF_8,out_options)
    end
    #
    the_string
  end
  #
  def transcode!(*args)
    data = self.transcode(*args)
    if data.is_a?(::String)
      self.force_encoding(data.encoding)
      self.replace(data)
    end
    self
  end
  #
  def to_d()
    ::BigDecimal.new(self)
  end
  #
  def numeric_values(categories=:any,delimiter="\t",locale=:en_US, numeric_base=10)
    results = []
    prepared = []
    # SOMEDAY: <string>.numeric_values: formulate regex patterns per locale and numeric_base
    quanta_pattern = /[a-zA-Z]*/
    # proposed: /^-{0,1}\d*\.{0,1}\d+$/
    # /^[-+]{0,1}\d*\.{0,1}\d+$/
    # old: /[0-9.,]*/
    numerical_pattern = /[-+0-9.,]*/
    self.to_enum(:each_line).each do |row_text|
      # ?? allow empty lines ??  I'm just not sure if I really *want* to attempt to preserve the structure that much.
      row_prep = []
      row_text.split(delimiter).to_enum.each do |column_text|
        if column_text.size > 0
          column_entry = {:text => column_text, :denomination => nil, :multiplier => nil}
          column_text.scan(quanta_pattern).to_enum.each do |quanta|
            if quanta.size > 0
              #
              interpretation = ::GxG::Units::interpret_units({:text => quanta,:categories => categories,:locale => locale, :base => numeric_base})
              #
              if interpretation[:error]
                raise interpretation[:error]
              else
                # SOMEDAY: <string>.numeric_values: a bit more discernment here than just the first interpretation.
                interpretation = interpretation[:result]
                if interpretation[0].is_a?(Hash)
                  if interpretation[0][:quantum].is_a?(Hash)
                    denomination = interpretation[0][:quantum].keys[0]
                    multiplier = interpretation[0][:quantum][(denomination)]
                    column_entry = {:text => column_text, :denomination => denomination, :multiplier => multiplier}
                    if interpretation[0][:attributes].is_a?(Hash)
                      column_entry[:attributes] = interpretation[0][:attributes]
                    end
                    break
                  end
                end
              end
              #
            end
            #
          end
          #
          row_prep << column_entry
          #
        else
          row_prep << nil
        end
      end
      prepared << row_prep
      #
    end
    # process prepared array
    prepared.to_enum.each do |row|
      results << row.to_enum.map do |column|
        result = nil
        if column.is_a?(Hash)
          column[:text].scan(numerical_pattern).to_enum.each do |text|
            text.gsub!(",","")
            if text.size > 0
              denomination = column[:denomination]
              multiplier = column[:multiplier]
              if text.include?(".")
                # Note: defaults *assume* base-10 numbers
                unless denomination
                  denomination = :float
                end
                unless multiplier
                  multiplier = 1.0
                end
                result = {}
                result[(denomination)] = text.to_f * multiplier.to_f
              else
                # Note: defaults *assume* base-10 numbers
                unless denomination
                  denomination = :integer
                end
                unless multiplier
                  multiplier = 1
                end
                result = {}
                result[(denomination)] = text.to_i * multiplier.to_i
              end
              if column[:attributes].is_a?(Hash)
                result.merge(column[:attributes])
              end
              break
            end
          end
        end
        result
      end
    end
    # unless it is a multi-line, or multi-column result, pass only the found denomination/value Hash.
    if results.size == 1
      # single row
      results = results[0]
      if results.size == 1
        # single column
        results = results[0]
      end
    end
    #
    results
  end
  #
  def valid_time?()
    # Parse for Time class
    instance = nil
    begin
      instance = ::Chronic::parse(self)
    rescue Exception
    end
    if instance.is_a?(::Time)
      true
    else
      false
    end
  end
  #
  def valid_date?()
    # Match for Date pattern
    if (/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/.match(self))
      true
    else
      false
    end
  end
  #
  def valid_datetime?()
    # Match for ISO 8601 pattern
    if (/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9][+-][0-9][0-9]:[0-9][0-9]/.match(self))
      true
    else
      false
    end
  end
  #
  def valid_datetime_nolocale?()
    # Match for not-so-much ISO 8601-ish pattern
    if (/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/.match(self))
      true
    else
      false
    end
  end
  #
  def valid_path?()
    if (/.*(?:\\|\/)(.+)$/.match(self) || (self.split(" ").size == 1 || self.split("/").size > 1 || self == "/"))
      true
    else
      false
    end
  end
  #
  def valid_jid?()
    # From Blather: /^(?:([^@]*)@)??([^@\/]*)(?:\/(.*?))?$/
    # From xmpp4r: /^(?:([^@\/<>\'\"]+)@)?([^@\/<>\'\"]+)(?:\/([^<>\'\"]*))?$/
    # Note: for now - using the one from Blather
    if /^(?:([^@]*)@)??([^@\/]*)(?:\/(.*?))?$/.match(self)
      true
    else
      false
    end
    # if /^(?:([^@]*)@)??([^@\/]*)(?:\/(.*?))?$/.match(self)
    #   true
    # else
    #   false
    # end
  end
  #
  def valid_mxid?()
    if /^[!@$#+][^:]+:.*$/.match(self)
      true
    else
      false
    end
  end
  #
  def camel_case?()
    # self.match(/([A-Z][a-z]+[A-Z][a-zA-Z]+)/)
    if self.match(/[A-Z]([A-Z0-9]*[a-z][a-z0-9]*[A-Z]|[a-z0-9]*[A-Z][A-Z0-9]*[a-z])[A-Za-z0-9]*/)      
      true
    else
      false
    end
  end
  #
  def split_camelcase()
    if self.camel_case?()
      self.split(/(?=[A-Z])/)
    else
      self
    end
  end
  #
  def mime_type()
    result = nil
    raw = ::MimeMagic.by_magic(::StringIO.new(self.clone))
    if raw
      result = {:type => (raw.type), :mediatype => (raw.mediatype), :subtype => (raw.subtype)}
    end
    result
  end
  #
  def xml?()
    declaration_test = self.include?("<?xml version=")
    parse_test = false
    if declaration_test
      begin
        mime = self.mime_type()
        if mime.is_a?(::Hash)
          if mime[:subtype] == "xml" || mime[:subtype] = "xhtml+xml"
            parse_test = true
          end
        end
      rescue Exception => the_error
      end
    end
    (declaration_test && parse_test)
  end
  #
  #  def from_xml(options={})
  #    #
  #    unless options[:no_test] == true
  #      unless self.xml?()
  #        raise Exception, "String is NOT formatted as XML."
  #      end
  #    end
  #    result = nil
  #    visit = Proc.new do |the_node=nil, accumulator=[]|
  #      node_stack = []
  #      if the_node
  #        node_stack.push(the_node)
  #        while (node_stack.size > 0) do
  #          a_node = node_stack.pop()
  #          # process(a_node)
  #          if a_node.is_a?(::Oga::XML::Text)
  #            accumulator << a_node.text()
  #          end
  #          if a_node.is_any?(::Oga::XML::Element, ::Oga::XML::Document)
  #            record = {:name => "document_root", :attributes => {}, :parent => nil, :object => nil, :path => "/", :assembled => false}
  #            if a_node.respond_to?(:name)
  #              record[:name] = a_node.name()
  #            end
  #            if a_node.respond_to?(:attributes)
  #              a_node.attributes.each do |the_attr|
  #                record[:attributes][(the_attr.name.to_s.to_sym)] = the_attr.value
  #              end
  #            end
  #            if a_node.respond_to?(:parent)
  #              record[:parent] = a_node.parent()
  #            else
  #              record[:parent] = a_node
  #            end
  #            record[:object] = a_node
  #            unless a_node.is_a?(::Oga::XML::Document)
  #              # set accumulator path
  #              #
  #            end
  #            accumulator << record
  #          end
  #          if a_node.children.size > 0
  #            a_node.children.each do |entry|
  #              node_stack.push(entry)
  #            end
  #          end
  #        end
  #      end
  #      accumulator
  #    end
  #    #
  #    begin
  #      if options[:sax] == true
  #        database = visit.call(::Oga::sax_parse_xml(self.transcode({:replace => "."},::Encoding::UTF_8)),[])
  #      else
  #        database = visit.call(::Oga::parse_xml(self.transcode({:replace => "."},::Encoding::UTF_8)),[])
  #      end
  #      link_db = []
  #      accumulator = []
  #      # Build link_db
  #      database.each do |the_node|
  #        if the_node.is_a?(::Hash)
  #          node_record = {}
  #          as_key = the_node[:name].to_s.to_sym
  #          if the_node[:object].is_a?(::Oga::XML::Document)
  #            node_record[(as_key)] = {:attributes => (the_node[:attributes]), :text => "", :children => []}
  #          else
  #            node_record[(as_key)] = {:attributes => (the_node[:attributes]), :text => (the_node[:object].text), :children => []}
  #          end
  #          link_record = {:desendents => [], :accumulator => (node_record[(as_key)][:children])}
  #          #
  #          database.each do |a_node|
  #            if a_node.is_a?(::Hash)
  #              if a_node[:parent].object_id == the_node[:object].object_id
  #                link_record[:desendents] << a_node[:object]
  #              end
  #            end
  #          end
  #          link_db << link_record
  #          if the_node[:parent].is_a?(::Oga::XML::Document)
  #            accumulator << node_record
  #          end
  #        else
  #          accumulator << the_node
  #        end
  #      end
  #      #
  #      while (link_db.size > 0) do
  #        entry = link_db.shift
  #        if entry.is_a?(::Hash)
  #          entry[:desendents].each do |node|
  #            unless node.is_a?(::Oga::XML::Document)
  #              if node.is_a?(::Oga::XML::Text)
  #                node_record = node.text
  #              else
  #                if node.is_a?(::Oga::XML::Comment)
  #                  node_record = {:comment => node.text}
  #                else
  #                  node_record = {}
  #                  as_key = node.name.to_s.to_sym
  #                  node_record[(as_key)] = {:attributes => {}, :text => (node.text), :children => []}
  #                  node.attributes.each do |the_attr|
  #                    node_record[(as_key)][:attributes][(the_attr.name.to_s.to_sym)] = the_attr.value
  #                  end
  #                  link_record = {:desendents => [], :accumulator => (node_record[(as_key)][:children])}
  #                  node.children.each do |node_descendent|
  #                    link_record[:desendents] << node_descendent
  #                  end
  #                  if link_record[:desendents].size > 0
  #                    link_db.push(link_record)
  #                  end
  #                end
  #              end
  #              #
  #              entry[:accumulator] << node_record
  #            end
  #          end
  #          #
  #        end
  #      end
  #      #
  #      result = accumulator
  #    rescue Exception => the_error
  #    end
  #    #
  #    result
  #  end
  #
  #  def from_xml_simple()
  #    if self.xml?
  #      the_hash = ::XmlSimple.xml_in(self)
  #      if the_hash.is_a?(::Hash)
  #        the_hash.symbolize_keys
  #        the_hash.process! do |value, selector, container|
  #          if value.is_a?(::String)
  #            item = value.numeric_values()
  #            if item.is_a?(::Hash)
  #              if item[:integer]
  #                item = item[:integer]
  #                container[(selector)] = item
  #              else
  #                if item[:float]
  #                  item = item[:float]
  #                  container[(selector)] = item
  #                end
  #              end
  #            else
  #              # Cast all time elements to ISO-8601
  #              if (value.valid_time? || value.valid_date? || value.valid_datetime? || value.valid_datetime_nolocale?)
  #                container[(selector)] = ::DateTime::parse(value.to_s)
  #              end
  #            end
  #          end
  #          nil
  #        end
  #      end
  #      the_hash
  #    else
  #      nil
  #    end
  #  end
  #
  def html?()
    declaration_test = (self.include?('<!DOCTYPE HTML') || self.include?('<!DOCTYPE html') || self.include?('<!DOCTYPE xhtml'))
    parse_test = false
    if declaration_test
      begin
        mime = self.mime_type()
        if mime.is_a?(::Hash)
          if ["html", "xhtml", "xhtml+xml"].include?(mime[:subtype])
            parse_test = true
          end
        end
      rescue Exception => the_error
      end
    end
    (declaration_test && parse_test)
  end
  #
  #  def from_html(options={})
  #    #
  #    unless options[:no_test] == true
  #      unless self.html?()
  #        raise Exception, "String is NOT formatted as HTML."
  #      end
  #    end
  #    result = nil
  #    visit = Proc.new do |the_node=nil, accumulator=[]|
  #      node_stack = []
  #      if the_node
  #        node_stack.push(the_node)
  #        while (node_stack.size > 0) do
  #          a_node = node_stack.pop()
  #          # process(a_node)
  #          if a_node.is_a?(::Oga::XML::Text)
  #            accumulator << a_node.text()
  #          end
  #          if a_node.is_any?(::Oga::XML::Element, ::Oga::XML::Document)
  #            record = {:name => "document_root", :attributes => {}, :parent => nil, :object => nil, :path => "/", :assembled => false}
  #            if a_node.respond_to?(:name)
  #              record[:name] = a_node.name()
  #            end
  #            if a_node.respond_to?(:attributes)
  #              a_node.attributes.each do |the_attr|
  #                record[:attributes][(the_attr.name.to_s.to_sym)] = the_attr.value
  #              end
  #            end
  #            if a_node.respond_to?(:parent)
  #              record[:parent] = a_node.parent()
  #            else
  #              record[:parent] = a_node
  #            end
  #            record[:object] = a_node
  #            unless a_node.is_a?(::Oga::XML::Document)
  #              # set accumulator path
  #              #
  #            end
  #            accumulator << record
  #          end
  #          if a_node.children.size > 0
  #            a_node.children.each do |entry|
  #              node_stack.push(entry)
  #            end
  #          end
  #        end
  #      end
  #      accumulator
  #    end
  #    #
  #    begin
  #      if options[:sax] == true
  #        database = visit.call(::Oga::sax_parse_html(self.transcode({:replace => "."},::Encoding::UTF_8)),[])
  #      else
  #        database = visit.call(::Oga::parse_html(self.transcode({:replace => "."},::Encoding::UTF_8)),[])
  #      end
  #      link_db = []
  #      accumulator = []
  #      # Build link_db
  #      database.each do |the_node|
  #        if the_node.is_a?(::Hash)
  #          node_record = {}
  #          as_key = the_node[:name].to_s.to_sym
  #          if the_node[:object].is_a?(::Oga::XML::Document)
  #            node_record[(as_key)] = {:attributes => (the_node[:attributes]), :text => "", :children => []}
  #          else
  #            node_record[(as_key)] = {:attributes => (the_node[:attributes]), :text => (the_node[:object].text), :children => []}
  #          end
  #          link_record = {:desendents => [], :accumulator => (node_record[(as_key)][:children])}
  #          #
  #          database.each do |a_node|
  #            if a_node.is_a?(::Hash)
  #              if a_node[:parent].object_id == the_node[:object].object_id
  #                link_record[:desendents] << a_node[:object]
  #              end
  #            end
  #          end
  #          link_db << link_record
  #          if the_node[:parent].is_a?(::Oga::XML::Document)
  #            accumulator << node_record
  #          end
  #        else
  #          accumulator << the_node
  #        end
  #      end
  #      #
  #      while (link_db.size > 0) do
  #        entry = link_db.shift
  #        if entry.is_a?(::Hash)
  #          entry[:desendents].each do |node|
  #            unless node.is_a?(::Oga::XML::Document)
  #              if node.is_a?(::Oga::XML::Text)
  #                node_record = node.text
  #              else
  #                if node.is_a?(::Oga::XML::Comment)
  #                  node_record = {:comment => node.text}
  #                else
  #                  node_record = {}
  #                  as_key = node.name.to_s.to_sym
  #                  node_record[(as_key)] = {:attributes => {}, :text => (node.text), :children => []}
  #                  node.attributes.each do |the_attr|
  #                    node_record[(as_key)][:attributes][(the_attr.name.to_s.to_sym)] = the_attr.value
  #                  end
  #                  link_record = {:desendents => [], :accumulator => (node_record[(as_key)][:children])}
  #                  node.children.each do |node_descendent|
  #                    link_record[:desendents] << node_descendent
  #                  end
  #                  if link_record[:desendents].size > 0
  #                    link_db.push(link_record)
  #                  end
  #                end
  #              end
  #              #
  #              entry[:accumulator] << node_record
  #            end
  #          end
  #          #
  #        end
  #      end
  #      #
  #      result = accumulator
  #    rescue Exception => the_error
  #    end
  #    #
  #    result
  #  end
  #
  def valid_uri?()
    result = false
    begin
      if ::URI::parse(self).is_a?(::URI::Generic)
        result = true
      end
    rescue Exception
    end
    result
  end
  #
  def to_uri()
    ::URI::parse(self)
  end
  #
  def slice_bytes(*args)
    # Return an ASCII_8BIT encoded sub-string
    result = nil
    the_range = nil
    if args[0].is_a?(Numeric)
      args[0] = args[0].to_i
      if args[0] < 0
        args[0] = self.bytesize + args[0]
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
          args[1] = self.bytesize + args[0].first
        else
          args[1] = args[0].first
        end
        if args[0].last < 0
          args[2] = self.bytesize + args[0].last
        else
          args[2] = args[0].last
        end
        if args[1] <= args[2]
          the_range = ((args[1])..(args[2]))
        else
          the_range = ((args[2])..(args[1]))
        end
      else
        raise ArgumentError.new("First parameter needs to be a Numeric or a Range, you provided #{args[0].inspect}")
      end
    end
    #
    if the_range
      result = ""
      result.force_encoding(::Encoding::ASCII_8BIT)
      #
      if self.encoding == ::Encoding::ASCII_8BIT
        if self.bytesize > 0
          if the_range.min != the_range.max
            result << self.slice(the_range)
          else
            result << self[(the_range.min)]
          end
        end
      else
        if self.bytesize > 0
          raw_text = self.clone
          raw_text.force_encoding(::Encoding::ASCII_8BIT)
          if the_range.min != the_range.max
            result << raw_text.slice(the_range)
          else
            result << raw_text[(the_range.min)]
          end
        end
      end
      #
    end
    result
  end
  #
  def byte_at(*args)
    # Random-access indexed byte value retrieval. Returns a Integer or nil.
    # why?  This is to pluck a single byte value out of a string as if it were merely a string of bytes. 1.8.7 used to provide a [] method for this purpose.
    if args[0].is_a?(Numeric)
      args[0] = args[0].to_i
    else
      raise ArgumentError.new("The parameter needs to be a Numeric, you provided #{args[0].inspect}")
    end
    if self.bytesize > 0
      if self.encoding == ::Encoding::ASCII_8BIT
        self[(args[0])].ord
      else
        self.slice_bytes(args[0])[0].ord
      end
    else
      nil
    end
  end
  #
  def bytes_at(*args)
    # Returns GxG::ByteArray
    unless args.size > 0
      args = [(0..-1)]
    end
    GxG::ByteArray.new(1,self.slice_bytes(*args))
  end
  #
  def unpack_bytes(format_template_string="")
    # See : http://ruby-doc.org/core-1.9.3/String.html#method-i-byteslice#This%20table%20summarizes
    GxG::ByteArray.new(self.unpack(format_template_string))
  end
  #
  # Note: documentation: recommend use of these methods and NOT those which they call to ensure cooperative event processing.
  # LATER: String: look into c code : is there a way to pluck a char off a string w/o using chars,bytes,codepoints,lines ?
  # This would afford an opportunity to override chars,bytes,codepoints and lines so that cooperative event processing was truly and invisibly supported.
  # This would be slower than the c code, but would let you load up gems w/o overriding another author's code to make it cooperative. (i.e. facets, etc)
  def each_line(separator=$/,&block)
    enumerator = self.lines(separator).to_enum
    if block.respond_to?(:call)
      enumerator.each do |item|
        block.call(item)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_line_with_index(separator=$/,offset=0,&block)
    enumerator = self.lines(separator).to_enum.with_index(offset)
    if block.respond_to?(:call)
      enumerator.each do |item,index|
        block.call(item,index)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_char(&block)
    enumerator = self.to_enum(:chars)
    if block.respond_to?(:call)
      enumerator.each do |item|
        block.call(item)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_char_with_index(offset=0,&block)
    # Thanks to Hanmac from IRC :)
    enumerator = self.to_enum(:chars).with_index(offset)
    if block.respond_to?(:call)
      enumerator.each do |item,index|
        block.call(item,index)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_byte(&block)
    enumerator = self.to_enum(:bytes)
    if block.respond_to?(:call)
      enumerator.each do |item|
        block.call(item)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_byte_with_index(offset=0,&block)
    # Thanks to Hanmac from IRC :)
    enumerator = self.to_enum(:bytes).with_index(offset)
    if block.respond_to?(:call)
      enumerator.each do |item,index|
        block.call(item,index)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_codepoint(&block)
    # String.codepoint will not return a GxG::Enumerator (non-blocking), so I'm providing these methods.
    enumerator = self.to_enum(:codepoints)
    if block.respond_to?(:call)
      enumerator.each do |item|
        block.call(item)
      end
      self
    else
      enumerator
    end
  end
  #
  def each_codepoint_with_index(offset=0,&block)
    enumerator = self.to_enum(:codepoints).with_index(offset)
    if block.respond_to?(:call)
      enumerator.each do |item,index|
        block.call(item,index)
      end
      self
    else
      enumerator
    end
  end
  # Encoding format detection and handling: Serialized, JSON & binhex(base64)
  def serialized?()
    if ((self[0..7].to_s == "marshal:" || self[0..9].to_s == "structure:") && (self[8..-1].to_s.base64?() || self[10..-1].to_s.base64?()))
      true
    else
      false
    end
  end
  #
  def unserialize()
    if self.serialized?()
      ::GxG::reconstitute(self)
    else
      self
    end
  end
  #
  def json_1?()
    self.slice(0,1) == '{'
  end
  #
  def json_2?()
    (self.json_1?() && (self.match('"apiVersion"\s?:\s?"2.0"') || false))
  end
  #
  def json?()
    self.json_1?() || self.json_2?()
  end
  #
  def from_json(symbolize_names = true)
    if self.json?
      the_object = ::JSON::parse(self,{:symbolize_names => symbolize_names})
      if the_object.is_any?(::Hash, ::Array)
        the_object.process! do |value, selector, container|
          if value.is_a?(::String)
            item = value.numeric_values()
            if item.is_a?(::Hash)
              if item[:integer]
                item = item[:integer]
                container[(selector)] = item
              else
                if item[:float]
                  item = item[:float]
                  container[(selector)] = item
                end
              end
            else
              if (value.valid_datetime? || value.valid_datetime_nolocale?)
                container[(selector)] = ::DateTime::parse(value)
              end
            end
            #
            if value[0..6] == "binary:" && value[7..-1].base64?
              container[(selector)] = GxG::ByteArray.new(value[7..-1].decode64)
            end
          end
          nil
        end
        #
      end
    else
      self
    end
  end
  # Base64 Stuff:
  def base64?()
    # RFC 4648
    # SOMEDAY: use regex based detection, current is open to some bugs.
    # See: http://ruby.about.com/od/advancedruby/ss/Base64-In-Ruby.htm
    # See: http://www.perlmonks.org/?node_id=775820
    # See: http://mattfaus.com/blog/2007/02/14/base64-regular-expression/
    # See: http://stackoverflow.com/questions/475074/regex-to-parse-or-validate-base64-data
    # Regex Testing: http://www.myregexp.com/signedJar.html
    # For now:
    begin
      # Review : So, for a work-around - keep adding exclusion tests to this conditional set as you discover them.      
      if (self.size > 0) && (not ["html","form","page","head","body","show","hide","play"].include?(self.downcase))
        # Review : *almost perfect* - words like 'html' 'form' 'page' get mangled because this regex senses they are base64 when they are not! (consult regex expert for remedy)
        if self.match(/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/)
          true
        else
          false
        end
      else
        false
      end
    rescue Exception => the_error
      false
    end
  end
  #
  def encode64()
    # RFC 4648
    ::Base64::strict_encode64(self)
  end
  #
  def decode64()
    # RFC 4648
    if self.base64?()
      ::Base64::strict_decode64(self)
    else
      self
    end
  end
  #
  def encode64!()
    data = self.encode64()
    if data != self
      self.replace(data)
    end
    self
  end
  #
  def decode64!()
    data = self.decode64()
    if data != self
      self.replace(data)
    end
    self
  end
  #
  def encrypt(withkey="")
    #
    if withkey.to_s.size > 0
      the_encoding = self.encoding()
      keybytes = ::GxG::ByteArray.new(withkey.to_s)
      container = ::GxG::ByteArray.new(self)
      #
      container.each_index do |index|
        the_value = container[(index)]
        #
        keybytes.each do |the_byte|
          [127,63,31,15,7,3,1,0].each do |the_bit|
            if the_byte > the_bit
              the_value += 1
              if the_value > 255
                the_value = 0
              end
            else
              the_value -= 1
              if the_value < 0
                the_value = 255
              end
            end
          end
        end
        #
        container[(index)] = the_value
      end
      #
      result = container.to_s
      result.force_encoding(the_encoding)
      result
    else
      self.dup
    end
  end
  #
  def encrypt_aes(withkey="",iv=nil)
    digest = Digest::SHA256.new
    digest.update(withkey)
    aes = OpenSSL::Cipher.new("AES-256-CBC")
    iv = OpenSSL::Cipher.new("AES-256-CBC").random_iv
    aes.encrypt
    aes.key = digest.digest
    aes.iv = iv
    cipher = aes.update(self)
    cipher << aes.final
    {:vector => iv, :data => cipher}
  end
  #
  def decrypt(withkey="")
    #
    if withkey.to_s.size > 0
      the_encoding = self.encoding()
      keybytes = ::GxG::ByteArray.new(withkey.to_s)
      container = ::GxG::ByteArray.new(self)
      #
      container.each_index do |index|
        the_value = container[(index)]
        #
        keybytes.each do |the_byte|
          [127,63,31,15,7,3,1,0].each do |the_bit|
            if the_byte > the_bit
              the_value -= 1
              if the_value < 0
                the_value = 255
              end
            else
              the_value += 1
              if the_value > 255
                the_value = 0
              end
            end
          end
        end
        #
        container[(index)] = the_value
      end
      #
      result = container.to_s
      result.force_encoding(the_encoding)
      result
    else
      self.dup
    end
  end
  #
  def decrypt_aes(withkey="", iv=nil)
    digest = Digest::SHA256.new
    digest.update(withkey)
    decode_cipher = OpenSSL::Cipher.new("AES-256-CBC")
    decode_cipher.decrypt
    decode_cipher.key = digest.digest
    decode_cipher.iv = iv
    plain = decode_cipher.update(self)
    plain << decode_cipher.final
    plain
  end
end
# Alteration to <Integer>.times block call loop
class Integer
  #
  #  def times(&block)
  #    if self > 0
  #      if block
  #        (1..(self)).to_enum.each do
  #          block.call
  #          # *should* use GxG::Enumerator, so no pause command needed here.
  #        end
  #        self
  #      else
  #        (1..(self)).to_enum(:times)
  #      end
  #    else
  #      self
  #    end
  #  end
  #  #
  #  def upto(number=nil,&block)
  #    if block.respond_to?(:call)
  #      if number.is_a?(::Numeric)
  #        number = number.to_i
  #        if self <= number
  #          ((self)..(number)).to_enum.each do |the_number|
  #            block.call(the_number)
  #          end
  #          self
  #        else
  #          number
  #        end
  #      else
  #        raise ArgumentError, "comparison of Fixnum and #{number.class} failed"
  #      end
  #    else
  #      self.to_enum(:upto,number)
  #    end
  #  end
  #  #
  #  def step(number=nil,skip=nil,&block)
  #    if block.respond_to?(:call)
  #      if number.is_a?(::Numeric)
  #        number = number.to_i
  #        if skip.is_any?(::Numeric,::NilClass)
  #          if skip
  #            skip = skip.to_i
  #          else
  #            skip = 1
  #          end
  #          #
  #          if self <= number
  #            current = self.dup
  #            while current <= number
  #              block.call(current)
  #              current += skip
  #              pause
  #            end
  #            self
  #          else
  #            number
  #          end
  #          #
  #        else
  #          raise ArgumentError, "comparison of #{number.class} and 0 failed"
  #        end
  #      else
  #        raise ArgumentError, "comparison of Fixnum and #{number.class} failed"
  #      end
  #    else
  #      if skip
  #        self.to_enum(:skip,number,skip)
  #      else
  #        self.to_enum(:skip,number)
  #      end
  #    end
  #  end
  #
  def to_d()
    ::BigDecimal.new(("%#{::Float::DIG}f" % self.to_f))
  end
end
# Alteration to Struct for support of structural processing:
#
class Struct
  #
  public
  def initialize_clone
    result = self.class.new
    self.each_pair do |key, value|
      result[(key)] = value.clone
    end
    result
  end
  alias :initialize_dup :initialize_clone
  alias :dup :initialize_clone
  def clone()
    initialize_clone
  end
  #
  def self.process(the_struct=::Struct.new(nil),&block)
    new_struct = ::Struct.new(nil)
    if block.respond_to?(:call)
      if the_struct.is_any?(::Array, ::Hash, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        new_struct = the_struct.process!(&block)
      else
        raise ArgumentError, "you must pass a Hash, or an Array, or a ByteArray, or a Set, or a Struct"
      end
    end
    new_struct
  end
  #
  def self.search(the_struct=::Struct.new(nil),&block)
    new_struct = ::Struct.new(nil)
    if block.respond_to?(:call)
      if the_struct.is_any?(::Array, ::Hash, ::Set, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        new_struct = the_struct.search(&block)
      else
        raise ArgumentError, "you must pass a Hash, or an Array, or a ByteArray, or a Set, or a Struct"
      end
    end
    new_struct
  end
  #
  #  def each_pair(&block)
  #    # ok, bizarre : this method is listed in instance_methods but is missing when called.  hrm.
  #    collection = {}
  #    self.members.to_enum.each do |key|
  #      collection[(key)] = (self[(key)])
  #    end
  #    if block.respond_to?(:call)
  #      collection.to_enum(:each_pair).each do |key,value|
  #        block.call(key,value)
  #      end
  #    else
  #      collection.to_enum(:each_pair)
  #    end
  #  end
  #
  def iterative(&block)
    result = []
    visit = Proc.new do |the_node=nil, accumulator=[]|
      node_stack = []
      if the_node
        node_stack << ({:parent => nil, :parent_selector => nil, :object => (the_node)})
        while (node_stack.size > 0) do
          a_node = node_stack.shift
          #
          if a_node[:object].is_any?(::Hash, ::Struct, ::GxG::Database::PersistedHash)
            a_node[:object].each_pair do |the_key, the_value|
              node_stack << ({:parent => a_node[:object], :parent_selector => the_key, :object => the_value})
            end
          end
          if a_node[:object].is_any?(::Array, ::GxG::Database::PersistedArray)
            a_node[:object].each_with_index do |the_value, the_index|
              node_stack << ({:parent => a_node[:object], :parent_selector => the_index, :object => the_value})
            end
          end
          #
          accumulator << a_node
        end
      end
      accumulator
    end
    #
    children_of = Proc.new do |the_db=[], the_parent=nil|
      list = []
      the_db.each do |node|
        if node[:parent].object_id == the_parent.object_id
          list << node
        end
      end
      list
    end
    #
    begin
      database = visit.call(self,[])
      link_db = children_of.call(database, self)
      if block.respond_to?(:call)
        while (link_db.size > 0) do
          entry = link_db.shift
          unless entry[:object].object_id == self.object_id
            # calls with parameters: the_value, the_key/the_index (the_selector), the_container
            raw_result = block.call(entry[:object], entry[:parent_selector], entry[:parent])
            if raw_result
              result << raw_result
            end
          end
          if entry[:object].object_id != nil.object_id
            children = children_of.call(database, entry[:object])
            children.each do |child|
              link_db << child
            end
          end
        end
      end
      #
    rescue Exception => the_error
      log_error({:error => the_error, :parameters => {}})
    end
    #
    result
  end
  #
  def process(&block)
    result = self.clone
    result.iterative(&block)
    result
  end
  #
  def process!(&block)
    self.iterative(&block)
    self
  end
  #
  def search(&block)
    results = []
    if block.respond_to?(:call)
      results = self.iterative(&block)
    end
    results
  end
  #
end
# Alteration to Hash and Array for support of structural processing:
# additional methods to address elements of, and process, structural combinations of Hashes, Arrays, and ByteArrays
# SOMEDAY: @Hash extend these to the pain-in-the-ass Struct class as well.
class Hash
  #
  def self.process(the_hash={},&block)
    new_hash = {}
    if block.respond_to?(:call)
      if the_hash.is_any?(::Array, ::Hash, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        new_hash = the_hash.process!(&block)
      else
        raise ArgumentError, "you must pass a Hash or an Array, or a ByteArray"
      end
    end
    new_hash
  end
  #
  def self.search(the_hash={},&block)
    new_hash = {}
    if block.respond_to?(:call)
      if the_hash.is_any?(::Array, ::Hash, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        new_hash = the_hash.search(&block)
      else
        raise ArgumentError, "you must pass a Hash or an Array, or a ByteArray"
      end
    end
    new_hash
  end
  # ### OpenStruct Integration
  def as_structure()
    ::OpenStruct.new(self)
  end
  #
  def iterative(&block)
    result = []
    visit = Proc.new do |the_node=nil, accumulator=[]|
      node_stack = []
      if the_node
        node_stack << ({:parent => nil, :parent_selector => nil, :object => (the_node)})
        while (node_stack.size > 0) do
          a_node = node_stack.shift
          #
          if a_node[:object].is_any?(::Hash, ::Struct, ::GxG::Database::PersistedHash)
            a_node[:object].each_pair do |the_key, the_value|
              node_stack << ({:parent => a_node[:object], :parent_selector => the_key, :object => the_value})
            end
          end
          if a_node[:object].is_any?(::Array, ::GxG::Database::PersistedArray)
            a_node[:object].each_with_index do |the_value, the_index|
              node_stack << ({:parent => a_node[:object], :parent_selector => the_index, :object => the_value})
            end
          end
          #
          accumulator << a_node
        end
      end
      accumulator
    end
    #
    children_of = Proc.new do |the_db=[], the_parent=nil|
      list = []
      the_db.each do |node|
        if node[:parent].object_id == the_parent.object_id
          list << node
        end
      end
      list
    end
    #
    begin
      database = visit.call(self,[])
      link_db = children_of.call(database, self)
      if block.respond_to?(:call)
        while (link_db.size > 0) do
          entry = link_db.shift
          unless entry[:object].object_id == self.object_id
            # calls with parameters: the_value, the_key/the_index (the_selector), the_container
            raw_result = block.call(entry[:object], entry[:parent_selector], entry[:parent])
            if raw_result
              result << raw_result
            end
          end
          if entry[:object].object_id != nil.object_id
            children = children_of.call(database, entry[:object])
            children.each do |child|
              link_db << child
            end
          end
        end
      end
      #
    rescue Exception => the_error
      log_error({:error => the_error, :parameters => {}})
    end
    #
    result
  end
  #
  def process(&block)
    result = self.clone
    result.iterative(&block)
    result
  end
  #
  def process!(&block)
    self.iterative(&block)
    self
  end
  #
  def search(&block)
    results = []
    if block.respond_to?(:call)
      results = self.iterative(&block)
    end
    results
  end
  #
  def paths_to(the_object=nil,base_path="")
    # new idea here:
    search_results = []
    unless base_path[0] == "/"
      base_path = ("/" << base_path)
    end
    if base_path.size > 1
      path_stack = base_path.split("/")[1..-1].reverse
    else
      path_stack = []
    end
    origin = self.get_at_path(base_path)
    container_stack = [{:selector => nil, :container => origin, :prefix => "/"}]
    find_container = Proc.new do |the_container|
      result = nil
      container_stack.each_with_index do |entry, index|
        if entry[:container] == the_container
          result = entry
          break
        end
      end
      result
    end
    last_container = origin
    found = false
    # tester = {:a=>1, :b=>2, :c=>[0, 5], :testing=>{:d=>4.0, :e=>0.9, :f => nil}}
    if origin.is_any?(::Hash, ::Array, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
      origin.process! do |the_value, selector, container|
        if last_container.object_id != container.object_id
          container_record = find_container.call(container)
          if container_record
            path_stack = container_record[:prefix].split("/").reverse
            if path_stack.size == 0
              path_stack << ""
            end
          end
          last_container = container
        end
        if selector.is_a?(Symbol)
          safe_key = (":" + selector.to_s)
        else
          safe_key = selector.to_s
        end
        safe_key = safe_key.gsub("/","%2f")
        path_stack.unshift(safe_key)
        # compare the_value
        found = false
        if (the_value == the_object)
          found = true
        end
        if found
          search_results << ("/" << path_stack.reverse.join("/"))
        end
        #
        if the_value.is_any?(::Array, ::Hash, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
          container_stack.unshift({:selector => selector, :container => the_value, :prefix => (path_stack.reverse.join("/"))})
        end
        path_stack.shift
        #
        nil
      end
    else
      search_results << ("/" << path_stack.join("/"))
    end
    search_results
  end
  #
  def get_at_path(the_path="/")
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
          else
            element = path_element
            element.gsub!("%2f","/")
            if element[0] == ":"
              element = element[(1..-1)].to_sym
            end
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
      container = self.get_at_path(::File::dirname(the_path))
      if container
        raw_selector = ::File::basename(the_path)
        selector = nil
        if raw_selector.size > 0
          if (raw_selector =~ /^(?:[0-9])*[0-9](?:[0-9])*$/) == 0
            selector = raw_selector.to_i
          else
            selector = raw_selector
            selector.gsub!("%2f","/")
            if selector[0] == ":"
              selector = selector[(1..-1)].to_sym
            end
          end
        end
        if selector
          container[(selector)] = the_value
          result = container[(selector)]
        else
          # ignore double slashes? '//'
          # break
        end
        #
      end
    end
    result
  end
  #
  def gxg_export()
    result = {:type => "Hash", :content => {}}
    export_db = [{:parent => nil, :parent_selector => nil, :object => self, :record => result}]
    children_of = Proc.new do |the_parent=nil|
      list = []
      export_db.each do |node|
        if node[:parent].object_id == the_parent.object_id
          list << node
        end
      end
      list
    end
    export_record = Proc.new do |the_value|
      if the_value.is_any?(Integer, Float, String)
        {:type => (the_value.class.to_s), :content => the_value}
      else
        {:type => (the_value.class.to_s), :content => the_value.to_s}
      end
    end
    # Build up export_db:
    self.search do |the_value, the_selector, the_container|
      if the_value.is_a?(::Hash)
        export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => "Hash", :content => {}}}
      else
        if the_value.is_a?(::Array)
          export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => "Array", :content => []}}
        else
          export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => export_record.call(the_value)}
        end
      end
    end
    # Collect children export content:
    link_db =[(export_db[0])]
    while link_db.size > 0 do
      entry = link_db.shift
      children_of.call(entry[:object]).each do |the_child|
        entry[:record][:content][(the_child[:parent_selector])] = the_child[:record]
        if the_child[:object].is_any?(Hash, Array)
          link_db << the_child
        end
      end
    end
    #
    result
  end
  #
  def self.gxg_import(the_exported_record=nil)
    result = nil
    if the_exported_record.is_a?(Hash)
      if the_exported_record[:type] == "Array"
        result = ::Array::gxg_import(the_exported_record)
      else
        import_value = Proc.new do |type,value|
          if value.is_a?(String)
            begin
              the_class = eval(type)
              if the_class.respond_to?(:parse)
                value = the_class.parse(value)
              else
                if the_class.respond_to?(:new)
                  value = the_class.new(value)
                else
                  if the_class.respond_to?(:try_convert)
                    value = the_class.try_convert(value)
                  end
                end
              end
            rescue Exception => the_error
            end
          end
          value
        end
        if the_exported_record[:type] == "Hash"
          result = {}
          import_db = [{:parent => nil, :parent_selector => nil, :object => result, :record => the_exported_record}]
          while import_db.size > 0 do
            entry = import_db.shift
            if entry[:record][:content].is_a?(Hash)
              entry[:record][:content].each_pair do |selector, value|
                if value[:type] == "Hash"
                  entry[:object][(selector)] = {}
                  import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                else
                  if value[:type] == "Array"
                    entry[:object][(selector)] = []
                    import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                  else
                    entry[:object][(selector)] = import_value.call(value[:type], value[:content])
                  end
                end
              end
            else
              if entry[:record][:content].is_a?(Array)
                entry[:record][:content].each_with_index do |value, selector|
                  if value[:type] == "Hash"
                    entry[:object][(selector)] = {}
                    import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                  else
                    if value[:type] == "Array"
                      entry[:object][(selector)] = []
                      import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                    else
                      entry[:object][(selector)] = import_value.call(value[:type], value[:content])
                    end
                  end
                end
              end
            end
          end
        else
          result = import_value.call(the_exported_record[:type], the_exported_record[:content])
        end
      end
    end
    result
  end
  #
  #  def to_xml_simple(options={})
  #    #      keyattr keeproot contentkey noattr rootname
  #    #      xmldeclaration outputfile noescape suppressempty
  #    #      anonymoustag indent grouptags noindent attrprefix
  #    the_options = {:xmldeclaration => true, :rootname => :root, :keeproot => false}
  #    if options.is_a?(::Hash)
  #      if options[:XmlDeclaration].is_any?(::TrueClass, ::FalseClass)
  #        the_options[:xmldeclaration] = options[:XmlDeclaration]
  #      end
  #      if options[:xmldeclaration].is_any?(::TrueClass, ::FalseClass)
  #        the_options[:xmldeclaration] = options[:xmldeclaration]
  #      end
  #      if options[:RootName].is_any?(::String, ::Symbol)
  #        the_options[:rootname] = options[:RootName]
  #      end
  #      if options[:rootname].is_any?(::String, ::Symbol)
  #        the_options[:rootname] = options[:rootname]
  #      end
  #      if options[:KeepRoot].is_any?(::TrueClass, ::FalseClass)
  #        the_options[:keeproot] = options[:KeepRoot]
  #      end
  #      if options[:keeproot].is_any?(::TrueClass, ::FalseClass)
  #        the_options[:keeproot] = options[:keeproot]
  #      end
  #    else
  #      raise ArgumentError, "You MUST provide options in the form of a Hash."
  #    end
  #    ::XmlSimple.xml_out(self, the_options).gsub("\n", "")
  #  end
  #
  #  def to_json()
  #    ::JSON.generate(self)
  #  end
  #
  def symbolize_keys()
    self.process! do |value, selector, container|
      if container.is_a?(::Hash)
        unless selector.is_a?(::Symbol)
          container[(selector.to_sym)] = container.delete(selector)
        end
      end
      nil
    end
    self
  end
  #
  #
end
#
class Array
  # Interesting research on extending ruby classes '|' for instance: http://verboselogging.com/2011/05/06/simple-ruby-pipes
  # Also: http://stackoverflow.com/questions/4234119/ruby-pipes-how-do-i-tie-the-output-of-two-subprocesses-together
  # And a *really* nice one: http://jstorimer.com/2012/03/18/a-unix-shell-in-ruby-pipes.html#Shell%20Pipelines%20Demystified
  #
  def self.process(the_array=[],&block)
    new_array = []
    if block.respond_to?(:call)
      if the_array.is_any?(::Array, ::Hash, ::GxG::ByteArray, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        new_array = the_array.process(&block)
      else
        raise ArgumentError, "you must pass a Array, a Hash, or a ByteArray"
      end
    end
    new_array
  end
  #
  def self.search(the_array=[],&block)
    new_array = []
    if block.respond_to?(:call)
      if the_array.is_any?(::Array, ::Hash, ::GxG::ByteArray, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        new_array = the_array.search(&block)
      else
        raise ArgumentError, "you must pass a Array, a Hash, or a ByteArray"
      end
    end
    new_array
  end
  #
  def iterative(&block)
    result = []
    visit = Proc.new do |the_node=nil, accumulator=[]|
      node_stack = []
      if the_node
        node_stack << ({:parent => nil, :parent_selector => nil, :object => (the_node)})
        while (node_stack.size > 0) do
          a_node = node_stack.shift
          #
          if a_node[:object].is_any?(::Hash, ::Struct, ::GxG::Database::PersistedHash)
            a_node[:object].each_pair do |the_key, the_value|
              node_stack << ({:parent => a_node[:object], :parent_selector => the_key, :object => the_value})
            end
          end
          if a_node[:object].is_any?(::Array, ::GxG::Database::PersistedArray)
            a_node[:object].each_with_index do |the_value, the_index|
              node_stack << ({:parent => a_node[:object], :parent_selector => the_index, :object => the_value})
            end
          end
          #
          accumulator << a_node
        end
      end
      accumulator
    end
    #
    children_of = Proc.new do |the_db=[], the_parent=nil|
      list = []
      the_db.each do |node|
        if node[:parent].object_id == the_parent.object_id
          list << node
        end
      end
      list
    end
    #
    begin
      database = visit.call(self,[])
      link_db = children_of.call(database, self)
      if block.respond_to?(:call)
        while (link_db.size > 0) do
          entry = link_db.shift
          unless entry[:object].object_id == self.object_id
            # calls with parameters: the_value, the_key/the_index (the_selector), the_container
            raw_result = block.call(entry[:object], entry[:parent_selector], entry[:parent])
            if raw_result
              result << raw_result
            end
          end
          if entry[:object].object_id != nil.object_id
            children = children_of.call(database, entry[:object])
            children.each do |child|
              link_db << child
            end
          end
        end
      end
      #
    rescue Exception => the_error
      log_error({:error => the_error, :parameters => {}})
    end
    #
    result
  end
  #
  def process(&block)
    result = self.clone
    result.iterative(&block)
    result
  end
  #
  def process!(&block)
    self.iterative(&block)
    self
  end
  #
  def search(&block)
    results = []
    if block.respond_to?(:call)
      results = self.iterative(&block)
    end
    results
  end
  #
  #
  def paths_to(the_object=nil,base_path="")
    # new idea here:
    search_results = []
    unless base_path[0] == "/"
      base_path = ("/" << base_path)
    end
    if base_path.size > 1
      path_stack = base_path.split("/")[1..-1].reverse
    else
      path_stack = []
    end
    origin = self.get_at_path(base_path)
    container_stack = [{:selector => nil, :container => origin}]
    find_container = Proc.new do |the_container|
      result = nil
      container_stack.each_with_index do |entry, index|
        if entry[:container] == the_container
          result = entry
          break
        end
      end
      result
    end
    last_container = origin
    found = false
    # tester = {:a=>1, :b=>2, :c=>[0, 5], :testing=>{:d=>4.0, :e=>0.9, :f => nil}}
    if origin.is_any?(::Hash, ::Array, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
      origin.process! do |the_value, selector, container|
        if last_container.object_id != container.object_id
          container_record = find_container.call(container)
          if container_record
            path_stack = container_record[:prefix].split("/").reverse
            if path_stack.size == 0
              path_stack << ""
            end
          end
          last_container = container
        end
        if selector.is_a?(Symbol)
          safe_key = (":" + selector.to_s)
        else
          safe_key = selector.to_s
        end
        safe_key.gsub!("/","%2f")
        path_stack.unshift(safe_key)
        # compare the_value
        found = false
        if (the_value == the_object)
          found = true
        end
        if found
          search_results << ("/" << path_stack.reverse.join("/"))
        end
        #
        if the_value.is_any?(::Array, ::Hash, ::Struct, ::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
          container_stack.unshift({:selector => selector, :container => the_value, :prefix => (path_stack.reverse.join("/"))})
        end
        path_stack.shift
        #
        nil
      end
    else
      search_results << ("/" << path_stack.join("/"))
    end
    search_results
  end
  #
  def get_at_path(the_path="/")
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
          else
            element = path_element
            element.gsub!("%2f","/")
            if element[0] == ":"
              element = element[(1..-1)].to_sym
            end
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
      container = self.get_at_path(::File::dirname(the_path))
      if container
        raw_selector = ::File::basename(the_path)
        selector = nil
        if raw_selector.size > 0
          if (raw_selector =~ /^(?:[0-9])*[0-9](?:[0-9])*$/) == 0
            selector = raw_selector.to_i
          else
            selector = raw_selector
            selector.gsub!("%2f","/")
            if selector[0] == ":"
              selector = selector[(1..-1)].to_sym
            end
          end
        end
        if selector
          container[(selector)] = the_value
          result = container[(selector)]
        else
          # ignore double slashes? '//'
          # break
        end
        #
      end
    end
    result
  end
  #
  def gxg_export()
    result = {:type => "Array", :content => []}
    export_db = [{:parent => nil, :parent_selector => nil, :object => self, :record => result}]
    children_of = Proc.new do |the_parent=nil|
      list = []
      export_db.each do |node|
        if node[:parent].object_id == the_parent.object_id
          list << node
        end
      end
      list
    end
    export_record = Proc.new do |the_value|
      if the_value.is_any?(Integer, Float, String)
        {:type => (the_value.class.to_s), :content => the_value}
      else
        {:type => (the_value.class.to_s), :content => the_value.to_s}
      end
    end
    # Build up export_db:
    self.search do |the_value, the_selector, the_container|
      if the_value.is_a?(::Hash)
        export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => "Hash", :content => {}}}
      else
        if the_value.is_a?(::Array)
          export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => "Array", :content => []}}
        else
          export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => export_record.call(the_value)}
        end
      end
    end
    # Collect children export content:
    link_db =[(export_db[0])]
    while link_db.size > 0 do
      entry = link_db.shift
      children_of.call(entry[:object]).each do |the_child|
        entry[:record][:content][(the_child[:parent_selector])] = the_child[:record]
        if the_child[:object].is_any?(Hash, Array)
          link_db << the_child
        end
      end
    end
    #
    result
  end
  #
  def self.gxg_import(the_exported_record=nil)
    result = nil
    if the_exported_record.is_a?(Hash)
      if the_exported_record[:type] == "Hash"
        result = ::Hash::gxg_import(the_exported_record)
      else
        import_value = Proc.new do |type,value|
          if value.is_a?(String)
            begin
              the_class = eval(type)
              if the_class.respond_to?(:parse)
                value = the_class.parse(value)
              else
                if the_class.respond_to?(:new)
                  value = the_class.new(value)
                else
                  if the_class.respond_to?(:try_convert)
                    value = the_class.try_convert(value)
                  end
                end
              end
            rescue Exception => the_error
            end
          end
          value
        end
        if the_exported_record[:type] == "Array"
          result = []
          import_db = [{:parent => nil, :parent_selector => nil, :object => result, :record => the_exported_record}]
          while import_db.size > 0 do
            entry = import_db.shift
            if entry[:record][:content].is_a?(Hash)
              entry[:record][:content].each_pair do |selector, value|
                if value[:type] == "Hash"
                  entry[:object][(selector)] = {}
                  import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                else
                  if value[:type] == "Array"
                    entry[:object][(selector)] = []
                    import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                  else
                    entry[:object][(selector)] = import_value.call(value[:type], value[:content])
                  end
                end
              end
            else
              if entry[:record][:content].is_a?(Array)
                entry[:record][:content].each_with_index do |value, selector|
                  if value[:type] == "Hash"
                    entry[:object][(selector)] = {}
                    import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                  else
                    if value[:type] == "Array"
                      entry[:object][(selector)] = []
                      import_db << {:parent => entry[:object], :parent_selector => selector, :object => entry[:object][(selector)], :record => value}
                    else
                      entry[:object][(selector)] = import_value.call(value[:type], value[:content])
                    end
                  end
                end
              end
            end
          end
        else
          result = import_value.call(the_exported_record[:type], the_exported_record[:content])
        end
      end
    end
    result
  end
  #
  def average()
    # See: https://stackoverflow.com/questions/1341271/how-do-i-create-an-average-from-a-ruby-array
    self.instance_eval { reduce(:+).to_f / size.to_f } 
  end
  #
end
# OpenStruct support for Arrays.
module GxG
  class ArrayWrapper
    # Review : match all public methods of a conventional array.
    def initialize(the_array=nil)
      @data = the_array
    end
    #
    def table()
      @data
    end
    #
    def [](*args)
      result = @data[*args]
      #
      if result.is_any?(::Array, ::GxG::Database::PersistedArray, ::GxG::Database::DetachedArray)
        result = ::GxG::ArrayWrapper.new(result)
      else
        if result.is_any?(::Hash, ::GxG::Database::PersistedHash, ::GxG::Database::DetachedHash)
          result = ::OpenStruct.new(result)
        end
      end
      #
      result
    end
    #
    def []=(the_index, the_value)
      if the_value.is_any?(::OpenStruct, ::GxG::ArrayWrapper)
        @data[(the_index)] = the_value.table
      else
        @data[(the_index)] = the_value
      end
    end
    #
    def shift()
      result = @data.shift
      #
      if result.is_any?(::Array, ::GxG::Database::PersistedArray, ::GxG::Database::DetachedArray)
        result = ::GxG::ArrayWrapper.new(result)
      else
        if result.is_any?(::Hash, ::GxG::Database::PersistedHash, ::GxG::Database::DetachedHash)
          result = ::OpenStruct.new(result)
        end
      end
      #
      result
    end
    #
    def unshift(the_value)
      if the_value.is_any?(::OpenStruct, ::GxG::ArrayWrapper)
        @data.unshift the_value.table
      else
        @data.unshift the_value
      end
    end
    #
    def pop()
      result = @data.pop
      #
      if result.is_any?(::Array, ::GxG::Database::PersistedArray, ::GxG::Database::DetachedArray)
        result = ::GxG::ArrayWrapper.new(result)
      else
        if result.is_any?(::Hash, ::GxG::Database::PersistedHash, ::GxG::Database::DetachedHash)
          result = ::OpenStruct.new(result)
        end
      end
      #
      result
    end
    #
    def push(the_value)
      if the_value.is_any?(::OpenStruct, ::GxG::ArrayWrapper)
        @data.push the_value.table
      else
        @data.push the_value
      end
    end
    #
    def each(&block)
      if block.respond_to?(:call)
        @data.each_index do |index|
          block.call(self[(index)])
        end
        self
      else
        self.to_enum(:each)
      end
    end
    #
    def each_index(&block)
      if block.respond_to?(:call)
        @data.each_index do |index|
          block.call(index)
        end
        self
      else
        self.to_enum(:each_index)
      end
    end
    #
    def each_with_index(&block)
      if block.respond_to?(:call)
        @data.each_index do |index|
          block.call(self[(index)], index)
        end
        self
      else
        self.to_enum(:each_with_index)
      end
    end
    #
    def first()
      self[0]
    end
    #
    def last()
      self[-1]
    end
    #
    def include?(the_value)
      result = false
      if the_value.is_any?(::OpenStruct, ::GxG::ArrayWrapper)
        the_value = the_value.table
      end
      @data.each do |element|
        if element == the_value
          result = true
          break
        end
      end
      result
    end
    #
    def find_index(the_value)
      result = nil
      if the_value.is_any?(::OpenStruct, ::GxG::ArrayWrapper)
        the_value = the_value.table
      end
      @data.each_with_index do |element, indexer|
        if element == the_value
          result = indexer
          break
        end
      end
      result
    end
    #
    def method_missing(the_method, *args)
      unless the_method.to_sym == :"[]" || the_method == :"[]="
        if @data.respond_to?(the_method.to_sym)
          @data.send(the_method.to_sym, *args)
        else
          begin
            super
          rescue NoMethodError => err
            err.backtrace.shift
            raise!
          end
        end
      end
    end
  end
  #
end
#
# OpenStruct Modifications to support nested structures.
class OpenStruct
  def new_ostruct_member!(name) # :nodoc:
    unless @table.key?(name) || is_method_protected!(name)
      define_singleton_method!(name) { self[name] }
      define_singleton_method!("#{name}=") {|x| self[name] = x}
    end
  end
  private :new_ostruct_member!
  #
  private def method_missing(mid, *args) # :nodoc:
    len = args.length
    if mname = mid[/.*(?==\z)/m]
      if len != 1
        raise! ArgumentError, "wrong number of arguments (given #{len}, expected 1)", caller(1)
      end
      if @table.respond_to?(mname.to_sym)
        @table.send(mname.to_sym, args[0])
      else
        set_ostruct_member_value!(mname, args[0])
      end
    elsif len == 0
      self[(mid)]
    else
      begin
        super
      rescue NoMethodError => err
        err.backtrace.shift
        raise!
      end
    end
  end
  #
  public
  #
  def [](name)
    if @table[name.to_sym].is_any?(::Hash, ::GxG::Database::PersistedHash, ::GxG::Database::DetachedHash)
      OpenStruct.new(@table[name.to_sym])
    else
      if @table[name.to_sym].is_any?(::GxG::Database::PersistedArray, ::GxG::Database::DetachedArray)
        @table[name.to_sym].as_structure(true)
      end
      @table[name.to_sym]
    end
  end
  #
  def []=(name, value)
    name = name.to_sym
    new_ostruct_member!(name)
    if @table[name].is_a?(::GxG::Database::PersistedHash)
      if ! value.is_a?(::GxG::Database::DetachedHash)
        if value.is_a?(::OpenStruct)
          if ! value.table.is_a?(::GxG::Database::DetachedHash)
            @table[name] = value.table
          else
            # makes a copy of the detached data
            @table[name] = value.table.unpersist()
          end
        else
          @table[name] = value
        end
      else
        # makes a copy of the detached data
        @table[name] = value.unpersist()
      end
    else
      if @table[name].is_a?(::GxG::Database::DetachedHash)
        if ! value.is_a?(::GxG::Database::PersistedHash)
          if value.is_a?(::OpenStruct)
            if ! value.table.is_a?(::GxG::Database::PersistedHash)
              @table[name] = value.table
            else
              # makes a copy of the persisted data
              @table[name] = value.table.unpersist()
            end
          else
            @table[name] = value
          end
        else
          # makes a copy of the persisted data
          @table[name] = value.unpersist()
        end
      else
        @table[name] = value
      end
    end
  end
  alias_method :set_ostruct_member_value!, :[]=
  private :set_ostruct_member_value!
  #
  def save()
    if @table.respond_to?(:save)
      @table.save()
    else
      false
    end
  end
  #
end
#