require 'pathname'

module GxG
  module Storage
    class BufferedSegments < ::StringIO
      #
      private
      def refresh_map()
        total = 0
        position = 0
        @map.each do |record|
          if record[:size] > 0
            record[:offset_range] = ((position)..(record[:size] - 1))
            position += (record[:size] - 1)
            total += record[:size]
          else
            record[:offset_range] = ((position)..(position))
          end
        end
        @total_length = total
      end
      #
      public
      def initialize(file_segments=nil)
        # 
        unless file_segments.is_a?(::GxG::Database::PersistedArray)
          raise ArgumentError, "You MUST provide a PersistedArray"
        end
        @read_buffer = ::GxG::ByteArray.new
        @write_buffer = ::GxG::ByteArray.new
        @data = file_segments
        @map = @data.element_byte_map(::GxG::ByteArray)
        @position = 0
        @total_length = 0
        refresh_map()
        super("")
        self
      end
      #
      def read(length = nil, outbuf = nil)
        eof = false
        if outbuf.is_a?(::String)
          result = outbuf
        else
          result = ::GxG::ByteArray.new
        end
        #
        if length.is_a?(::Integer)
          if length > 0
            if @total_length == 0
              eof = true
            else
              start_offset = @position
              if length > @total_length
                end_offset = (start_offset + (@total_length - 1))
              else
                end_offset = (start_offset + (length - 1))
              end
              @read_buffer.clear
              #
              @map.each do |record|
                if start_offset < record[:offset_range].first && start_offset < record[:offset_range].last
                  segment_start = 0
                end
                if start_offset >= record[:offset_range].first && start_offset <= record[:offset_range].last
                  segment_start = start_offset - record[:offset_range].first
                end
                if end_offset <= record[:offset_range].last && end_offset >= record[:offset_range].first
                  segment_end = (record[:size] - 1) - (record[:offset_range].last - end_offset)
                end
                if end_offset > record[:offset_range].last
                  segment_end = record[:size] - 1
                end
                @read_buffer << @data[(record[:index])][((segment_start)..(segment_end))].to_s
              end
              #
              @position += (@read_buffer.size)
              result << @read_buffer.to_s
              @read_buffer.clear
            end
          end
        else
          # return entire data length bytes
          @read_buffer.clear
          #
          @map.each do |record|
            @read_buffer << @data[(record[:index])].to_s
          end
          @position += (@read_buffer.size)
          result << @read_buffer.to_s
          @read_buffer.clear
        end
        #
        if eof == true
          nil
        else
          result.to_s
        end
      end
      #
      def seek(amount=nil, whence=::IO::SEEK_SET)
        unless amount.is_a?(::Integer)
          amount = 0
        end
        unless whence
          whence = ::IO::SEEK_SET
        end
        case whence
        when ::IO::SEEK_CUR
          @position += amount
        when ::IO::SEEK_END
          @position = @total_length + amount
        when ::IO::SEEK_SET
          @position = amount
        end
        0
      end
      #
      #  write(string, ...) → integer
      # syswrite(string) → integer
      # Appends the given string to the underlying buffer string. The stream must be opened for writing. If the argument is not a string, it will be converted to a string using to_s.
      # Returns the number of bytes written. See IO#write.
      def write(data=nil)
        result = 0
        @write_buffer.clear
        @write_buffer << data.to_s
        start_offset = @position
        end_offset = start_offset + @write_buffer.size - 1
        if start_offset > (@total_length - 1)
          @data << @write_buffer.clone
          @position += @write_buffer.size
          result = @write_buffer.size
          @write_buffer.clear
          refresh_map()
        else
          manifest = []
          cursor = 0
          @map.each_with_index do |record|
            if start_offset >= record[:offset_range].first && end_offset <= record[:offset_range].last
              # AT or Within
              src_start = cursor
              src_end = cursor + (end_offset - start_offset)
              dst_start = (start_offset - record[:offset_range].first)
              dst_end = dst_start + (src_end - src_start)
              manifest << {:op => :overwrite, :index => record[:index], :source_range => ((src_start)..(src_end)), :destination_range => ((dst_start)..(dst_end))}
              cursor += ((src_start)..(src_end)).size
            end
            if start_offset < record[:offset_range].first && end_offset >= record[:offset_range].first && end_offset <= record[:offset_range].last
              # Stradles Start
              src_start = cursor
              src_end = cursor + (end_offset - record[:offset_range].first)
              dst_start = 0
              dst_end = (end_offset - record[:offset_range].first)
              manifest << {:op => :overwrite, :index => record[:index], :source_range => ((src_start)..(src_end)), :destination_range => ((dst_start)..(dst_end))}
              cursor += ((src_start)..(src_end)).size
            end
            if start_offset >= record[:offset_range].first && end_offset >= record[:offset_range].last
              # Strandles End
              src_start = cursor
              src_end = cursor + (record[:offset_range].last - start_offset)
              dst_start = (start_offset - record[:offset_range].first)
              dst_end = dst_start + (src_end - src_start)
              manifest << {:op => :overwrite, :index => record[:index], :source_range => ((src_start)..(src_end)), :destination_range => ((dst_start)..(dst_end))}
              cursor += ((src_start)..(src_end)).size
            end
          end
          if end_offset > (@total_length - 1)
            src_start = cursor
            src_end = ((@write_buffer.size - 1) - cursor)
            @position += (end_offset - (@total_length - 1))
            manifest << {:op => :append, :source_range => ((src_start)..(src_end))}
          else
            @position += (end_offset + 1)
          end
          # Review : add truncate functionality to this method. (research)
          manifest.each do |record|
            if record[:op] == :overwrite
              segment = @data[(record[:index])]
              @write_buffer[(record[:source_range])].each_with_index do |the_byte, indexer|
                segment[(indexer + record[:destination_range].first)] = the_byte
              end
            end
            if record[:op] == :append
              @data << @write_buffer[(record[:source_range])]
            end
          end
          refresh_map()
          #
        end
        result
      end
      alias :syswrite :write
      #
      def rewind()
        @position = 0
        0
      end
      #
      def size()
        @total_length
      end
      #
    end
    #
    class FileSpace
      def initialize()
        @thread_safety = ::Mutex.new
        @mounted = []
      end
      #
      def subpath(src_path="", the_path="")
        if src_path == "/"
          the_path
        else
          src_path.each_char do |the_char|
            if the_char == the_path[0]
              the_path = the_path[(1..-1)]
            end
          end
          the_path
        end
      end
      #
      def path_prefix(src_path="", the_path="")
        result = ""
        src_path.each_char do |the_char|
          if the_char == the_path[0]
            the_path = the_path[(1..-1)]
            result << the_char
          else
            break
          end
        end
        result
      end
      #
      def volume_of_path(the_path="")
        result = nil
        @thread_safety.synchronize {
          @mounted.reverse.each do |volume_entry|
            if self.path_prefix(volume_entry[:path].to_s,the_path.to_s) == (volume_entry[:path].to_s)
              result = {:volume => volume_entry[:volume], :subpath => self.subpath(volume_entry[:path].to_s, the_path.to_s) }
              break
            end
          end
        }
        result
      end
      #
      def valid_path?(the_path="")
        result = false
        if the_path.to_s == "/"
          result = true
        else
          # VFS check
          path_table = []
          @thread_safety.synchronize {
              @mounted.reverse.each do |volume_entry|
              path_entry = volume_entry[:path].to_s.split("/")
              unless path_table.include?(path_entry)
                path_table << path_entry
              end
            end
          }
          path_array = the_path.to_s.split("/")
          vfs_check = false
          path_table.each do |entry|
            (0..(path_array.size - 1)).each do |indexer|
              if entry == (path_array[(0..(indexer))])
                vfs_check = true
                break
              end
            end
            if vfs_check
              break
            end
          end
          # volume check
          if vfs_check
            volume_record = self.volume_of_path(the_path.to_s)
            if volume_record
              result = volume_record[:volume].exist?(volume_record[:subpath].to_s)
            else
              result = true
            end
          end
          #
        end
        result
      end
      #
      def exist?(the_path="")
        self.valid_path?(the_path)
      end
      #
      def get_permissions(the_path="", the_credential=nil)
        result = []
        if self.valid_path?(the_path.to_s)
          if the_path.to_s == "/"
            volume_record = nil
          else
            volume_record = self.volume_of_path(the_path.to_s)
          end
          if volume_record
            result = volume_record[:volume].get_permissions(volume_record[:subpath].to_s, the_credential)
          end
        end
        result
      end
      #
      def revoke_permissions(the_path="", the_credential=nil)
        result = false
        if self.valid_path?(the_path.to_s)
          if the_path.to_s == "/"
            volume_record = nil
          else
            volume_record = self.volume_of_path(the_path.to_s)
          end
          if volume_record
            result = volume_record[:volume].revoke_permissions(volume_record[:subpath].to_s, the_credential)
          end
        end
        result
      end
      #
      #
      def set_permissions(the_path="", the_credential=nil, the_permissions={})
          result = false
          if self.valid_path?(the_path.to_s)
            if the_path.to_s == "/"
              volume_record = nil
            else
              volume_record = self.volume_of_path(the_path.to_s)
            end
            if volume_record
              result = volume_record[:volume].set_permissions(volume_record[:subpath].to_s, the_credential, the_permissions)
            end
          end
          result
      end
      #
      def profile(the_path="",params=nil)
        result = nil
        if self.valid_path?(the_path.to_s)
          if the_path.to_s == "/"
            volume_record = nil
          else
            volume_record = self.volume_of_path(the_path.to_s)
          end
          if volume_record
            if volume_record[:subpath].to_s.size > 0
              if params
                  result = volume_record[:volume].profile(volume_record[:subpath].to_s,params)
              else
                  result = volume_record[:volume].profile(volume_record[:subpath].to_s)
              end
              result[:title] = (the_path.split("/").last.to_s)
            else
              # VFS
              if params
                  base_profile = volume_record[:volume].profile(volume_record[:subpath].to_s,params)
              else
                  base_profile = volume_record[:volume].profile(volume_record[:subpath].to_s)
              end
              if base_profile
                result = {:title => "", :type => :virtual_directory, :owner_type => :virtual_directory, :uuid => nil, :on_device => nil, :on_device_major => nil, :on_device_minor => nil, :is_device => nil, :is_device_major => nil, :is_device_minor => nil, :inode => nil, :flags => [:read], :hardlinks_to => 0, :user_id => nil, :group_id => nil, :size => 0, :block_size => 0, :blocks => 0, :accessed => nil, :modified => nil, :status_modified => nil, :permissions => {:effective => {:execute => true, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read=>true}}, :mode=>nil}
                result[:title] = (the_path.split("/").last.to_s)
                result[:accessed] = DateTime.now
                if base_profile[:permissions][:effective][:write]
                  result[:permissions][:effective][:write] = true
                  result[:permissions][:effective][:create] = true
                end
              end
            end
          else
            # VFS Other
            result = {:title => "", :type => :virtual_directory, :owner_type => :virtual_directory, :uuid => nil, :on_device => nil, :on_device_major => nil, :on_device_minor => nil, :is_device => nil, :is_device_major => nil, :is_device_minor => nil, :inode => nil, :flags => [:read], :hardlinks_to => 0, :user_id => nil, :group_id => nil, :size => 0, :block_size => 0, :blocks => 0, :accessed => nil, :modified => nil, :status_modified => nil, :permissions => {:effective => {:execute => true, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read=>true}}, :mode=>nil}
            result[:title] = (the_path.split("/").last.to_s)
            result[:accessed] = DateTime.now
          end
        else
          begin
            raise Exception, "Path not found: #{the_path}"
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path}})
          end         
        end
        result
      end
      #
      def entries(the_path="", as_credential=nil)
        result = []
        if self.valid_path?(the_path.to_s)
          if the_path.to_s == "/"
            volume_record = nil
          else
            volume_record = self.volume_of_path(the_path.to_s)
          end
          #
          if volume_record
            result = volume_record[:volume].entries(volume_record[:subpath].to_s, as_credential)
            @mounted.each do |volume_entry|
              if (volume_entry[:path].to_s).include?(the_path) && volume_entry[:path].to_s != the_path
                result << self.profile(volume_entry[:path].to_s)
              end
            end
            result = result.sort {|a,b| a[:title] <=> b[:title]}
          else
            path_table = []
            @thread_safety.synchronize {
              @mounted.reverse.each do |volume_entry|
                path_entry = volume_entry[:path].to_s.split("/")
                unless path_table.include?(path_entry)
                  path_table << path_entry
                end
              end
            }
            if the_path == "/"
              offset = 1
            else
              offset = (the_path.to_s.split("/").size - 1)
            end
            #
            already = []
            path_table.each do |subpath|
              if self.path_prefix(the_path.to_s,subpath.join("/").to_s) == the_path.to_s
                if subpath[(offset)].to_s.size > 0
                  unless already.include?(subpath[(offset)].to_s)
                    the_profile = self.profile((the_path + "/" + subpath[(offset)].to_s).gsub("//","/"), {:with_credential => as_credential})
                    if the_profile
                      the_profile[:title] = (subpath[(offset)].to_s)
                      the_profile[:accessed] = DateTime.now
                      result << the_profile
                    end
                    already << subpath[(offset)].to_s
                  end
                end
              end
            end
            result = result.sort {|a,b| a[:title] <=> b[:title]}
            #
          end
          #
        else
          begin
            raise Exception, "Path not found: #{the_path}"
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path}})
          end
        end
        result
      end
      #
      def rmdir(the_path="")
        result = false
        if self.valid_path?(the_path.to_s)
          begin
            if the_path.to_s == "/"
              raise Exception, "You do not have destroy permissions here"
            else
              volume_record = self.volume_of_path(the_path.to_s)
            end
            if volume_record
              the_profile = self.profile(the_path.to_s)
              if the_profile
                if the_profile[:permissions][:effective][:destroy]
                  if [:virtual_directory, :directory, :persisted_array].include?(the_profile[:type])
                    result = volume_record[:volume].rmdir(volume_record[:subpath].to_s)
                  else
                    raise Exception, "Not a directory"
                  end
                else
                  raise Exception, "You do not have destroy permissions here. See unmount method."
                end
              else
                raise Exception, "Invalid path"
              end
              #
            else
              raise Exception, "Invalid path"
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path}})
          end
        else
          begin
            raise Exception, "Invalid path"
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path}})
          end
        end
        result
      end
      #
      def rmfile(the_path="")
        result = false
        if self.valid_path?(the_path.to_s)
          begin
            if the_path.to_s == "/"
              raise Exception, "You do not have destroy permissions here"
            else
              volume_record = self.volume_of_path(the_path.to_s)
            end
            if volume_record
              the_profile = self.profile(the_path.to_s)
              if the_profile
                if the_profile[:permissions][:effective][:destroy]
                  if [:virtual_directory, :directory, :persisted_array].include?(the_profile[:type])
                    raise Exception, "Not a valid :file or :persisted_hash"
                  else
                    result = volume_record[:volume].rmfile(volume_record[:subpath].to_s)
                  end
                else
                  raise Exception, "You do not have destroy permissions here. See unmount method."
                end
              else
                raise Exception, "Invalid path"
              end
              #
            else
              raise Exception, "Invalid path"
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path}})
          end
        else
          begin
            raise Exception, "Invalid path"
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path}})
          end
        end
        result
      end
      #
      def mkdir(the_path="", permissions=nil)
        result = false
        if self.valid_path?(the_path.to_s)
          result = true
        else
          if self.valid_path?(::File::dirname(the_path.to_s))
            if the_path.to_s == "/"
              volume_record = nil
            else
              volume_record = self.volume_of_path(the_path.to_s)
            end
            if volume_record
              result = volume_record[:volume].mkdir(volume_record[:subpath].to_s, permissions)
            else
              begin
                raise Exception, "You do not have sufficient priviledges to create here.  See the mount method."
              rescue Exception => the_error
                result = false
                log_error({:error => the_error, :parameters => {:path => the_path}})
              end
            end
          else
            begin
              raise Exception, "Invalid path to new directory"
            rescue Exception => the_error
              result = false
              log_error({:error => the_error, :parameters => {:path => the_path}})
            end
          end
        end
        result
      end
      #
      def mkpath(the_path="")
        result = false
        if the_path.to_s == ""
          the_path = "/"
        end
        if self.valid_path?(the_path.to_s)
          result = true
        else
          error_flag = false
          path_array = the_path.to_s.split("/")
          (0..(path_array.size - 1)).each do |indexer|
            temp_path = path_array[(0..(indexer))].join("/")
            if temp_path == ""
              temp_path = "/"
            end
            unless self.valid_path?(temp_path)
              unless self.mkdir(temp_path)
                error_flag = true
                break
              end
            end
          end
          unless error_flag
            result = true
          end
        end
        result
      end
      #
      def open(the_path="", options={})
        result = nil
        if self.valid_path?(the_path.to_s)
          if the_path.to_s == "/"
            volume_record = nil
          else
            volume_record = self.volume_of_path(the_path.to_s)
          end
          if volume_record
            result = volume_record[:volume].open(volume_record[:subpath].to_s, options)
          else
            begin
              raise Exception, "You do not have sufficient priviledges to open here."
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
            end
          end
        else
          begin
            raise Exception, "Invalid path"
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
          end
        end
        result
      end
      #
      def rename(the_path="", new_name="", options={})
        result = false
        if self.valid_path?(the_path.to_s)
          if the_path.to_s == "/"
            volume_record = nil
          else
            volume_record = self.volume_of_path(the_path.to_s)
          end
          if volume_record
            result = volume_record[:volume].rename(volume_record[:subpath].to_s, new_name, options)
          else
            begin
              raise Exception, "You do not have sufficient priviledges to rename here."
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
            end
          end
        else
          begin
            raise Exception, "Invalid path"
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
          end
        end
        result
      end
      #
      def mkfile(the_path="", options={})
        result = nil
        if self.valid_path?(the_path.to_s)
          result = self.open(the_path,options)
        else
          if self.valid_path?(::File::dirname(the_path.to_s))
            if the_path.to_s == "/"
              volume_record = nil
            else
              volume_record = self.volume_of_path(the_path.to_s)
            end
            if volume_record
              result = volume_record[:volume].open(volume_record[:subpath].to_s, options)
            else
              begin
                raise Exception, "You do not have sufficient priviledges to create here."
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
              end
            end
          else
            begin
              raise Exception, "Invalid path to new :file"
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
            end
          end
        end
        result
      end
      # Copying support:
      def copy(source_path=nil,destination_path=nil, options={})
        # Four scenarios: FS_to_FS, DB_to_DB, FS_to_DB, DB_to_FS
        # Objective: handle both file/object and directory/persisted_array in one method!
        # Does OVERWRITE copy onto existing files/folders of same name.
        result = false
        error = false
        if source_path == destination_path
          error = true
        end
        #
        source = {:enclosure => nil, :profile => nil, :record => nil, :permissions => nil}
        if self.valid_path?(source_path.to_s)
          if source_path.to_s == "/"
            source[:record] = nil
          else
            source[:record] = self.volume_of_path(source_path.to_s)
          end
          if source[:record]
            source[:profile] = self.profile(source_path,options.merge({:follow_symlinks => true}))
            source[:enclosure] = self.profile(File.dirname(source_path),options.merge({:follow_symlinks => true}))
            source[:permissions] = self.get_permissions(source_path)
          else
            error = true
            log_error({:error => Exception.new("You do not have sufficient priviledges."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
          end
        else
          error = true
          log_error({:error => Exception.new("Invalid source path"), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
        end
        # Note: if destination is not full path, but path to its future enclosure, append the filename to fully qualify the destination_path
        if File.basename(source_path) != File.basename(destination_path)
          destination_path = File.expand_path(destination_path + "/" + File.basename(source_path))
        end
        #
        destination = {:enclosure => self.profile(File.dirname(destination_path),options.merge({:follow_symlinks => true})), :profile => nil, :record => nil, :permissions => source[:permissions].clone}
        if self.valid_path?(destination_path.to_s)
          if destination_path.to_s == "/"
            destination[:record] = nil
          else
            destination[:record] = self.volume_of_path(destination_path.to_s)
          end
          if destination[:record]
            destination[:profile] = self.profile(destination_path,options.merge({:follow_symlinks => true}))
          else
            error = true
            log_error({:error => Exception.new("You do not have sufficient permissions."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
          end
        else
          if destination[:enclosure].is_a?(::Hash)
            unless destination[:enclosure][:permissions][:effective][:create] == true
              error = true
              log_error({:error => Exception.new("You do not have sufficient permissions to create at destination."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
            end
            unless error == true
              destination[:record] = self.volume_of_path(File.dirname(destination_path))
              if destination[:record].is_a?(::Hash)
                # Note: this won't exist yet, but is here for future reference.
                destination[:record][:subpath] = (destination[:record][:subpath] + "/" + File.basename(destination_path))
              end
            end
          else
            error = true
            log_error({:error => Exception.new("Invalid destination path"), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
          end
        end
        unless error == true
          if source[:profile]
            # determine permissions
            if source[:profile][:permissions][:effective][:read] == true
              # Does destination already exist? --> overwrite permissions?
              if destination[:profile]
                unless destination[:profile][:permissions][:effective][:write] == true
                  error = true
                  log_error({:error => Exception.new("You do not have sufficient permissions at destination."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})      
                end
              end
              unless error == true
                # determine copying scenario: FS_to_FS, DB_to_DB, FS_to_DB, DB_to_FS
                if source[:record][:volume].file_system?()
                  if destination[:enclosure][:uuid].to_s.size > 0
                    scenario = :FS_to_DB
                  else
                    scenario = :FS_to_FS
                  end
                else
                  if destination[:enclosure][:uuid].to_s.size > 0
                    scenario = :DB_to_DB
                  else
                    scenario = :DB_to_FS
                  end
                end
                # create source/destination path pairings:
                file_list = []
                dir_list = []
                if ["persisted_array","directory","virtual_directory"].include?(source[:profile][:type].to_s)
                  # directory / collection
                  search_queue = [{:source => (source_path), :destination => (destination_path)}]
                  while search_queue.size > 0 do
                    entry = search_queue.shift
                    if entry
                      self.entries(entry[:source]).each do |the_profile|
                        new_record = {:source => (entry[:source] + "/" + the_profile[:title]), :destination => (entry[:destination] + "/" + the_profile[:title]), :mode => the_profile[:mode], :mime => the_profile[:mime]}
                        if ["persisted_array","directory","virtual_directory"].include?(the_profile[:type].to_s)
                          dir_list << new_record
                          search_queue << new_record
                        else
                          file_list << new_record
                        end
                      end
                    end
                  end
                else
                  # single object
                  file_list << {:source => (source_path), :destination => (destination_path)}
                end
                # lay down dir structure
                dir_list.each do |the_record|
                  self.mkpath(the_record[:destination])
                end
                #
                case scenario
                when :FS_to_FS
                  # copy files one at a time.
                  file_list.each do |the_record|
                    if self.exist?(the_record[:destination])
                      self.rmfile(the_record[:destination])
                    end
                    # FIXME: find a way to preserve :mode (via REAL FS path) on new file.
                    begin
                      source_file = self.open(the_record[:source])
                      destination_file = self.mkfile(the_record[:destination])
                      if source_file && destination_file
                        GxG::apportioned_ranges(source_file.size,65536).each do |the_range|
                          source_file.seek(the_range.first)
                          destination_file.write(GxG::ByteArray.new(source_file.read(the_range.size)).to_s)
                        end
                        destination_file.close
                        source_file.close
                      else
                        raise Exception, "Error opening source or destination files."
                      end
                    rescue Exception => the_error
                      log_error({:error => the_error, :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})      
                      error = true
                      break
                    end
                  end
                  unless error == true
                    destination[:permissions].each do |the_entry|
                      self.set_permissions(destination_path, the_entry[:credential], the_entry[:permissions])
                    end
                    result = true
                  end
                when :FS_to_DB
                  file_list.each do |the_record|
                    begin
                      # Question: should I support an object import format from a text file ??
                      if File.extname(the_record[:source]) == ".gxg_export" && (the_record[:mime] == "application/octet-stream" || the_record[:mime] == "application/json")
                        source_file = self.open(the_record[:source])
                        #
                        import_record = source_file.read()
                        source_file.close
                        if import_record.to_s.json?
                          import_record = ::JSON::parse(import_record,{:symbolize_names => true})
                        end
                        if import_record.is_a?(::Hash)
                          database = nil
                          if destination[:record].is_a?(::Hash)
                            if destination[:record][:volume].is_a?(GxG::Storage::Volume)
                              database = destination[:record][:volume].database()
                            end
                          end
                          if database
                            enclosure_uuid = self.profile(File.dirname(the_record[:destination]))[:uuid].to_s.to_sym
                            destination_uuid = import_record[:record][:uuid].to_s.to_sym
                            # Import Formats first
                            if import_record[:formats].is_a?(::Hash)
                              op_frame = {:operation => :merge_format, :data => []}
                              import_record[:formats].keys.each do |the_format_key|
                                op_frame[:data] << import_record[:formats][(the_format_key)]
                              end
                              if op_frame[:data].size > 0
                                database.synchronize_records([(op_frame)],destination[:record][:volume].credential())
                              end
                            end
                            #
                            database.synchronize_records([{:operation => :merge, :data => [(import_record[:record])]}],destination[:record][:volume].credential())
                            #
                            unless self.exist?(the_record[:destination])
                              the_enclosure = database.retrieve_by_uuid(enclosure_uuid, destination[:record][:volume].credential())
                              the_enclosure.wait_for_reservation
                              destination_object = database.retrieve_by_uuid(destination_uuid, destination[:record][:volume].credential())
                              the_enclosure << destination_object
                              destination_object.deactivate
                              the_enclosure.release_reservation
                              the_enclosure.deactivate
                            end
                            #
                          else
                            raise Exception, "Error aquiring destination database."
                          end
                        else
                          raise Exception, "Error importing source file."
                        end
                      else
                        # Import the FS file into the DB as a org.gxg.file object
                        source_file = self.open(the_record[:source])
                        destination_object = self.open(the_record[:destination],{:format => "org.gxg.file"})
                        if source_file && destination_object
                          destination_object.wait_for_reservation
                          destination_object[:mime] = the_record[:mime]
                          if destination_object[:file_segments].size > 0
                            (0..(destination_object[:file_segments].size - 1)).to_a.reverse.each do |the_segment_index|
                              destination_object[:file_segments].delete_at(the_segment_index).destroy
                            end
                          end
                          GxG::apportioned_ranges(source_file.size,65536).each do |the_range|
                            source_file.seek(the_range.first)
                            destination_object[:file_segments] << GxG::ByteArray.new(source_file.read(the_range.size))
                            destination_object[:file_segments].save
                            destination_object[:file_segments].unload(destination_object[:file_segments].size - 1)
                          end
                          destination_object.release_reservation
                          destination_object.deactivate
                          source_file.close
                        else
                          if source_file
                            source_file.close
                            raise Exception, "Error opening destination object."
                          else
                            raise Exception, "Error opening source file & destination object."
                          end
                        end
                      end
                    rescue Exception => the_error
                      log_error({:error => the_error, :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})      
                      error = true
                      break
                    end
                  end
                  unless error == true
                    destination[:permissions].each do |the_entry|
                      self.set_permissions(destination_path, the_entry[:credential], the_entry[:permissions])
                    end
                    result = true
                  end
                when :DB_to_FS
                  file_list.each do |the_record|
                    begin
                      # Unless the object format is org.gxg.file --> export as .gxg_export object (formats + record)
                      source_object = self.open(the_record[:source])
                      database = source_object.db_address[:database]
                      # check if it is an org.gxg.file for export
                      current_format = nil
                      if source_object.format().to_s.size > 0
                        the_format = database.format_load({:uuid => source_object.format().to_s.to_sym})
                        if the_format[:ufs].to_s == "org.gxg.file"
                          current_format = the_format[:ufs].to_s
                        end
                      end
                      if current_format.to_s == "org.gxg.file"
                        destination_file = self.open(the_record[:destination])
                        source_object[:file_segments].each_with_index do |the_segment, segment_index|
                          destination_file.write(the_segment.to_s)
                          source_object[:file_segments].unload(segment_index)
                          # Field no longer exists: the_segment.unload
                        end
                        source_object.release_reservation
                        source_object.deactivate
                        destination_file.close
                      else
                        # Review: replace with <db>.sync_export(<uuid-array>).to_json
                        format_records = {}
                        object_record = source_object.export
                        object_record.search do |item,selector,container|
                            if selector == :format || selector == :constraint
                                if item.to_s.size > 0
                                    format_uuid = item
                                    unless format_records[(item.to_s.to_sym)].is_a?(::Hash)
                                        format_sample = database.format_load({:uuid => format_uuid.to_s.to_sym})
                                        format_sample[:content] = format_sample[:content].gxg_export()
                                        format_records[(format_uuid.to_s.to_sym)] = format_sample
                                    end
                                end
                            end
                        end
                        buffer = GxG::ByteArray.new({:formats => format_records, :record => object_record}.to_json)
                        #
                        unless File.extname(the_record[:destination]) == ".gxg_export"
                          the_record[:destination] = (File.dirname(the_record[:destination]) + "/" + File.basename(the_record[:destination]) + ".gxg_export")
                        end
                        if self.exist?(the_record[:destination])
                          self.rmfile(the_record[:destination])
                        end
                        destination_file = self.open(the_record[:destination])
                        destination_file.write(buffer.to_s)
                        destination_file.close
                      end
                      #
                    rescue Exception => the_error
                      log_error({:error => the_error, :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})      
                      error = true
                      break
                    end
                  end
                  unless error == true
                    destination[:permissions].each do |the_entry|
                      self.set_permissions(destination_path, the_entry[:credential], the_entry[:permissions])
                    end
                    result = true
                  end
                when :DB_to_DB
                  source_database = source[:record][:volume].database()
                  destination_database = destination[:record][:volume].database()
                  if source_database && destination_database
                    file_list.each do |the_record|
                      source_object = self.open(the_record[:source])
                      current_format = nil
                      if source_object.format().to_s.size > 0
                        the_format = source_database.format_load({:uuid => source_object.format().to_s.to_sym})
                        if the_format[:ufs].to_s == "org.gxg.file"
                          current_format = the_format[:ufs].to_s
                        end
                      end
                      #
                      if source_database == destination_database
                        if current_format.to_s == "org.gxg.file"
                          import_record = {:formats => {}, :record => source_object.export({:clone => true, :exclude_file_segments => true})}
                        else
                          import_record = {:formats => {}, :record => source_object.export({:clone => true})}
                        end
                      else
                        if current_format.to_s == "org.gxg.file"
                          import_record = {:formats => {}, :record => source_object.export({:exclude_file_segments => true})}
                        else
                          import_record = {:formats => {}, :record => source_object.export()}
                        end
                      end
                      # Gather format records for the object.
                      import_record.search do |item,selector,container|
                          if selector == :format || selector == :constraint
                              if item.to_s.size > 0
                                  format_uuid = item
                                  unless format_records[(item.to_s.to_sym)].is_a?(::Hash)
                                      format_sample = source_database.format_load({:uuid => format_uuid.to_s.to_sym})
                                      format_sample[:content] = format_sample[:content].gxg_export()
                                      format_records[(format_uuid.to_s.to_sym)] = format_sample
                                  end
                              end
                          end
                      end
                      #
                      enclosure_uuid = self.profile(File.dirname(the_record[:destination]))[:uuid].to_s.to_sym
                      destination_uuid = import_record[:record][:uuid].to_s.to_sym
                      if source_database != destination_database
                        # Import Formats first
                        if import_record[:formats].is_a?(::Hash)
                          op_frame = {:operation => :merge_format, :data => []}
                          import_record[:formats].keys.each do |the_format_key|
                            op_frame[:data] << import_record[:formats][(the_format_key)]
                          end
                          if op_frame[:data].size > 0
                            destination_database.synchronize_records([(op_frame)],destination[:record][:volume].credential())
                          end
                        end
                        #
                      end
                      #
                      if self.exist?(the_record[:destination])
                        # Why? Because an object of the same NAME, but differing format/content may be present (unacceptable)
                        self.rmfile(the_record[:destination])
                        # Risky, but avoids situation where: diff.db, same.uuid, gets deleted, then imported to deleted object (doh!)
                        destination_database.empty_trash
                      end
                      #
                      destination_database.synchronize_records([{:operation => :merge, :data => [(import_record[:record])]}],destination[:record][:volume].credential())
                      #
                      unless self.exist?(the_record[:destination])
                        the_enclosure = destination_database.retrieve_by_uuid(enclosure_uuid, destination[:record][:volume].credential())
                        the_enclosure.wait_for_reservation
                        destination_object = destination_database.retrieve_by_uuid(destination_uuid, destination[:record][:volume].credential())
                        if current_format.to_s == "org.gxg.file"
                          # copy file segments
                          destination_object.wait_for_reservation
                          source_object[:file_segments].each_with_index do |the_segment, segment_index|
                            destination_object[:file_segments] << ByteArray.new(the_segment.to_s)
                            destination_object[:file_segments].save
                            destination_object[:file_segments].unload(destination_object[:file_segments].size - 1)
                            # destination_object[:file_segments][(destination_object[:file_segments].size - 1)].save
                            # destination_object[:file_segments][(destination_object[:file_segments].size - 1)].unload
                            source_object[:file_segments].unload(segment_index)
                            # Field no longer exists : the_segment.unload
                          end
                          destination_object.release_reservation
                        end
                        the_enclosure << destination_object
                        destination_object.deactivate
                        the_enclosure.release_reservation
                        the_enclosure.deactivate
                      end
                      #
                    end
                    unless error == true
                      destination[:permissions].each do |the_entry|
                        self.set_permissions(destination_path, the_entry[:credential], the_entry[:permissions])
                      end
                      result = true
                    end
                  else
                    log_error({:error => Exception.new("Error aquiring source or destination database."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})      
                    error = true
                  end
                end
                #
              end
            else
              error = true
              log_error({:error => Exception.new("You do not have sufficient permissions."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
            end
          end
        end
        result
      end
      # Moving support
      def move(source_path=nil, destination_path=nil, options={})
        result = false
        error = false
        if source_path == destination_path
          error = true
        end
        #
        source = {:enclosure => nil, :profile => nil, :record => nil}
        if self.valid_path?(source_path.to_s)
          if source_path.to_s == "/"
            source[:record] = nil
          else
            source[:record] = self.volume_of_path(source_path.to_s)
          end
          if source[:record]
            source[:profile] = self.profile(source_path,options.merge({:follow_symlinks => true}))
            source[:enclosure] = self.profile(File.dirname(source_path),options.merge({:follow_symlinks => true}))
          else
            error = true
            log_error({:error => Exception.new("You do not have sufficient priviledges."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
          end
        else
          error = true
          log_error({:error => Exception.new("Invalid source path"), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
        end
        # Note: if destination is not full path, but path to its future enclosure, append the filename to fully qualify the destination_path
        if File.basename(source_path) != File.basename(destination_path)
          destination_path = File.expand_path(destination_path + "/" + File.basename(source_path))
        end
        #
        destination = {:enclosure => self.profile(File.dirname(destination_path),options.merge({:follow_symlinks => true})), :profile => nil, :record => nil}
        if self.valid_path?(destination_path.to_s)
          if destination_path.to_s == "/"
            destination[:record] = nil
          else
            destination[:record] = self.volume_of_path(destination_path.to_s)
          end
          if destination[:record]
            destination[:profile] = self.profile(destination_path,options.merge({:follow_symlinks => true}))
          else
            error = true
            log_error({:error => Exception.new("You do not have sufficient permissions."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
          end
        else
          if destination[:enclosure].is_a?(::Hash)
            unless destination[:enclosure][:permissions][:effective][:create] == true
              error = true
              log_error({:error => Exception.new("You do not have sufficient permissions to create at destination."), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
            end
            unless error == true
              destination[:record] = self.volume_of_path(File.dirname(destination_path))
              if destination[:record].is_a?(::Hash)
                # Note: this won't exist yet, but is here for future reference.
                destination[:record][:subpath] = (destination[:record][:subpath] + "/" + File.basename(destination_path))
              end
            end
          else
            error = true
            log_error({:error => Exception.new("Invalid destination path"), :parameters => {:source_path => source_path, :destination_path => destination_path, :options => options}})
          end
        end
        #
        unless error == true
          if source[:record][:volume].file_system?()
            if destination[:enclosure][:uuid].to_s.size > 0
              scenario = :FS_to_DB
            else
              scenario = :FS_to_FS
            end
          else
            if destination[:enclosure][:uuid].to_s.size > 0
              scenario = :DB_to_DB
            else
              scenario = :DB_to_FS
            end
          end
          if scenario == :DB_to_DB && (source[:record][:volume].database() == destination[:record][:volume].database())
            database = source[:record][:volume].database()
            source_enclosure = database.retrieve_by_uuid(source[:enclosure][:uuid].to_s.to_sym, source[:record][:volume].credential())
            source_enclosure.wait_for_reservation
            destination_enclosure = database.retrieve_by_uuid(destination[:enclosure][:uuid].to_s.to_sym, source[:record][:volume].credential())
            destination_enclosure.wait_for_reservation
            #
            source_enclosure.each_index do |the_index|
              if source_enclosure[(the_index)].uuid().to_s.to_sym == source[:profile][:uuid].to_s.to_sym
                destination_enclosure << source_enclosure.delete_at(the_index)
                break
              else
                source_enclosure[(the_index)].deactivate
              end
            end
            source_enclosure.release_reservation
            destination_enclosure.release_reservation
            source_enclosure.deactivate
            destination_enclosure.deactivate
            result = true
          else
            # copy to destination_path
            if self.copy(source_path, destination_path, options) == true
              # delete source_path object
              if ["directory","persisted_array"].include?(source[:profile][:type].to_s)
                result = self.rmdir(source_path)
              else
                result = self.rmfile(source_path)
              end
            end
          end
        end
        #
        result
      end
      #
      def mount(the_volume = nil, the_path = "")
        # Allow for a path to be mounted over the top of another - design choice
        if the_volume.is_a?(::GxG::Storage::Volume)
          @thread_safety.synchronize { @mounted << {:volume => the_volume, :path => ::Pathname.new(the_path.to_s)} }
          true
        else
          @mounted
        end
      end
      #
      def mounted?(the_path="")
        result = false
        @thread_safety.synchronize {
          @mounted.reverse.each do |entry|
            if entry[:path] == the_path
              result = true
              break
            end
          end
        }
        result
      end
      #
      def unmount(the_path="")
        # Allow for a path to be mounted over the top of another - design choice
        result = nil
        @thread_safety.synchronize {
          if @mounted.size > 0
            (0..(@mounted.size - 1)).to_a.reverse.each do |indexer|
              if the_path.to_s == (@mounted[(indexer)][:path].to_s)
                result = @mounted[(indexer)][:volume]
                @mounted.delete_at(indexer)
                break
              end
            end
          end
        }
        # returns the volume object for proper closing
        result
      end
      #
    end
    
    #
    class Volume
      #
      def inspect()
        "<Volume: #{(@database || @directory).inspect}>"
      end
      #
      def credential()
        @credential
      end
      #
      def database()
        @database
      end
      #
      def directory()
        @directory
      end
      #
      def file_system?()
        if self.directory()
          true
        else
          false
        end
      end
      # 
      def db_path(subpath="")
        result = nil
        unless subpath.to_s[0] == "/"
          subpath = ("/" << subpath.to_s)
        end
        subpath_array = subpath.to_s.split("/")
        if subpath_array.size == 0
          subpath_array << "Volume Root"
        else
          subpath_array[0] = "Volume Root"
        end
        path_array = [{:uuid => @root_uuid, :title => "Volume Root"}]
        subpath_array.each_with_index do |the_entry, indexer|
          parent_uuid = path_array.last[:uuid]
          #
          @database.connector()[:array_elements].filter({:parent_uuid => parent_uuid.to_s}).order(:ordinal).each do |item|
            if [:element_array, :element_hash].include?(item[:element].to_s.to_sym)
              if item[:element].to_s.to_sym == :element_array
                record = @database.connector()[:element_array].filter({:uuid => item[:element_array_uuid].to_s}).first
              else
                record = @database.connector()[:element_hash].filter({:uuid => item[:element_hash_uuid].to_s}).first
              end
              if record
                if record[:title] == subpath_array[(indexer + 1)].to_s
                  path_array << {:uuid => record[:uuid].to_sym, :title => record[:title]}
                  break
                end
              end
            end
          end
          #
        end
        if path_array.size == subpath_array.size
          result = path_array
        end
        result
      end
      #
      def exist?(subpath="")
        result = false
        if @directory
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          result = ::File::exist?(the_path)
        else
          # DB object exist?
          if self.db_path(subpath)
            result = true
          end
        end
        result
      end
      #
      def profile(subpath="",params={:follow_symlinks => true})
        unless params.is_a?(::Hash)
          params = {:follow_symlinks => true}
        end
        unless params[:follow_symlinks]
          unless params.keys.include?(:follow_symlinks)
            params[:follow_symlinks] = true
          end
        end
        platform_details = GxG::SYSTEM.platform()
        result = {:title => "", :type => :unspecified, :owner_type => :unspecified, :uuid => nil, :version => 0.0, :on_device => nil, :on_device_major => nil, :on_device_minor => nil, :is_device => nil, :is_device_major => nil, :is_device_minor => nil, :inode => nil, :flags => [:read], :hardlinks_to => 0, :user_id => nil, :group_id => nil, :size => 0, :block_size => 0, :blocks => 0, :accessed => nil, :modified => nil, :status_modified => nil, :permissions => {:effective => {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read=>false}}, :mode=>nil, :mime => nil}
        if @directory
          # return FS object profile
          result[:title] = (subpath.split("/").last.to_s)
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          if params[:follow_symlinks]
            raw_stat = ::File::stat(the_path.to_s)
          else
            raw_stat = ::File::lstat(the_path.to_s)
          end
          raw_mode = raw_stat.mode.to_s(base=8)
          # puts "Got: #{raw_mode}"
          if raw_mode.size < 6
            raw_mode = ("0" << raw_mode)
          end
          # puts "Then Got: #{raw_mode}"
          set_user_id = false
          set_group_id = false
          set_sticky_bit = false
          if (raw_mode[2].to_i & 4) == 4
            set_user_id = true
          end
          if (raw_mode[2].to_i & 2) == 2
            set_group_id = true
          end
          if (raw_mode[2].to_i & 1) ==  1
            set_sticky_bit = true
          end
          raw_permission = { :execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false }
          case raw_stat.ftype.to_s.downcase.to_sym
          when :link
            # are .lnk files handled properly on win32 for this?
            result[:type] =  :symlink
          when :file
             the_extension = ::File::basename(the_path.to_s).split(".")[-1].to_s.downcase
             if the_extension == "lnk"
               result[:type] =  :symlink
             else
               if ["so","la","a","dylib","dll","class"].include?(the_extension)
                 result[:type] =  :library
               else
                 if (["out","exe","misc","java","jar", "sh", "rb", "py", "pyc"].include?(the_extension) || raw_stat.executable_real?)
                   result[:type] =  :application
                 else
                   # TODO: find a way to externally sense if a tty
                   result[:type] = :file
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
          #
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
          # ### :file_id
          if ::GxG::SYSTEM.platform()[:platform] == :windows
            # FIX / Review : use Fiddle to call GetFileInformationByHandle from Kernel32.dll
            # See : https://docs.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information?redirectedfrom=MSDN
            # See : https://ruby-doc.org/stdlib-2.5.3/libdoc/fiddle/rdoc/Fiddle.html
            # FOR NOW : if you rename the file it will mess this idea up, but it's all I got for now.
            result[:file_id] = Digest::MD5.hexdigest(the_path).to_s
          else
            result[:file_id] = "#{(result[:on_device] || 0).to_s}-#{(result[:on_device_major] || 0).to_s}-#{(result[:on_device_minor] || 0).to_s}-#{(result[:inode] || 0).to_s}"
          end
          result[:flags] = []
          if ::File::writable_real?(the_path.to_s)
            result[:flags] << :write
          end
          if ::File::readable_real?(the_path.to_s)
            result[:flags] << :read
          end
          #
          result[:hardlinks_to] = raw_stat.nlink.to_i
          result[:user_id] = raw_stat.uid.to_i
          result[:group_id] = raw_stat.gid.to_i
          result[:size] = raw_stat.size
          result[:block_size] = raw_stat.blksize
          result[:blocks] = raw_stat.blocks
          result[:version] = raw_stat.mtime.to_f.to_d
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
          #
          # owner permissions
          if (raw_mode[3].to_i & 4) == 4
            result[:permissions][:owner][:read] = true
          end
          if (raw_mode[3].to_i & 2) == 2
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
          if (raw_mode[3].to_i & 1) == 1
            result[:permissions][:owner][:execute] = true
          end
          # group permissions
          if (raw_mode[4].to_i & 4) == 4
             result[:permissions][:group][:read] = true
          end
          if (raw_mode[4].to_i & 2) == 2
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
          if (raw_mode[4].to_i & 1) == 1
            result[:permissions][:group][:execute] = true
          end
          # other permissions
          if (raw_mode[5].to_i & 4) == 4
            result[:permissions][:other][:read] = true
          end
          if (raw_mode[5].to_i & 2) == 2
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
          if (raw_mode[5].to_i & 1) == 1
            result[:permissions][:other][:execute] = true
          end
          # effective (this user) permissions (while opened, supercedes normal effective file system permissions)
          if result[:flags].index(:read)
            result[:permissions][:effective][:read] = true
            #
          end
          # ### db-based virtualized permission system keyed by :file_id
          # ### on non-linux systems - make sure to support the :file_id format subsystem, and map to local-arch-platform equivilents.
          # search_database(credential, {:ufs => "the.ufs.code", :properties => [{:the_property => {:equals => value}}]})
          if ::GxG::valid_uuid?(params[:with_credential] || @credential)
            acts_as = :group
            current_roles = GxG::DB[:authority].user_roles(params[:with_credential] || @credential)
            current_roles.each do |role_record|
              unless GxG::DB[:roles][:vfs].vfs_permission_exist?(result[:file_id], role_record[:credential])
                if role_record[:credential] == GxG::DB[:authority][:system_credentials][:designers] || role_record[:credential] == GxG::DB[:authority][:system_credentials][:developers] || role_record[:credential] == GxG::DB[:authority][:system_credentials][:administrators]
                  GxG::DB[:roles][:vfs].create_vfs_permission(result[:file_id], role_record[:credential], result[:permissions][:owner])
                  acts_as = :owner
                else
                  GxG::DB[:roles][:vfs].create_vfs_permission(result[:file_id], role_record[:credential], result[:permissions][:group])
                end
                #
              end
            end
            #
            unless GxG::DB[:roles][:vfs].vfs_permission_exist?(result[:file_id], :"00000000-0000-4000-0000-000000000000")
              GxG::DB[:roles][:vfs].create_vfs_permission(result[:file_id], :"00000000-0000-4000-0000-000000000000", result[:permissions][:other])
            end
            # ### Review : should I support individual permissions at all, or rather confine it to roles and the public id?
            # unless GxG::DB[:roles][:vfs].vfs_permission_exist?(result[:file_id], (params[:with_credential] || @credential))
            #   if acts_as == :owner
            #     GxG::DB[:roles][:vfs].create_vfs_permission(result[:file_id], (params[:with_credential] || @credential), result[:permissions][:owner])
            #   else
            #     GxG::DB[:roles][:vfs].create_vfs_permission(result[:file_id], (params[:with_credential] || @credential), result[:permissions][:group])
            #   end
            # end
            #
            result[:permissions][:effective] = GxG::DB[:roles][:vfs].effective_vfs_permission(result[:file_id], (params[:with_credential] || @credential))
            #
          else
            log_error({:error => Exception.new("Invalid credential: #{params[:with_credential] || @credential}")})
          end
          result[:permissions].delete(:owner)
          result[:permissions].delete(:group)
          result[:permissions].delete(:other)
          #
          #
          # if @act_as.is_a?(::Symbol) || params[:with_credential]
          #   if ::GxG::valid_uuid?(params[:with_credential])
          #     if GxG::DB[:authority].role_member?(GxG::DB[:authority][:system_credentials][:administrators], params[:with_credential].to_s.to_sym)
          #       now_act_as = :owner
          #     else
          #       if GxG::DB[:authority].role_member?(GxG::DB[:authority][:system_credentials][:developers].to_s.to_sym, params[:with_credential].to_s.to_sym) || GxG::DB[:authority].role_member?(GxG::DB[:authority][:system_credentials][:designers].to_s.to_sym, params[:with_credential].to_s.to_sym)
          #         now_act_as = :group
          #       else
          #         now_act_as = :other
          #       end
          #     end
          #     result[:permissions][:effective] = result[:permissions][(now_act_as)].clone
          #   else
          #     result[:permissions][:effective] = result[:permissions][(@act_as)].clone
          #   end
          # else
          #   if result[:flags].index(:write)
          #     result[:permissions][:effective][:write] = true
          #     if platform_details[:platform] == :windows
          #       # :windows way of reading :rename, :move, and :destroy permission for file/directory.
          #     else
          #       result[:permissions][:effective][:rename] = true
          #       result[:permissions][:effective][:move] = true
          #       result[:permissions][:effective][:destroy] = true
          #       result[:permissions][:effective][:create] = true
          #     end
          #   end
          #   if raw_stat.executable?
          #     result[:permissions][:effective][:execute] = true
          #   end
          # end
          #
          result[:mode] = raw_mode
          # Mime type identification:
          if File.directory?(the_path)
            mime_type = "inode/directory"
          else
            mime_type = MimeMagic.by_extension(File.extname(result[:title]))
            unless mime_type
                mime_type = MimeMagic.by_path(the_path)
            end
            unless mime_type
              handle = ::File.open(the_path,"rb")
              handle.rewind
              mime_type = ::MimeMagic.by_magic(handle)
              handle.close
            end
            if mime_type
                mime_type = mime_type.type()
            else
                mime_type = "application/octet-stream"
            end
          end
          result[:mime] = mime_type
          #
          #
        else
          # return DB object profile
          unless subpath.to_s[0] == "/"
            subpath = ("/" << subpath.to_s)
          end
          #
          path_array = self.db_path(subpath.to_s)
          if path_array
            object_details = {:uuid => path_array.last[:uuid], :table => :unspecified, :dbid => 0}
            header = @database.connector()[:element_hash].filter({:uuid => object_details[:uuid].to_s}).first
            if header
              object_details[:table] = :element_hash
              object_details[:dbid] = header[:dbid]
            else
              header = @database.connector()[:element_array].filter({:uuid => object_details[:uuid].to_s}).first
              if header
                object_details[:table] = :element_array
                object_details[:dbid] = header[:dbid]
              end
            end
            #
            result = {:title => path_array.last[:title], :type => :virtual_directory, :owner_type => :virtual_directory, :uuid => path_array.last[:uuid], :version => ::BigDecimal.new(header[:version].to_s), :on_device => nil, :on_device_major => nil, :on_device_minor => nil, :is_device => nil, :is_device_major => nil, :is_device_minor => nil, :inode => nil, :file_id => nil, :flags => [:read], :hardlinks_to => 0, :user_id => nil, :group_id => nil, :size => 0, :block_size => 0, :blocks => 0, :accessed => nil, :modified => nil, :status_modified => nil, :permissions => {:effective => {:execute => true, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read=>true}}, :mode=>nil, :mime => nil}
            if object_details[:table] == :element_array
              result[:type] = :persisted_array
              result[:owner_type] = :persisted_array
            else
              result[:type] = :persisted_hash
              result[:owner_type] = :persisted_hash
            end
            if ::GxG::valid_uuid?(params[:with_credential])
              result[:permissions][:effective] = @database.effective_uuid_permission(object_details[:uuid], params[:with_credential])
            else
              result[:permissions][:effective] = @database.effective_uuid_permission(object_details[:uuid], @credential)
            end
            # Object Size in DB:
            if result[:type] == :persisted_hash
              # Review : DB overhaul - ensure @database.byte_size_by_uuid supports new arch.
              # result[:size] = @database.byte_size_by_uuid(object_details[:uuid])
            else
              # result[:size] = 0
            end
            # Pseudo-mime for objects:
            mime_type = nil
            if header[:format].to_s.size > 0
              the_format = @database.format_list({:uuid => header[:format]})[0]
              if the_format
                mime_type = "vnd.gxg/#{the_format[:ufs].to_s.gsub('_','-')}"
              else
                mime_type = "vnd.gxg/org.gxg.hash.persisted"
              end
            else
              if object_details[:table] == :element_array
                mime_type = "vnd.gxg/org.gxg.array.persisted"
              end
            end
            result[:mime] = mime_type
          else
            # raise Exception, "Invalid path"
          end
        end
        result
      end
      #
      def initialize(options={})
        # options: :directory => "/path/to/dir", :credential => <UUID>.to_s, :act_as => :owner? || :database => <GxG::Database::Database>, :credential => <UUID>.to_s, :root_uuid => <UUID>.to_s
        @thread_safety = ::Mutex.new
        @credential = GxG::DB[:administrator].to_s
        @database = nil
        @root_uuid = nil
        # Acts As: :owner, :group, :other for File System Volumes
        if [:owner, :group, :other].include?(options[:act_as])
          @act_as = options[:act_as]
        else
          @act_as = nil
        end
        @directory = options[:directory]
        if @directory.to_s.size > 0
          if ::GxG::valid_uuid?(options[:credential].to_s.to_sym)
            unless @act_as
              # set @act_as according to credential Group/Role membership: Administrators=:owner, Developers/Designers=:group, all others=:other
              if GxG::DB[:authority].role_member?(GxG::DB[:authority][:system_credentials][:administrators], options[:credential].to_s.to_sym)
                @act_as = :owner
              else
                if GxG::DB[:authority].role_member?(GxG::DB[:authority][:system_credentials][:developers].to_s.to_sym, options[:credential].to_s.to_sym) || GxG::DB[:authority].role_member?(GxG::DB[:authority][:system_credentials][:designers].to_s.to_sym, options[:credential].to_s.to_sym)
                  @act_as = :group
                else
                  @act_as = :other
                end
              end
            end
          end
          if ::Dir.exist?(@directory.to_s)
            if ::File.readable_real?(@directory.to_s)
              @directory = ::Dir.new(@directory.to_s)
            else
              raise Exception, "You do not have read permissions to directory #{@directory.inspect}."
            end
          else
            raise Exception, "Directory #{@directory.inspect} does not exist in the filesystem."
          end
          #
        else
          @credential = (options[:credential] || GxG::DB[:administrator]).to_s
          if options[:database].is_a?(::GxG::Database::Database) and @credential.size > 0
            @database = options[:database]
            if @database.setting_keys.include?(:volume_information)
              vol_info = @database[:volume_information]
            else
              if @database.db_permissions()[:write]
                new_root = @database.try_persist([], @credential)
                if new_root
                  new_root.wait_for_reservation()
                  new_root.set_title("Volume Root")
                  new_root.set_permissions(@credential, {:destroy => false, :move => false, :rename => false, :create => true, :write => true})
                  vol_info = {:volume_root => new_root.uuid()}
                  new_root.deactivate
                  @database[:volume_information] = vol_info
                else
                  raise Exception, "Unable to initialize volume root"
                end
              else
                raise Exception, "Cannot initialize Volume Information on read-only database."
              end
            end
            # One can specify a sub-array to the volume as this volume's root array.
            if GxG::valid_uuid?(options[:root_uuid].to_s)
                # verify array's existence
                the_persisted_array = @database.retrieve_by_uuid(options[:root_uuid], @credential)
                if the_persisted_array.is_a?(::GxG::Database::PersistedArray)
                    the_persisted_array.deactivate
                    @root_uuid = options[:root_uuid].to_s.to_sym
                else
                    raise Exception, "The root_uuid points to a non-existent or invalid object, or you do not have permissions to read it."
                end
                #
            else
                @root_uuid = vol_info[:volume_root].to_sym
            end
          else
            raise ArgumentError, "You MUST supply a valid credential and a database object.  :credential => #{@credential.inspect}, :database => #{options[:database].inspect}"
          end
        end
        #
      end
      #
      def entries(subpath="", as_credential=nil, options={:follow_symlinks => true})
        results = []
        if @directory
          # FS
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          ::Dir::entries(the_path).each do |item|
            unless [".", ".."].include?(item)
              if as_credential
                the_profile = self.profile((subpath + "/" + item), options.merge({:with_credential => as_credential}))
              else
                the_profile = self.profile((subpath + "/" + item), options)
              end
              if the_profile
                the_profile[:title] = item
                results << the_profile
              end
            end
          end
          #
        else
          # DB
          unless subpath.to_s[0] == "/"
            subpath = ("/" << subpath.to_s)
          end
          path_array = self.db_path(subpath.to_s)
          if path_array
            base_profile = self.profile(subpath.to_s, {:with_credential => as_credential})
            if base_profile
              if base_profile[:permissions][:effective][:read]
                if base_profile[:type] == :persisted_array
                  object_details = {:uuid => path_array.last[:uuid], :table => :unspecified, :dbid => 0}
                  header = @database.connector()[:element_array].filter({:uuid => object_details[:uuid].to_s}).first
                  if header
                    object_details[:table] = :element_array
                    object_details[:dbid] = header[:dbid]
                  end
                  contained_titles = []
                  @database.connector()[:array_elements].select(:element_hash_uuid, :element_array_uuid).where({:parent_uuid => path_array.last[:uuid].to_s}).each do |link_record|
                    if link_record[:element_hash_uuid].to_s.size > 0
                      header = @database.connector()[:element_hash].filter({:uuid => link_record[:element_hash_uuid].to_s}).first
                      if header
                        contained_titles << header[:title].to_s
                      end
                    else
                      if link_record[:element_array_uuid].to_s.size > 0
                        header = @database.connector()[:element_array].filter({:uuid => link_record[:element_array_uuid].to_s}).first
                        if header
                          contained_titles << header[:title].to_s
                        end
                      end
                    end
                  end
                  contained_titles.sort.each do |the_title|
                    if the_title.size > 0
                      results << self.profile((subpath.to_s + "/" + the_title).gsub("//","/"), {:with_credential => as_credential})
                    end
                  end
                end
              end
            end
          end
        end
        results
      end
      #
      def rmdir(subpath="")
        result = false
        if @directory
          # FS rmdir
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          #
          if ::File::exist?(the_path)
            begin
              the_profile = self.profile(subpath.to_s)
              if the_profile
                if the_profile[:permissions][:effective][:destroy]
                  # Recursively delete any content files and subdirs first
                  file_list = []
                  dir_list = []
                  vfs_list = [ (the_profile[:file_id]) ]
                  # Gather up all VFS-DB :file_id entries:
                  search_queue = [(subpath)]
                  while search_queue.size > 0 do
                    entry = search_queue.shift
                    self.entries(entry).each do |the_subitem_profile|
                      if the_subitem_profile[:file_id].to_s.size > 0
                        vfs_list << the_subitem_profile[:file_id]
                      end
                      if [:virtual_directory, :persisted_array, :directory].include?(the_subitem_profile[:type])
                        search_queue << (entry + "/" + the_subitem_profile[:title])
                      end
                    end
                  end
                  # Do the FS work:
                  search_queue = [(the_path)]
                  while search_queue.size > 0 do
                    entry = search_queue.shift
                    if entry
                      Dir.entries(entry).each do |the_item_name|
                        unless [".",".."].include?(the_item_name)
                          if File.directory?(entry + "/" + the_item_name)
                            dir_list << (entry + "/" + the_item_name)
                            search_queue << (entry + "/" + the_item_name)
                          else
                            file_list << (entry + "/" + the_item_name)
                          end
                        end
                      end
                    end
                  end
                  file_list.each do |the_file_path|
                    File.delete(the_file_path)
                  end
                  dir_list.each do |the_dir_path|
                    ::Dir::rmdir(the_dir_path)
                  end
                  if ::Dir::rmdir(the_path) == 0
                    vfs_list.each do |the_file_id|
                      GxG::DB[:roles][:vfs].destroy_vfs_permission(the_file_id)
                    end
                    result = true
                  end
                else
                  raise Exception, "You do not have destroy permissions to do this"
                end
              else
                raise Exception, "Inavalid path"
              end
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path}})
            end
          else
            begin
              raise Exception, "Invaid path"
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path}})
            end
          end
          #
        else
          # DB rmdir
          unless subpath.to_s[0] == "/"
            subpath = ("/" << subpath.to_s)
          end
          path_array = self.db_path(subpath.to_s)
          if path_array
            if path_array.size > 1
              the_profile = self.profile(subpath.to_s)
              if the_profile
                if the_profile[:permissions][:effective][:destroy]
                  parent_uuid = (path_array[-2] || {})[:uuid]
                  link_uuids = []
                  found_link = nil
                  if parent_uuid
                    @database.connector()[:array_elements].filter({:parent_uuid => parent_uuid.to_s}).order(:ordinal).each do |link_record|
                      header = nil
                      if link_record[:element_array_uuid].to_s.size > 0
                        header = @database.connector()[:element_array].filter({:uuid => link_record[:element_array_uuid].to_s}).first
                      end
                      if header
                        if header[:uuid] == path_array.last[:uuid] && header[:title] == path_array.last[:title]
                          found_link = {:uuid => header[:uuid], :linkid => link_record[:dbid]}
                        else
                          link_uuids << {:uuid => header[:uuid], :linkid => link_record[:dbid]}
                        end
                      end
                    end
                    if found_link
                      # Review : how to deal with lots of users deleting objects at once??
                      if @database.destroy_by_uuid(@credential, found_link[:uuid].to_sym) == true
                        # ### Delete array_elements link of id ...
                        @database.connector()[:array_elements].filter({:dbid => found_link[:linkid]}).delete
                        # ### Reset ordinals of array_elements links. (Even though VFS.entries sorts results)
                        link_uuids.each_with_index do |link_record, ordinal|
                          @database.connector()[:array_elements].filter({:dbid => found_link[:linkid]}).update({:ordinal => ordinal})
                        end
                      end
                    end
                  end
                else
                  begin
                    raise Exception, "You do not have permissions to destroy this object"
                  rescue Exception => the_error
                    log_error({:error => the_error, :parameters => {:path => subpath}})
                  end
                end
              else
                begin
                  raise Exception, "Invalid path"
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:path => subpath}})
                end
              end
            else
              begin
                raise Exception, "You do not have permissions to destroy this object"
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:path => subpath}})
              end
            end
          else
            begin
              raise Exception, "Invalid path"
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => subpath}})
            end
          end
        end
        result
      end
      #
      def rmfile(subpath="")
        result = false
        if @directory
          # FS rmfile
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          #
          if ::File::exist?(the_path)
            begin
              the_profile = self.profile(subpath.to_s)
              if the_profile
                if the_profile[:permissions][:effective][:destroy]
                  if ::File::delete(the_path)
                    GxG::DB[:roles][:vfs].destroy_vfs_permission(the_profile[:file_id])
                    result = true
                  end
                else
                  raise Exception, "You do not have destroy permissions to do this"
                end
              else
                raise Exception, "Inavalid path"
              end
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path}})
            end
          else
            begin
              raise Exception, "Invaid path"
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => the_path}})
            end
          end
          #
        else
          # DB rmfile
          path_array = self.db_path(subpath.to_s)
          if path_array
            the_profile = self.profile(subpath.to_s)
            if the_profile
              if the_profile[:permissions][:effective][:destroy]
                parent_uuid = (path_array[-2] || {})[:uuid]
                link_uuids = []
                found_link = nil
                if parent_uuid
                  @database.connector()[:array_elements].filter({:parent_uuid => parent_uuid.to_s}).order(:ordinal).each do |link_record|
                    header = nil
                    if link_record[:element_hash_uuid].to_s.size > 0
                      header = @database.connector()[:element_hash].filter({:uuid => link_record[:element_hash_uuid].to_s}).first
                    end
                    if header
                      if header[:uuid] == path_array.last[:uuid] && header[:title] == path_array.last[:title]
                        found_link = {:uuid => header[:uuid], :linkid => link_record[:dbid]}
                      else
                        link_uuids << {:uuid => header[:uuid], :linkid => link_record[:dbid]}
                      end
                    end
                  end
                  if found_link
                    # Review : how to deal with lots of users deleting objects at once??
                    if @database.destroy_by_uuid(@credential, found_link[:uuid].to_sym) == true
                      # ### Delete array_elements link of id ...
                      @database.connector()[:array_elements].filter({:dbid => found_link[:linkid]}).delete
                      # ### Reset ordinals of array_elements links. (Even though VFS.entries sorts results)
                      link_uuids.each_with_index do |link_record, ordinal|
                        @database.connector()[:array_elements].filter({:dbid => found_link[:linkid]}).update({:ordinal => ordinal})
                      end
                    end
                  end
                end
                #
              else
                begin
                  raise Exception, "You do not have destroy permissions to do this"
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:path => subpath.to_s}})
                end
              end
            else
              begin
                raise Exception, "Invaid path"
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:path => subpath.to_s}})
              end
            end
          else
            begin
              raise Exception, "Invaid path"
            rescue Exception => the_error
              log_error({:error => the_error, :parameters => {:path => subpath.to_s}})
            end
          end
        end
        result
      end
      #
      def rename(subpath="", new_name="", options={})
        result = false
        if @directory
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          # FS
          begin
            if options[:with_credential]
              item_profile = self.profile(subpath.to_s,options.merge({:follow_symlinks => true}))
            else
              item_profile = self.profile(subpath.to_s)
            end
            if item_profile.is_a?(::Hash)
              if item_profile[:permissions][:effective][:rename] == true
                ::File.rename(the_path,(File.dirname(the_path) + "/" + new_name))
                # Review : check for file_id changes and update the VFS-DB permission records.
                result = true
              else
                raise Exception, "You do not have rename permissions here"
              end
            else
              raise Exception, "Invalid path"
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
            #
          end
        else
          # DB open/create :persisted_hash or open :persisted_array
          begin
            path_array = self.db_path(subpath.to_s)
            if path_array
              if options[:with_credential]
                profile = self.profile(subpath.to_s, options)
              else
                profile = self.profile(subpath.to_s)
              end
              profile = self.profile(subpath.to_s)
              if profile[:permissions][:effective][:rename] == true
                if profile[:type] == :persisted_hash
                  @database.connector()[:element_hash].filter({:uuid => profile[:uuid].to_s}).update({:title => new_name})
                  result = true
                else
                  if profile[:type] == :persisted_array
                    @database.connector()[:element_array].filter({:uuid => profile[:uuid].to_s}).update({:title => new_name})
                    result = true
                  end
                end
                #
              else
                raise Exception, "You do not have rename permissions here"
              end
              #
            else
              raise Exception, "Invalid path"
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
          end
        end
        result
      end
      #
      def open(subpath="", options={})
        result = nil
        if @directory
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          flags = 0
          flag_array = (options[:flags] || [:readwrite])
          flag_array.each do |the_flag|
            case the_flag
            when :append
              flags += ::File::APPEND
            when :binary
              flags += ::File::BINARY
            when :create
              flags += ::File::CREAT
            when :direct
              flags += ::File::DIRECT
            when :dsync
              flags += ::File::DSYNC
            when :duplex
              flags += ::File::DUPLEX
            when :exclusive
              flags += ::File::EXCL
            when :casefold
              flags += ::File::FNM_CASEFOLD
            when :dotmatch
              flags += ::File::FNM_DOTMATCH
            when :no_escape
              flags += ::File::FNM_NOESCAPE
            when :pathname
              flags += ::File::FNM_PATHNAME
            when :system_case
              flags += ::File::FNM_SYSCASE
            when :lock_ex
              flags += ::File::LOCK_EX
            when :lock_nb
              flags += ::File::LOCK_NB
            when :lock_sh
              flags += ::File::LOCK_SH
            when :lock_un
              flags += ::File::LOCK_UN
            when :no_atime
              flags += ::File::NOATIME
            when :no_ctty
              flags += ::File::NOCTTY
            when :no_follow
              flags += ::File::NOFOLLOW
            when :nonblock
              flags += ::File::NONBLOCK
            when :read
              flags += ::File::RDONLY
            when :rsync
              flags += ::File::RSYNC
            when :seek_cur
              flags += ::File::SEEK_CUR
            when :seek_end
              flags += ::File::SEEK_END
            when :seek_set
              flags += ::File::SEEK_SET
            when :setenc_by_bom
              flags += ::File::SETENC_BY_BOM
            when :sync
              flags += ::File::SYNC
            when :text
              flags += ::File::TEXT
            when :truncate
              flags += ::File::TRUNC
            when :tty
              flags += ::File::TTY
            when :write
              flags += ::File::WRONLY
            when :readwrite
              flags += ::File::RDWR
            when :wsplit
              flags += ::File::WSPLIT
            when :wsplit_initialized
              flags += ::File::WSPLIT_INITIALIZED
            end
          end
          perm = 16384
          permissions = options[:permissions]
          if permissions.is_a?(::Hash)
            # Best if you pass the entire :permissions hash from a profile query
            "040000".each_char_with_index do |digit, indexer|
              case indexer
              when 0
              when 1
                # TODO: process other flags
              when 2
              when 3
                if permissions[:owner].is_a?(::Hash)
                  if permissions[:owner][:execute]
                    perm += 256
                  end
                  if permissions[:owner][:write]
                    perm += 128
                  end
                  if permissions[:owner][:read]
                    perm += 64
                  end
                end
              when 4
                if permissions[:group].is_a?(::Hash)
                  if permissions[:group][:execute]
                    perm += 32
                  end
                  if permissions[:group][:write]
                    perm += 16
                  end
                  if permissions[:group][:read]
                    perm += 8
                  end
                end
              when 5
                if permissions[:other].is_a?(::Hash)
                  if permissions[:other][:execute]
                    perm += 4
                  end
                  if permissions[:other][:write]
                    perm += 2
                  end
                  if permissions[:other][:read]
                    perm += 1
                  end
                end
              end
            end
            #
          else
            base_profile = self.profile("/")
            if base_profile.is_a?(::Hash)
              if base_profile[:mode].is_a?(::String)
                perm = (base_profile[:mode][0..2].to_s + "644").to_i(base=8)
              else
                perm = 16804
              end
            else
              perm = 16804
            end
          end
          # FS
          begin
            parent_profile = self.profile(::File::dirname(subpath.to_s))
            if parent_profile
              if ::File::exist?(the_path)
                if ::File::directory?(the_path)
                  result = ::Dir::new(the_path)
                else
                  if flag_array.include?(:read)
                    unless parent_profile[:permissions][:effective][:read]
                      raise Exception, "You do not have read permissions here."
                    end
                  end
                  if flag_array.include?(:write)
                    unless parent_profile[:permissions][:effective][:write]
                      raise Exception, "You do not have write permissions here."
                    end
                  end
                  if flag_array.include?(:readwrite)
                    unless parent_profile[:permissions][:effective][:read]
                      raise Exception, "You do not have read permissions here."
                    end
                    unless parent_profile[:permissions][:effective][:write]
                      raise Exception, "You do not have write permissions here."
                    end
                  end
                  if ::GxG::Engine::available_file_descriptors() > 0
                    result = ::File::open(the_path, flags)
                  else
                    raise Exception, "Maximum File Descriptor count exceeded. Aborting"
                  end
                end
              else
                if parent_profile[:permissions][:effective][:create]
                  if ::GxG::Engine::available_file_descriptors() > 0
                    ::File::new(the_path, "w", perm).close
                    result = ::File::open(the_path, flags)
                    # Generate VFS-DB permissions, return result
                    self.profile(subpath)
                  else
                    raise Exception, "Maximum File Descriptor count exceeded. Aborting"
                  end
                else
                  raise Exception, "You do not have create permissions here"
                end
              end
            else
              raise Exception, "Invalid path"
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path, :options => options}})
            #
          end
        else
          # DB open/create :persisted_hash
          begin
            path_array = self.db_path(subpath.to_s)
            if path_array
              profile = self.profile(subpath.to_s)
              if profile[:permissions][:effective][:read]
                result = @database.retrieve_by_uuid(path_array.last[:uuid], @credential)
              else
                # Review : keep? this breaks the 'if you don't have privs you can't see it - no errors, security through obscurity' idea.
                raise Exception, "You do not have read permissions on this object"
              end
            else
              parent_profile = self.profile(::File::dirname(subpath.to_s))
              if parent_profile
                if parent_profile[:permissions][:effective][:create] == true
                  if options[:format]
                    if GxG::valid_uuid?(options[:format])
                      new_object = @database.new_structure_from_format(@credential,{:uuid => options[:format]})
                    else
                      new_object = @database.new_structure_from_format(@credential,{:ufs => options[:format]})
                    end
                  else
                    if options[:ufs]
                      new_object = @database.new_structure_from_format(@credential,{:ufs => options[:ufs]})
                    else
                      new_object = @database.try_persist({}, @credential)
                    end
                  end
                  # ### allow to create the object with a specific UUID.
                  if ::GxG::valid_uuid?(options[:with_uuid])
                    address = new_object.db_address()
                    new_object.deactivate
                    @database.connector()[(address[:table])].filter({:dbid => address[:dbid]}).first.update({:uuid => options[:with_uuid].to_s})
                    new_object = @database.retrieve_by_uuid(options[:with_uuid].to_s.to_sym, @credential)
                  end
                  #
                  new_object.wait_for_reservation
                  new_object.set_title(::File::basename(subpath.to_s))
                  # ### Fashion a link under the parent uuid.
                  new_ordinal = @database.connector()[:array_elements].filter({:parent_uuid => parent_profile[:uuid].to_s}).count
                  @database.connector()[:array_elements].insert({:parent_uuid => parent_profile[:uuid].to_s, :version => new_object.version(), :ordinal => new_ordinal, :element => "element_hash", :element_hash_uuid => new_object.uuid.to_s})
                  # ### Wrap up and return new object
                  new_object.release_reservation
                  result = new_object
                else
                  raise Exception, "You do not have create permissions here"
                end
                #
              else
                raise Exception, "Invalid path"
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => subpath, :options => options}})
          end
        end
        result
      end
      #
      def mkdir(subpath="", permissions=nil)
        result = false
        if @directory
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          perm = 16384
          if permissions.is_a?(::Hash)
            # Best if you pass the entire :permissions hash from a profile query
            "040000".each_char_with_index do |digit, indexer|
              case indexer
              when 0
              when 1
                # TODO: process other flags
              when 2
              when 3
                if permissions[:owner].is_a?(::Hash)
                  if permissions[:owner][:execute]
                    perm += 256
                  end
                  if permissions[:owner][:write]
                    perm += 128
                  end
                  if permissions[:owner][:read]
                    perm += 64
                  end
                end
              when 4
                if permissions[:group].is_a?(::Hash)
                  if permissions[:group][:execute]
                    perm += 32
                  end
                  if permissions[:group][:write]
                    perm += 16
                  end
                  if permissions[:group][:read]
                    perm += 8
                  end
                end
              when 5
                if permissions[:other].is_a?(::Hash)
                  if permissions[:other][:execute]
                    perm += 4
                  end
                  if permissions[:other][:write]
                    perm += 2
                  end
                  if permissions[:other][:read]
                    perm += 1
                  end
                end
              end
            end
            #
          else
            base_profile = self.profile("/")
            if base_profile.is_a?(::Hash)
              if base_profile[:mode].is_a?(::String)
                perm = base_profile[:mode].to_i(base=8)
              else
                perm = 16877
              end
            else
              perm = 16877
            end
          end
          # FS mkdir
          begin
            parent_profile = self.profile(::File::dirname(subpath.to_s))
            if parent_profile
              if parent_profile[:permissions][:effective][:create]
                if ::File::exist?(the_path)
                  result = true
                else
                  if ::Dir::mkdir(the_path, perm) == 0
                    # Generate VFS-DB permissions, return result
                    self.profile(subpath)
                    result = true
                  end
                end
              else
                raise Exception, "You do not have create permissions here"
              end
            else
              raise Exception, "Invalid path"
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => the_path, :permissions => permissions}})
            #
          end
        else
          # DB dir create
          begin
            parent_profile = self.profile(::File::dirname(subpath.to_s))
            if parent_profile
              if parent_profile[:permissions][:effective][:create] == true
                new_object = @database.try_persist([], @credential)
                new_object.wait_for_reservation
                new_object.set_title(::File::basename(subpath.to_s))
                # ### Fashion a link under the parent uuid.
                new_ordinal = @database.connector()[:array_elements].filter({:parent_uuid => parent_profile[:uuid].to_s}).count
                @database.connector()[:array_elements].insert({:parent_uuid => parent_profile[:uuid].to_s, :version => new_object.version(), :ordinal => new_ordinal, :element => "element_array", :element_array_uuid => new_object.uuid.to_s})
                # ### Wrap up and return new object
                new_object.release_reservation
                result = true
              else
                raise Exception, "You do not have create permissions here"
              end
            else
              raise Exception, "Invalid path"
            end
            #
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:path => subpath, :permissions => permissions}})
            #
          end
          #
        end
        result
      end
      #
      def get_permissions(subpath="", the_credential=nil)
        result = []
        if @directory
          if self.exist?(subpath)
            the_profile = self.profile(subpath)
            if the_profile[:file_id]
              result = GxG::DB[:roles][:vfs].vfs_permission_manifest(the_profile[:file_id], the_credential)
            end
            # ????            
            # xxx
            # group_roles = GxG::DB[:authority][:system_credentials]
            # the_record = {:credential => group_roles[:administrators], :permissions => the_profile[:permissions][:owner], :details => {}}
            # role = GxG::DB[:authority].role_fetch({:uuid => the_record[:credential].to_s})
            # group = GxG::DB[:authority].group_fetch({:uuid => role[:group_uuid].to_s})
            # the_record[:details][:role_title] = role[:title]
            # the_record[:details][:group] = group[:uuid].to_s.to_sym
            # the_record[:details][:group_title] = group[:title]
            # result << the_record
            # the_record = {:credential => group_roles[:developers], :permissions => the_profile[:permissions][:group], :details => {}}
            # role = GxG::DB[:authority].role_fetch({:uuid => the_record[:credential].to_s})
            # group = GxG::DB[:authority].group_fetch({:uuid => role[:group_uuid].to_s})
            # the_record[:details][:role_title] = role[:title]
            # the_record[:details][:group] = group[:uuid].to_s.to_sym
            # the_record[:details][:group_title] = group[:title]
            # result << the_record
            # the_record = {:credential => group_roles[:designers], :permissions => the_profile[:permissions][:group], :details => {}}
            # role = GxG::DB[:authority].role_fetch({:uuid => the_record[:credential].to_s})
            # group = GxG::DB[:authority].group_fetch({:uuid => role[:group_uuid].to_s})
            # the_record[:details][:role_title] = role[:title]
            # the_record[:details][:group] = group[:uuid].to_s.to_sym
            # the_record[:details][:group_title] = group[:title]
            # result << the_record
            # the_record = {:credential => :"00000000-0000-4000-0000-000000000000", :permissions => the_profile[:permissions][:other], :details => {}}
            # user = GxG::DB[:authority].user_fetch({:uuid => the_record[:credential].to_s})
            # the_record[:details][:user_title] = user[:user_id]
            # result << the_record
          end
        else
          if self.exist?(subpath)
            the_profile = self.profile(subpath)
            result = @database.element_permissions_by_uuid(the_profile[:uuid])
          end
        end
        result
      end
      #
      def revoke_permissions(subpath="", the_credential=nil)
        # revoke_element_permissions(table=:unspecified, dbid=0, credential=nil)
        result = false
        if @directory
          # Review - all I need is the :file_id : make more efficient
          profile = self.profile(subpath)
          if profile[:file_id]
            result = GxG::DB[:roles][:vfs].destroy_vfs_permission(profile[:file_id], the_credential)
          end
        else
          if self.exist?(subpath)
            the_profile = self.profile(subpath)
            result = @database.revoke_permissions_by_uuid(the_profile[:uuid], the_credential)
          end
        end
        result
      end
      #
      def set_permissions(subpath="", the_credential=nil, the_permissions={})
        result = false
        if @directory
          if subpath.to_s == "" or subpath.to_s == "/"
            the_path = (@directory.path)
          else
            unless subpath.to_s[0] == "/"
              subpath = ("/" << subpath.to_s)
            end
            the_path = (@directory.path + subpath.to_s).gsub("//", "/")
          end
          if ::File::exist?(the_path)
            # Review - all I need is the :file_id : make more efficient
            profile = self.profile(subpath, the_credential)
            the_credentials = []
            owner_roles = [(GxG::DB[:authority][:system_credentials][:administrators]), (GxG::DB[:authority][:system_credentials][:developers]), (GxG::DB[:authority][:system_credentials][:designers])].flatten!
            user_roles = GxG::DB[:authority].user_roles(the_credential).collect {|record| record[:credential]}
            the_role = :other
            user_roles.each do |the_role_credential|
              if owner_roles.include?(the_role_credential)
                the_role = :owner
                the_credentials = owner_roles
                break
              end
            end
            unless the_role == :owner
              if the_credential.to_s == "00000000-0000-4000-0000-000000000000"
                the_role = :other
                the_credentials = [ :"00000000-0000-4000-0000-000000000000" ]
              else
                the_role = :group
                the_credentials = user_roles
              end
            end
            # translate to unix permissions
            old_permission = ::File.stat(the_path).mode.to_s(base=2)
            x = nil
            if ::File.directory?(the_path)
              x = 1
            else
              if the_permissions.keys.include?(:execute)
                if the_permissions[:execute] == true
                  x = 1
                else
                  x = 0
                end
              end
            end
            w = nil
            if the_permissions.keys.include?(:write)
              if the_permissions[:write] == true
                w = 1
              else
                w = 0
              end
            else
              [:rename, :move, :destroy, :create].each do |the_action|
                if the_permissions.keys.include?(the_action)
                  if the_permissions[(the_action)] == true
                    w = 1
                    break
                  end
                end
              end
            end
            if the_permissions.keys.include?(:read)
              if the_permissions[:read] == true
                r = 1
              else
                r = 0
              end
            else
              r = nil
            end
            case the_role
            when :owner
              if x
                old_permission[-7] = x.to_s
              end
              if w
                old_permission[-8] = w.to_s
              end
              if r
                old_permission[-9] = r.to_s
              end
            when :group
              if x
                old_permission[-4] = x.to_s
              end
              if w
                old_permission[-5] = w.to_s
              end
              if r
                old_permission[-6] = r.to_s
              end
            when :other
              if x
                old_permission[-1] = x.to_s
              end
              if w
                old_permission[-2] = w.to_s
              end
              if r
                old_permission[-3] = r.to_s
              end
            end
            ::File.chmod(old_permission.to_i(2), the_path)
            if profile[:file_id]
              the_credentials.each do |credential_uuid|
                GxG::DB[:roles][:vfs].update_vfs_permission(profile[:file_id], credential_uuid, the_permissions)
              end
            end
            result = true
          end
        else
          # DB object exist?
          path_array = self.db_path(subpath.to_s)
          if path_array
            object_details = {:uuid => path_array.last[:uuid], :table => :unspecified, :dbid => 0}
            header = @database.connector()[:element_hash].filter({:uuid => object_details[:uuid].to_s}).first
            if header
              object_details[:table] = :element_hash
              object_details[:dbid] = header[:dbid]
            else
              header = @database.connector()[:element_array].filter({:uuid => object_details[:uuid].to_s}).first
              if header
                object_details[:table] = :element_array
                object_details[:dbid] = header[:dbid]
              end
            end
            if object_details[:uuid].to_s.size > 0
              if object_details[:table] = :element_array
                manifest = [{:table => object_details[:table], :dbid => object_details[:dbid]}]
              else
                # Note: for an element_hash - ensure all sub-objects are extended this permission.
                manifest = []
                structures = [{:table => object_details[:table], :dbid => object_details[:dbid]}]
                while structures.size > 0 do
                  entry = structures[0]
                  @database.element_manifest(entry[:table],entry[:dbid]).each do |record|
                    if [:element_hash, :element_array].include?(record[:table])
                      unless structures.include?(record)
                        structures << record
                      end
                    end
                  end
                  manifest << structures.shift
                end
              end
              #
              manifest.each do |record|
                @database.assign_element_permission(record[:table], record[:dbid], credential, the_permissions)
              end
              result = true
            end
          end
        end
        result
      end
      #
      def set_permissions_recursive(subpath="", the_credential=nil, the_permissions={})
        the_profile = self.profile((File.expand_path(subpath)).to_s)
        if the_profile
          if [:virtual_directory, :directory, :persisted_array].include?(the_profile[:type])
            paths = [(File.expand_path(subpath))]
            while paths.size > 0 do
              the_path = paths.shift
              the_path_profile = self.profile(the_path.to_s)
              if [:virtual_directory, :directory, :persisted_array].include?(the_path_profile[:type])
                self.entries(the_path, the_credential).each do |a_profile|
                  paths << File.expand_path(the_path + "/" + a_profile[:title].to_s)
                end
                self.set_permissions(the_path, the_credential, the_permissions)
              else
                self.set_permissions(the_path, the_credential, the_permissions)
              end
            end
          else
            self.set_permissions(subpath, the_credential, the_permissions)
          end
        end
        true
      end
      #
    end
  end
  VFS = ::GxG::Storage::FileSpace.new
  #
end
