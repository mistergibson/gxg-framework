# PersistedHash Code:
module GxG
  module Database
    #
    class DetachedHash
      #
      public
      # ### OpenStruct Integration
      def as_structure()
        ::OpenStruct.new(self)
      end
      #
      def uuid()
          @uuid.clone
      end
      #
      def uuid=(the_uuid=nil)
        if GxG::valid_uuid?(the_uuid)
          @uuid = the_uuid.to_s.to_sym
        end
      end
      #
      def title()
          @title.clone
      end
      #
      def title=(the_title=nil)
        if the_title
          @title = the_title.to_s[0..255]
          self.increment_version
        end
      end
      #
      def version()
        @version.clone
      end
      #
      def version=(the_version=nil)
        if the_version.is_a?(::Numeric)
          @version = the_version.to_s("F").to_d
        end
      end
      #
      def element_version(key=nil)
        result = 0.0
        if key.is_a?(::Symbol)
          if key.to_s.size > 256
            log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
            key = key.to_s[(0..255)].to_sym
          end
          #
          if @property_links[(key.to_s.to_sym)]
            result = @property_links[(key.to_s.to_sym)][:record][:version]
          else
            result = 0.0
          end
          #
        end
        result
      end
      #
      def set_element_version(element_key, the_version=nil)
        result = false
        if @property_links[(element_key)]
          if the_version.is_a?(::Numeric)
            @property_links[(element_key)][:record][:version] = (((the_version.to_f) * 10000.0).to_i.to_f / 10000.0)
            result = true
          else
            log_warning("Attempted to set version to an invalid version value #{the_version.inspect} for #{element_key.inspect} on Object #{@uuid.inspect}")
          end
        else
          log_warning("Attempted to set version with an invalid key #{element_key.inspect} on Object #{@uuid.inspect}")
        end
        result
      end
      #
      def format()
        @format.clone
      end
      #
      def format=(the_format=nil)
        if GxG::valid_uuid?(the_format)
          @format = the_format.to_s.to_sym
        end
      end
      #
      def parent()
          @parent
      end
      #
      def parent=(object=nil)
        if object.is_any?([::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray])
          # Review : parent can only be set once -- is this best??
          unless @parent
            @parent = object
          end
        end
      end
      #
      def write_reserved?()
        true
      end
      #
      def release_reservation()
        true
      end
      #
      def get_reservation()
        true
      end
      #
      def wait_for_reservation(timeout=nil)
        true
      end
      # ### Review: move to Database class as generic toolbox method at some point:
      #
      def self.import(import_record=nil)
        result = nil
        unless import_record.is_any?(::Hash, ::GxG::Database::DetachedHash)
            raise Exception, "Malformed import record passed."
        end
        # {:type => :element_hash, :uuid => @uuid.clone, :title => @title.clone, :version => @version.clone, :format => @format.clone, :content => {}}
        import_db = [{:target => ::GxG::Database::DetachedHash.new, :record => import_record}]
        result =  import_db[0][:target]
        while import_db.size > 0 do
            entry = import_db.shift
            case entry[:record][:type].to_s.to_sym
            when :element_hash
                entry[:target].uuid = entry[:record][:uuid].to_s.to_sym
                entry[:target].title = entry[:record][:title].to_s
                 entry[:record][:content].keys.each do |the_key|
                     case entry[:record][:content][(the_key)][:type].to_s.to_sym
                     when :element_hash
                         new_target = GxG::Database::DetachedHash.new
                         entry[:target][(the_key)] = new_target
                         import_db << {:target => new_target, :record => (entry[:record][:content][(the_key)])}
                         entry[:target][(the_key)].parent = (entry[:target])
                     when :element_array
                         new_target = GxG::Database::DetachedArray.new
                         entry[:target][(the_key)] = new_target
                         import_db << {:target => new_target, :record => (entry[:record][:content][(the_key)])}
                         entry[:target][(the_key)].parent = (entry[:target])
                     when :element_boolean, :element_integer, :element_float, :element_text
                         entry[:target][(the_key)] = entry[:record][:content][(the_key)][:content]
                      when :element_bigdecimal
                          entry[:target][(the_key)] = ::BigDecimal.new(entry[:record][:content][(the_key)][:content].to_s)
                      when :element_datetime
                        entry[:target][(the_key)] = ::Chronic::parse(entry[:record][:content][(the_key)][:content].to_s)
                      when :element_binary
                        entry[:target][(the_key)] = ::GxG::ByteArray.new(entry[:record][:content][(the_key)][:content].to_s.decode64)
                     end
                 end
                entry[:target].version = ::BigDecimal.new(entry[:record][:version].to_s)
                entry[:target].format = entry[:record][:format].to_s.to_sym
            when :element_array
                entry[:target].uuid = entry[:record][:uuid].to_s.to_sym
                entry[:target].title = entry[:record][:title].to_s
                 entry[:record][:content].each_index do |indexer|
                      case entry[:record][:content][(indexer)][:type].to_s.to_sym
                      when :element_hash
                         new_target = GxG::Database::DetachedHash.new
                         entry[:target][(indexer)] = new_target
                         import_db << {:target => new_target, :record => (entry[:record][:content][(indexer)])}
                         entry[:target][(indexer)].parent =(entry[:target])
                      when :element_array
                         new_target = GxG::Database::DetachedArray.new
                         entry[:target][(indexer)] = new_target
                         import_db << {:target => new_target, :record => (entry[:record][:content][(indexer)])}
                         entry[:target][(indexer)].parent = (entry[:target])
                      when :element_boolean, :element_integer, :element_float, :element_text
                         entry[:target][(indexer)] = entry[:record][:content][(indexer)][:content]
                      when :element_bigdecimal
                          entry[:target][(indexer)] = ::BigDecimal.new(entry[:record][:content][(indexer)][:content].to_s)
                      when :element_datetime
                        entry[:target][(indexer)] = ::Chronic::parse(entry[:record][:content][(indexer)][:content].to_s)
                      when :element_binary
                        entry[:target][(indexer)] = ::GxG::ByteArray.new(entry[:record][:content][(indexer)][:content].to_s.decode64)
                      end
                 end
                entry[:target].version = ::BigDecimal.new(entry[:record][:version].to_s)
                entry[:target].constraint = entry[:record][:constraint].to_s.to_sym
            end
        end
        #
        result
      end
      #
      def self.create_from_format(the_format=nil)
        result = nil
        format_record = nil
        if ::GxG::valid_uuid?(the_format)
          format_record = ::GxG::DB[:roles][:formats].format_load({:uuid => the_format})
        else
          format_record = ::GxG::DB[:roles][:formats].format_load({:ufs => the_format})
        end
        if format_record
          # Review : ?? the ability to ingest a detached_object's data while retaining self's identity data. worth it ??
          new_object = ::GxG::Database::DetachedHash.new
          new_object.uuid = ::GxG::uuid_generate.to_sym
          new_object.title = "Untitled #{new_object.uuid.to_s}"
          object_db = [{:destination => new_object, :source => format_record[:content]}]
          while object_db.size > 0 do
            pair = object_db.shift
            if pair
              pair[:source].search do |item, selector, container|
                if item.is_any?(::Array, ::Hash)
                  if item.is_a?(::Hash)
                    unless pair[:destination][(selector)].is_a?(::GxG::Database::DetachedHash)
                      new_item = ::GxG::Database::DetachedHash.new
                      new_item.uuid = ::GxG::uuid_generate.to_sym
                      new_item.title = "Untitled #{new_object.uuid.to_s}"
                      pair[:destination][(selector)] = new_item
                    end
                    object_db << [{:destination => pair[:destination][(selector)], :source => item}]
                  else
                    if item.is_a?(::Array)
                      unless pair[:destination][(selector)].is_a?(::GxG::Database::PersistedArray)
                        new_item = ::GxG::Database::DetachedArray.new
                        new_item.uuid = ::GxG::uuid_generate.to_sym
                        new_item.title = "Untitled #{new_object.uuid.to_s}"
                        pair[:destination][(selector)] = new_item
                      end
                      object_db << [{:destination => pair[:destination][(selector)], :source => item}]
                    end
                  end
                  #
                else
                  pair[:destination][(selector)] = item
                end
              end
            end
          end
          new_object.format = format_record[:uuid].to_s.to_sym
          #
          unless ::GxG::DB_SAFETY.synchronize { GxG::DB[:formats][(format_record[:uuid].to_s.to_sym)] }
            ::GxG::DB_SAFETY.synchronize { GxG::DB[:formats][(format_record[:uuid].to_s.to_sym)] = format_record }
          end
          #
          result = new_object
        else
          result = ::GxG::Database::DetachedHash.new
          result.uuid = ::GxG::uuid_generate.to_sym
          result.title = "Untitled #{new_object.uuid.to_s}"
        end
        #
        result
      end
      #
      def self.create()
        ::GxG::Database::DetachedHash::create_from_format(nil)
      end
      #
      def ufs()
        if @format
          record = GxG::DB[:formats][(@format.to_s.to_sym)]
          if record
            record[:ufs].to_s.to_sym
          else
            ""
          end
        else
          ""
        end
      end
      #
      def increment_version()
        @version += 0.0001
      end
      #
      def initialize()
        @active = true
        @uuid = nil
        @title = nil
        @version = ::BigDecimal.new("0.0")
        @format = nil
        @parent = nil
        @property_links = {}
        self
      end
      #
      def inspect()
        # FORNOW: make re-entrant (yes, I know!) Fortunately, circular links are impossible with DetachedHash.
        # TODO: make interative instead of re-entrant.
        last_key = @property_links.keys.last
        result = "{"
        @property_links.keys.each do |element_key|
          result = result + (":#{element_key.to_s} => " + @property_links[(element_key)][:content].inspect)
          # if @property_links[(element_key)][:loaded] == true
          #   result = result + (":#{element_key.to_s} => " + @property_links[(element_key)][:content].inspect)
          # else
          #   result = result + (":#{element_key.to_s} => (Not Loaded)")
          # end
          unless last_key == element_key
            result = result + ", "
          end
        end
        result = result + "}"
        result
      end
      #
      def alive?()
        @active
      end
      #
      def save()
        result = false
        if self.alive?
          begin
            # Review : expand to save to server
            result = true
          rescue Exception => the_error
            log_error({:error => the_error})
          end
        end
        result
      end
      #
      def deactivate()
        ::GxG::DB_SAFETY.synchronize { ::GxG::DB[:cache].delete(@uuid) }
        @active = false
        true
      end
      #
      def destroy()
        result = false
        if self.alive?
          result = self.deactivate
        end
        result
      end
      #
      def size()
        @property_links.size
      end
      #
      def keys()
        @property_links.keys
      end
      #
      def []=(key=nil, value=nil)
        # Only works with Symbols.
        unless self.alive?()
          raise Exception, "Attempted to alter a defunct structure"
        end
        result = nil
        if key.is_a?(::Symbol)
          if key.to_s.size > 256
            log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
            key = key.to_s[(0..255)].to_sym
          end
          property_key = key.to_s.to_sym
          # Review : rewrite ????
          if value.is_any?(::NilClass, ::TrueClass, ::FalseClass, ::Integer, ::Float, ::BigDecimal, ::String, ::Time, ::GxG::ByteArray, ::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray, ::Hash, ::Array)
            unless self.write_reserved?()
              self.get_reservation()
            end
            if self.write_reserved?()
              # Further screen value provided:
              # ### Check provided DetachedHashes and DetachedArrays
              # ### Check provided Hashes and Arrays
              # ### Property Exists?
              if @property_links[(key.to_s.to_sym)]
                # set property to value
                operation = :set_value
              else
                if @format
                  raise Exception, "Formatted - the structure cannot be altered"
                else
                  # add property : value pair
                  operation = :add_value
                end
              end
              # ### Prepare new value
              new_value = {
                :linkid => nil,
                :content => nil,
                :loaded => true,
                :state => 0,
                :record => {
                  :parent_uuid => @uuid.to_s,
                  :property => key.to_s,
                  :ordinal => 0,
                  :version => ::BigDecimal.new("0.0"),
                  :element => "element_boolean",
                  :element_boolean => -1,
                  :element_integer => 0,
                  :element_float => 0.0,
                  :element_bigdecimal => ::BigDecimal.new("0.0"),
                  :element_datetime => ::Time.now,
                  :time_offset => 0.0,
                  :time_prior => 0.0,
                  :time_after => 0.0,
                  :length => 0,
                  :element_text => "",
                  :element_binary => nil,
                  :element_array => nil,
                  :element_hash => nil
                }
              }
              #
              if value.is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                # ### Assimilate DetachedHash or DetachedArray
                new_value[:content] = value
                new_value[:loaded] = true
                new_value[:state] = new_value[:content].hash
                # Note: version is sync'd here, but don't rely upon property version with linked structures, but use structure's version method.
                new_value[:record][:version] = new_value[:content].version()
                if value.is_a?(::GxG::Database::DetachedHash)
                  new_value[:record][:element] = "element_hash"
                  new_value[:record][:element_hash] = value
                else
                  new_value[:record][:element] = "element_array"
                  new_value[:record][:element_array] = value
                end
              else
                # ### Persist Hashes and Arrays
                if value.is_any?(::Hash, ::Array)
                  new_value[:content] = ::GxG::Database::iterative_detached_persist(value)
                  new_value[:loaded] = true
                  new_value[:state] = new_value[:content].hash
                  # Note: version is sync'd here, but don't rely upon property version with linked structures, but use structure's version method.
                  new_value[:record][:version] = new_value[:content].version()
                  if value.is_a?(::Hash)
                    new_value[:record][:element] = "element_hash"
                    new_value[:record][:element_hash] = new_value[:content]
                  else
                    new_value[:record][:element] = "element_array"
                    new_value[:record][:element_array] = new_value[:content]
                  end
                else
                  # ### Persist Base Element Values
                  new_value[:record][:element] = ::GxG::Database::element_table_for_instance(value).to_s
                  case new_value[:record][:element]
                  when "element_boolean"
                    if value.class == ::NilClass
                      new_value[:record][:element_boolean] = -1
                      new_value[:content] = nil
                    end
                    if value.class == ::FalseClass
                      new_value[:record][:element_boolean] = 0
                      new_value[:content] = false
                    end
                    if value.class == ::TrueClass
                      new_value[:record][:element_boolean] = 1
                      new_value[:content] = true
                    end
                  when "element_integer"
                    new_value[:record][:element_integer] = value
                    new_value[:content] = value
                  when "element_float"
                    new_value[:record][:element_float] = value
                    new_value[:content] = value
                  when "element_bigdecimal"
                    new_value[:record][:element_bigdecimal] = ::BigDecimal.new(value.to_s)
                    new_value[:content] = new_value[:record][:element_bigdecimal]
                  when "element_datetime"
                    new_value[:record][:element_datetime] = value
                    new_value[:content] = value
                  when "element_text"
                    new_value[:record][:element_text] = value
                    new_value[:record][:length] = value.size
                    new_value[:content] = value
                  when "element_binary"
                    # Note: be sure to keep version & length sync'd with linked binary element record
                    if operation == :set_value
                      new_value[:record][:version] = @property_links[(property_key)][:record][:version]
                      new_value[:record][:element_binary] = @property_links[(property_key)][:record][:element_binary]
                    end
                    new_value[:record][:length] = value.size
                    new_value[:content] = value
                  else
                    raise Exception, "Unable to map an element type for value: #{value.inspect}"
                  end
                end
              end
              # ### Commit Changes
              case operation
              when :set_value
                # Note: Set In-memory value only, don't save unless you have to.
                if new_value[:content].is_a?(@property_links[(property_key)][:content].class) || ([true, false, nil].include?(new_value[:content]) && [true, false, nil].include?(@property_links[(property_key)][:content]))
                  # Replace value directly, but don't save yet unless you have to (:state refers to the last 'loaded-in-from-db' state of the data).
                  new_value[:linkid] = @property_links[(property_key)][:linkid]
                  if new_value[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (@property_links[(property_key)][:record][:version] + 0.0001)
                  end
                  new_value[:record][:ordinal] = @property_links[(property_key)][:record][:ordinal]
                  new_value[:loaded] = true
                  new_value[:state] = @property_links[(property_key)][:state]
                  #
                  @property_links[(property_key)] = new_value
                  #
                else
                  # Other class value being substituted.
                  if new_value[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (((@property_links[(property_key)][:record][:version].to_f + 0.0001) * 10000.0).to_i.to_f / 10000.0)
                  end
                  new_value[:record][:ordinal] = @property_links[(property_key)][:record][:ordinal]
                  new_value[:loaded] = true
                  #
                  @property_links[(property_key)] = new_value
                end
                result = @property_links[(property_key)][:content]
                #
              when :add_value
                # Note: set in-memory value and save.
                if new_value[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                  new_value[:record][:version] = new_value[:content].version()
                else
                  new_value[:record][:version] = ::BigDecimal.new("0.0")
                end
                new_value[:record][:ordinal] = @property_links.keys.size
                new_value[:loaded] = true
                #
                @property_links[(property_key)] = new_value
                # Review : is this wise to do this here??
                # property_write(property_key)
                # refresh_ordinals
              end
              # ### Handle coordination between persisted objects:
              if @property_links[(property_key)][:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                @property_links[(property_key)][:content].parent = (self)
              end
              #
              self.increment_version()
              result = @property_links[(property_key)][:content]
              #
            else
              raise Exception, "You do not have sufficient privileges to make this change. (write-reservation)"
            end
          else
            raise Exception, "The value is not persistable."
          end
        else
          raise Exception, "You must provide a property key in the form of a Symbol."
        end
        result
      end
      #
      def [](key=nil)
        result = nil
        # if key exists
        if self.alive?()
          if key.is_a?(::Symbol)
            if key.to_s.size > 256
              log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
              key = key.to_s[(0..255)].to_sym
            end
            property_key = key.to_s.to_sym
            if @property_links[(property_key)]
              result = @property_links[(property_key)][:content]
            end
          else
            raise ArgumentError, "You must specify with a Symbol, not a #{key.class.inspect}"
          end
        else
          raise Exception, "Attempted to access a defunct structure"
        end
        result
      end
      #
      def include?(the_key)
        @property_links.keys.include?(the_key)
      end
      #
      def delete(key=nil)
        result = nil
        if key.is_a?(::Symbol)
          if key.to_s.size > 256
            log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
            key = key.to_s[(0..255)].to_sym
          end
          if @format
            raise Exception, "Formatted - the structure cannot be altered"
          else
            if @property_links[(key)]
              result = @property_links[(key)][:content]
              @property_links.delete(key)
              # Review : send a 'delete_element' to server with the uuid of the DetachedHash and the key name.
              # ### -OR- develop @ the server: an 'overwrite' push call that will trim missing elements from stored copy.
            end
          end
        else
          raise ArgumentError, "You must specify with a Symbol, not a #{key.class.inspect}"
        end
        #
        result
      end
      #
      def unpersist()
        result = {}
        if self.alive?
          #
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
          # Build up export_db:
          self.search do |the_value, the_selector, the_container|
            if the_value.is_a?(::GxG::Database::DetachedHash)
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {}}
            else
              if the_value.is_a?(::GxG::Database::DetachedArray)
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => []}
              else
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => the_value}
              end
            end
          end
          # Collect children export content:
          link_db =[(export_db[0])]
          while link_db.size > 0 do
            entry = link_db.shift
            children_of.call(entry[:object]).each do |the_child|
              entry[:record][(the_child[:parent_selector])] = the_child[:record]
              if the_child[:object].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                link_db << the_child
              end
            end
          end
          #
        end
        result
      end
      #
      def export(options={:exclude_file_segments=>false})
        exclude_file_segments = (options[:exclude_file_segments] || false)
        if options[:clone] == true
          # Review : why are cloned objects unformatted? sync issues??
          result = {:type => :element_hash, :uuid => GxG::uuid_generate.to_s.to_sym, :title => @title.clone, :version => @version.to_s("F"), :content => {}}
        else
          result = {:type => :element_hash, :uuid => @uuid.clone, :title => @title.clone, :version => @version.to_s("F"), :format => @format.clone, :content => {}}
        end
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
        # Build up export_db:
        self.search do |the_value, the_selector, the_container|
          if the_value.is_a?(::GxG::Database::DetachedHash)
            if options[:clone] == true
              the_uuid = GxG::uuid_generate.to_s.to_sym
            else
              the_uuid = the_value.uuid().clone
            end
            if (exclude_file_segments == true) && (the_selector == :file_segments || the_selector == :segments || the_selector == :portions)
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => {}, :record => {:type => :element_hash, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().to_s("F"), :format => the_value.format().clone, :content => {}}}
            else
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => :element_hash, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().to_s("F"), :format => the_value.format().clone, :content => {}}}
            end
          end
          if the_value.is_a?(::GxG::Database::DetachedArray)
            if options[:clone] == true
              the_uuid = GxG::uuid_generate.to_s.to_sym
            else
              the_uuid = the_value.uuid().clone
            end
            if (exclude_file_segments == true) && (the_selector == :file_segments || the_selector == :segments || the_selector == :portions)
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => [], :record => {:type => :element_array, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().to_s("F"), :constraint => the_value.constraint().clone, :content => []}}
            else
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => :element_array, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().to_s("F"), :constraint => the_value.constraint().clone, :content => []}}
            end
          end
          if the_value.is_any?(::NilClass, ::TrueClass, ::FalseClass, ::Integer, ::Float, ::BigDecimal, ::String, ::Time, ::GxG::ByteArray)
            data_type = GxG::Database::element_table_for_instance(the_value)
            #
            case data_type
            when :element_bigdecimal
              data = the_value.to_s
            when :element_datetime
              data = the_value.iso8601.to_s
            when :element_binary
              data = the_value.to_s.encode64
            when :element_text
              data = the_value.to_s
            else
              data = the_value
            end
            #
            export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => data_type, :version => (the_container.version(the_selector) || ::BigDecimal.new("0.0")).to_s("F"), :content => data}}
          end
        end
        # Collect children export content:
        link_db = [(export_db[0])]
        while link_db.size > 0 do
          entry = link_db.shift
          children_of.call(entry[:object]).each do |the_child|
            entry[:record][:content][(the_child[:parent_selector])] = the_child[:record]
            if the_child[:object].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
              link_db << the_child
            end
          end
        end
        #
        result
      end
      #
      def export_package(options={:exclude_file_segments=>false})
        result = {:formats => {}, :records => []}
        object_record = self.export(options)
        object_record.search do |item,selector,container|
          if selector == :format || selector == :constraint
            if item.to_s.size > 0
              format_uuid = item
              unless result[:formats][(format_uuid.to_s.to_sym)].is_a?(::Hash)
                format_sample = ::GxG::DB[:roles][:formats].format_load({:uuid => format_uuid.to_s.to_sym})
                format_sample[:content] = format_sample[:content].gxg_export()
                result[:formats][(format_uuid.to_s.to_sym)] = format_sample
              end
            end
          end
        end
        result[:records] << object_record
        result
      end
      #
      #
      def each_pair(&block)
        collection = {}
        @property_links.keys.each do |key|
          collection[(key)] = (self[(key)])
        end
        if block.respond_to?(:call)
          collection.to_enum(:each_pair).each do |key,value|
            block.call(key,value)
          end
        else
          collection.to_enum(:each_pair)
        end
      end
      #
      def iterative(options={:include_inactive => true}, &block)
        result = []
        visit = Proc.new do |the_node=nil, accumulator=[]|
          node_stack = []
          if the_node
            node_stack << ({:parent => nil, :parent_selector => nil, :object => (the_node)})
            while (node_stack.size > 0) do
              a_node = node_stack.shift
              #
              if a_node[:object].is_a?(::GxG::Database::DetachedHash)
                if a_node[:object].alive?
                  a_node[:object].each_pair do |the_key, the_value|
                    node_stack << ({:parent => a_node[:object], :parent_selector => the_key, :object => the_value})
                  end
                else
                  if options[:include_inactive]
                    accumulator << a_node
                  end
                end
              end
              if a_node[:object].is_a?(::GxG::Database::DetachedArray)
                if a_node[:object].alive?
                  a_node[:object].each_with_index do |the_value, the_index|
                    node_stack << ({:parent => a_node[:object], :parent_selector => the_index, :object => the_value})
                  end
                else
                  if options[:include_inactive]
                    accumulator << a_node
                  end
                end
              end
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
      def process!(options={:include_inactive => true}, &block)
        self.iterative(options, &block)
        self
      end
      #
      def search(options={:include_inactive => true}, &block)
        results = []
        if block.respond_to?(:call)
          results = self.iterative(options, &block)
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
        if origin.is_any?(::Hash, ::Array, ::Struct, ::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
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
            if the_value.is_any?(::Array, ::Hash, ::Struct, ::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
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
    end
    #
    class PersistedHash
      #
      private
      #
      def property_destroy(the_key=nil)
        # Destroy database property record, but leave in-memory property intact - for now. (preserves key-ordinal position)
        result = false
        if the_key
          if @property_links[(key.to_s.to_sym)]
            property = @property_links[(key.to_s.to_sym)]
            # ### Delete sub-object linked to.
            the_table = nil
            the_uuid = nil
            if property[:record][:element_text_uuid].size > 0
              the_table = :element_text
              the_uuid = property[:record][:element_text_uuid]
            end
            if property[:record][:element_binary_uuid].size > 0
              the_table = :element_binary
              the_uuid = property[:record][:element_binary_uuid]
            end
            if property[:record][:element_array_uuid].size > 0
              the_table = :element_array
              the_uuid = property[:record][:element_array_uuid]
            end
            if property[:record][:element_hash_uuid].size > 0
              the_table = :element_hash
              the_uuid = property[:record][:element_hash_uuid]
            end
            case the_table
            when :element_text
              the_temp_record = @db_address[:database].connector()[:element_text].select(:dbid).where({:uuid => the_uuid}).first
              if the_temp_record
                @db_address[:database].element_destroy(@credential, :element_text, the_temp_record[:dbid])
              end
            when :element_binary
              the_temp_record = @db_address[:database].connector()[:element_binary].select(:dbid).where({:uuid => the_uuid}).first
              if the_temp_record
                @db_address[:database].element_destroy(@credential, :element_binary, the_temp_record[:dbid])
              end
            when :element_array, :element_hash
              @db_address[:database].destroy_by_uuid(@credential, the_uuid)
            end
            # ### Delete property record.
            @db_address[:database].connector()[:hash_properties].filter({:dbid => property[:linkid]}).delete
            result = true
          end
        end
        result
      end
      # Note: property_read handled by load_property_links
      def property_write(the_key=nil)
        result = false
        if the_key
          if @property_links[(the_key.to_s.to_sym)]
            the_property = @property_links[(the_key.to_s.to_sym)]
            # Save out text and binary pages if needed.
            if the_property[:content].is_a?(::String)
              if the_property[:content].size > 256
                unless the_property[:record][:element_text_uuid].size > 0
                  # create text header
                  the_uuid = ::GxG::uuid_generate
                  while @db_address[:database].connector()[:element_text].filter({:uuid => the_uuid.to_s}).count > 0 do
                    the_uuid = ::GxG::uuid_generate
                  end
                  the_property[:record][:length] = the_property[:content].size
                  the_dbid = @db_address[:database].connector()[:element_text].insert({:uuid => the_uuid.to_s, :version => the_property[:record][:version], :length => the_property[:record][:length]})
                  #
                  the_property[:record][:element_text_uuid] = the_uuid
                end
              end
            else
              if the_property[:content].is_a?(::GxG::ByteArray)
                unless the_property[:record][:element_binary_uuid].size > 0
                  # create binary header
                  the_uuid = ::GxG::uuid_generate
                  while @db_address[:database].connector()[:element_binary].filter({:uuid => the_uuid.to_s}).count > 0 do
                    the_uuid = ::GxG::uuid_generate
                  end
                  the_property[:record][:length] = the_property[:content].size
                  # format field??
                  the_dbid = @db_address[:database].connector()[:element_binary].insert({:uuid => the_uuid.to_s, :version => the_property[:record][:version], :length => the_property[:record][:length]})
                  #
                  the_property[:record][:element_binary_uuid] = the_uuid
                end
              end
            end
            # Store text pages
            if the_property[:record][:element_text_uuid].size > 0
              header_record = @db_address[:database].connector()[:element_text].filter({:uuid => the_property[:record][:element_text_uuid].to_s}).first
              if header_record
                old_segments = []
                @db_address[:database].connector()[:text_page].filter({:parent_uuid => header_record[:uuid].to_s}).order(:ordinal).each do |entry|
                  old_segments << entry[:dbid]
                end
                if the_property[:content].size == 0
                  # delete all text_pages if count > 0
                  if old_segments.size > 0
                    @db_address[:database].connector()[:text_page].filter({:parent_uuid => (header_record[:uuid])}).order(:ordinal).delete
                  end
                else
                  new_segments = ::GxG::apportioned_ranges(the_property[:content].size, 4096)
                  if old_segments.size > new_segments.size
                    the_count = old_segments.size
                  else
                    the_count = new_segments.size
                  end
                  manifest = []
                  (0..(the_count - 1)).each do |the_ordinal|
                    if new_segments[(the_ordinal)] and old_segments[(the_ordinal)]
                      #overwrite with new segment range
                      manifest << {:operation => :overwrite, :dbid => (old_segments[(the_ordinal)]), :ordinal => (the_ordinal), :portion => (new_segments[(the_ordinal)])}
                    else
                      if new_segments[(the_ordinal)]
                        # create new segment at this ordinal
                        manifest << {:operation => :create, :ordinal => (the_ordinal), :portion => (new_segments[(the_ordinal)])}
                      else
                        # delete old segment
                        manifest << {:operation => :delete, :dbid => (old_segments[(the_ordinal)])}
                      end
                    end
                  end
                  #
                  manifest.each do |action|
                    case action[:operation]
                    when :overwrite
                      @db_address[:database].element_update(:text_page,{:dbid => action[:dbid]},{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => the_property[:content][(action[:portion])].size, :content => the_property[:content][(action[:portion])]})
                      # @db_address[:database].connector()[:text_page].filter({:dbid => (action[:dbid])}).update({:ordinal => (action[:ordinal]), :length => (@content[(action[:portion])].size), :content => (@content[(action[:portion])])})
                    when :create
                      new_dbid = @db_address[:database].element_create(:text_page,{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => the_property[:content][(action[:portion])].size, :content => the_property[:content][(action[:portion])]})
                      # @db_address[:database].connector()[:text_page].insert({:parent_uuid => (record[:uuid]), :ordinal => (action[:ordinal]), :length => (@content[(action[:portion])].size), :content => (@content[(action[:portion])])})
                    when :delete
                      @db_address[:database].element_destroy(@credential,:text_page,action[:dbid])
                      # @db_address[:database].connector()[:text_page].filter({:dbid => (action[:dbid])}).delete
                    end
                  end
                  #
                end
              end
            else
              if the_property[:record][:element_binary_uuid].size > 0
                header_record = @db_address[:database].connector()[:element_binary].filter({:uuid => the_property[:record][:element_binary_uuid].to_s}).first
                if header_record
                  old_segments = []
                  @db_address[:database].connector()[:binary_page].filter({:parent_uuid => header_record[:uuid].to_s}).order(:ordinal).each do |entry|
                    old_segments << entry[:dbid]
                  end
                  if the_property[:content].size == 0
                    # delete all text_pages if count > 0
                    if old_segments.size > 0
                      @db_address[:database].connector()[:binary_page].filter({:parent_uuid => (header_record[:uuid])}).order(:ordinal).delete
                    end
                  else
                    new_segments = ::GxG::apportioned_ranges(the_property[:content].size, 65536)
                    if old_segments.size > new_segments.size
                      the_count = old_segments.size
                    else
                      the_count = new_segments.size
                    end
                    manifest = []
                    (0..(the_count - 1)).each do |the_ordinal|
                      if new_segments[(the_ordinal)] and old_segments[(the_ordinal)]
                        #overwrite with new segment range
                        manifest << {:operation => :overwrite, :dbid => (old_segments[(the_ordinal)]), :ordinal => (the_ordinal), :portion => (new_segments[(the_ordinal)])}
                      else
                        if new_segments[(the_ordinal)]
                          # create new segment at this ordinal
                          manifest << {:operation => :create, :ordinal => (the_ordinal), :portion => (new_segments[(the_ordinal)])}
                        else
                          # delete old segment
                          manifest << {:operation => :delete, :dbid => (old_segments[(the_ordinal)])}
                        end
                      end
                    end
                    #
                    manifest.each do |action|
                      case action[:operation]
                      when :overwrite
                        @db_address[:database].element_update(:binary_page,{:dbid => action[:dbid]},{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => the_property[:content][(action[:portion])].size, :content => the_property[:content][(action[:portion])]})
                        # @db_address[:database].connector()[:text_page].filter({:dbid => (action[:dbid])}).update({:ordinal => (action[:ordinal]), :length => (@content[(action[:portion])].size), :content => (@content[(action[:portion])])})
                      when :create
                        new_dbid = @db_address[:database].element_create(:binary_page,{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => the_property[:content][(action[:portion])].size, :content => the_property[:content][(action[:portion])]})
                        # @db_address[:database].connector()[:text_page].insert({:parent_uuid => (record[:uuid]), :ordinal => (action[:ordinal]), :length => (@content[(action[:portion])].size), :content => (@content[(action[:portion])])})
                      when :delete
                        @db_address[:database].element_destroy(@credential,:binary_page,action[:dbid])
                        # @db_address[:database].connector()[:text_page].filter({:dbid => (action[:dbid])}).delete
                      end
                    end
                    #
                  end
                end
              end
            end
            # ### Create new property record if missing: otherwise just update it.
            if the_property[:linkid] == nil || the_property[:linkid] == 0
              the_property[:linkid] = @db_address[:database].connector()[:hash_properties].insert(the_property[:record])
            else
              @db_address[:database].connector()[:hash_properties].filter({:dbid => the_property[:linkid]}).update(the_property[:record])
            end
            #
            the_property[:state] = the_property[:content].hash
            result = true
          end
        end
        result
      end
      #
      def load_property_links
        #
        result = true
        begin
          if @db_address
            if @db_address[:database].is_a?(::GxG::Database::Database)
              if @db_address[:database].open?()
                new_links = {}
                the_records = @db_address[:database].connector()[:hash_properties].filter({:parent_uuid => @uuid.to_s}).order(:ordinal)
                the_records.each do |entry|
                  # :property_name => {:linkid => 0, :content => nil, :loaded => false, :state => 0, :record => {}}
                  the_key = entry[:property].to_sym
                  new_links[(the_key)] = {:linkid => entry.delete(:dbid), :content => nil, :loaded => false, :state => 0, :record => entry}
                  # Load indicated :content
                  case new_links[(the_key)][:record][:element]
                  when "element_boolean"
                    case new_links[(the_key)][:record][:element_boolean]
                    when -1
                      new_links[(the_key)][:content] = nil
                      new_links[(the_key)][:loaded] = true
                    when 0
                      new_links[(the_key)][:content] = false
                      new_links[(the_key)][:loaded] = true
                    when 1
                      new_links[(the_key)][:content] = true
                      new_links[(the_key)][:loaded] = true
                    end
                  when "element_integer"
                    new_links[(the_key)][:content] = new_links[(the_key)][:record][:element_integer]
                    new_links[(the_key)][:loaded] = true
                  when "element_float"
                    new_links[(the_key)][:content] = new_links[(the_key)][:record][:element_float]
                    new_links[(the_key)][:loaded] = true
                  when "element_bigdecimal"
                    new_links[(the_key)][:content] = ::BigDecimal.new(new_links[(the_key)][:record][:element_bigdecimal].to_s)
                    new_links[(the_key)][:loaded] = true
                  when "element_datetime"
                    new_links[(the_key)][:content] = new_links[(the_key)][:record][:element_datetime]
                    if new_links[(the_key)][:content].is_a?(::Time)
                      new_links[(the_key)][:content] = new_links[(the_key)][:content].to_datetime()
                    end
                    new_links[(the_key)][:loaded] = true
                  when "element_text"
                    if new_links[(the_key)][:record][:element_text_uuid].size > 0
                      # Load full text content from pages
                      new_links[(the_key)][:content] = ""
                      @db_address[:database].connector()[:text_page].filter({:parent_uuid => new_links[(the_key)][:record][:element_text_uuid].to_s}).order(:ordinal).each do |text_page|
                        new_links[(the_key)][:content] << text_page[:content]
                     end
                    else
                      new_links[(the_key)][:content] = new_links[(the_key)][:record][:element_text]
                    end
                    new_links[(the_key)][:loaded] = true
                  when "element_binary"
                    # Load binary data
                    new_links[(the_key)][:content] = ::GxG::ByteArray.new
                    new_links[(the_key)][:loaded] = false
                    # Review : support on-read segment loading and property unloading. (thinking of large binary files here)
                  when "element_array"
                    # Load PersistedArray
                    new_links[(the_key)][:content] = @db_address[:database].retrieve_by_uuid(new_links[(the_key)][:record][:element_array_uuid].to_s.to_sym, @credential, (@reservation || @delegate))
                    if new_links[(the_key)][:content].is_a?(::GxG::Database::PersistedArray)
                      new_links[(the_key)][:loaded] = true
                      new_links[(the_key)][:state] = new_links[(the_key)][:content].hash
                      new_links[(the_key)][:content].set_parent(self)
                    else
                      new_links[(the_key)][:loaded] = false
                    end
                  when "element_hash"
                    # Load PersistedHash
                    # Review : HOW to keep the version info updated when the sub-object changes happen?? objects have ZERO knowledge of thier parent properties.
                    # Maybe: @ object --> @parent.update_property_version(self,version) : it can match on :content and property_write(key) of found item.
                    new_links[(the_key)][:content] = @db_address[:database].retrieve_by_uuid(new_links[(the_key)][:record][:element_hash_uuid].to_s.to_sym, @credential, (@reservation || @delegate))
                    if new_links[(the_key)][:content].is_a?(::GxG::Database::PersistedHash)
                      new_links[(the_key)][:loaded] = true
                      new_links[(the_key)][:state] = new_links[(the_key)][:content].hash
                      new_links[(the_key)][:content].set_parent(self)
                    else
                      new_links[(the_key)][:loaded] = false
                    end
                  end
                end
                # xxx
                # :property_name => {:linkid => 0, :table => :unspecified, :dbid => 0, :ordinal => 0, :element => nil}
                # link_record => {:dbid => 0, :parent_uuid => "", :property => "", :ordinal => 0, :element => 0, :elementid => 0}
                # the_links = @db_address[:database].connector()[:hash_links].filter({:parent_uuid => @uuid.to_s}).order(:ordinal)
                # the_links.each do |entry|
                #   #
                #   the_key = entry[:property].to_sym
                #   new_links[(the_key)] = {:linkid => (entry[:dbid])}
                #   new_links[(the_key)][:table] = ::GxG::Database::Database::element_table_by_index(entry[:element])
                #   new_links[(the_key)][:dbid] = entry[:elementid]
                #   new_links[(the_key)][:ordinal] = entry[:ordinal]
                #   # TODO: load element based upon setting in Database: :immediate or :lazy (default)
                #   new_links[(the_key)][:element] = nil
                #   if @property_links[(the_key)]
                #     if @property_links[(the_key)][:element]
                #       new_links[(the_key)][:element] = @property_links[(the_key)][:element]
                #     end
                #   end
                # end
                # xxx
                @property_links = new_links
              else
                raise Exception, "Database not available"
              end
            else
              raise Exception, "Invalid Database object"
            end
          else
            # Deactivated
            result = false
          end
        rescue Exception => the_error
          result = false
          log_error({:error => the_error})
        end
        result
      end
      #
      def refresh_ordinals()
        if self.alive?
          if @db_address[:database].open?
            @property_links.keys.each_with_index do |the_key, ordinal|
              @property_links[(the_key)][:record][:ordinal] = ordinal
              @db_address[:database].connector()[:hash_properties].filter({:dbid => @property_links[(the_key)][:linkid]}).update({:ordinal => (ordinal)})
            end
          end
        end
      end
      #
      public
      #
      def assimilate_detached(detached_object=nil)
        result = false
        if detached_object.is_a?(::GxG::Database::DetachedHash)
          # Review : ?? the ability to ingest a detached_object's data while retaining self's identity data. worth it ??
          object_db = [{:destination => self, :source => detached_object}]
          while object_db.size > 0 do
            pair = object_db.shift
            if pair
              pair[:source].search do |item, selector, container|
                if item.is_any?(::GxG::Database::DetachedArray, ::GxG::Database::DetachedHash)
                  if item.is_a?(::GxG::Database::DetachedHash)
                    unless pair[:destination][(selector)].is_a?(::GxG::Database::PersistedHash)
                      pair[:destination][(selector)] = @db_address[:database].try_persist({}, @credential, {:with_uuid => item.uuid.to_s, :with_title => item.title.to_s, :with_version => item.version, :with_format => item.format})
                    end
                    object_db << [{:destination => pair[:destination][(selector)], :source => item}]
                  else
                    if item.is_a?(::GxG::Database::DetachedArray)
                      unless pair[:destination][(selector)].is_a?(::GxG::Database::PersistedArray)
                        pair[:destination][(selector)] = @db_address[:database].try_persist([], @credential, {:with_uuid => item.uuid.to_s, :with_title => item.title.to_s, :with_version => item.version, :with_constraint => item.constraint})
                      end
                      object_db << [{:destination => pair[:destination][(selector)], :source => item}]
                    end
                  end
                  #
                else
                  pair[:destination][(selector)] = item
                end
              end
            end
          end
          #
          result = true
        end
        result
      end
      #
      def detach()
        ::GxG::Database::detached_import(self.export())
      end
      # ### OpenStruct Integration
      def as_structure()
        ::OpenStruct.new(self)
      end
      # Review : favor the following more Ruby-like accessors over the set_xxx style methods, eliminate older duplicate methods.
      def uuid()
          @uuid.clone
      end
      #
      def uuid=(the_uuid=nil)
        if GxG::valid_uuid?(the_uuid)
          @uuid = the_uuid.to_s.to_sym
        end
      end
      #
      def title()
          @title.clone
      end
      #
      def title=(the_title=nil)
        if the_title
          @title = the_title.to_s[0..255]
          self.increment_version
        end
      end
      #
      def version()
        @version.clone
      end
      #
      def version=(the_version=nil)
        if the_version.is_a?(::Numeric)
          @version = (((the_version.to_f) * 10000.0).to_i.to_f / 10000.0)
        end
      end
      #
      def element_version(key=nil)
        result = 0.0
        if key.is_a?(::Symbol)
          if key.to_s.size > 256
            log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
            key = key.to_s[(0..255)].to_sym
          end
          #
          if @property_links[(key.to_s.to_sym)]
            result = @property_links[(key.to_s.to_sym)][:record][:version]
          else
            result = 0.0
          end
          #
        end
        result
      end
      #
      def set_element_version(element_key, the_version=nil)
        result = false
        if @property_links[(element_key)]
          if the_version.is_a?(::Numeric)
            @property_links[(element_key)][:record][:version] = (((the_version.to_f) * 10000.0).to_i.to_f / 10000.0)
            result = true
          else
            log_warning("Attempted to set version to an invalid version value #{the_version.inspect} for #{element_key.inspect} on Object #{@uuid.inspect}")
          end
        else
          log_warning("Attempted to set version with an invalid key #{element_key.inspect} on Object #{@uuid.inspect}")
        end
        result
      end
      #
      def format()
        @format.clone
      end
      #
      def format=(the_format=nil)
        if GxG::valid_uuid?(the_format)
          @format = the_format.to_s.to_sym
        end
      end
      #
      def parent()
          @parent
      end
      #
      def parent=(object=nil)
        if object.is_any?([::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray])
          # Review : parent can only be set once -- is this best??
          unless @parent
            @parent = object
          end
        end
      end
      # ### Review: move to Database class as generic toolbox method at some point:
      #
      def get_permissions()
        @permission.clone
      end
      #
      def set_permissions(credential=nil, the_permission=nil)
        if self.alive?
          if credential.is_a?(::Hash) && the_permission.is_a?(::Hash)
            if credential[:user]
              if credential[:user] == "public" || credential[:user] == "Public"
                credential = "00000000-0000-4000-0000-000000000000"
              else
                credential = (@db_address[:database].user_fetch({:user_id => credential[:user].to_s}) || {})[:uuid]
              end
              if credential
                credential = credential.to_s.to_sym
              end
            else
              if credential[:group]
                credential = @db_address[:database].group_credential(credential)
              else
                credential = nil
              end
            end
          else
            if credential.is_a?(::Hash) && the_permission == nil
              the_permission = credential
              credential = @credential
            else
              unless credential
                credential = @credential
              end
            end
          end
          if the_permission.is_a?(::Hash) && ::GxG::valid_uuid?(credential)
            manifest = []
            structures = [{:table => @db_address[:table], :dbid => @db_address[:dbid]}]
            while structures.size > 0 do
              entry = structures[0]
              @db_address[:database].element_manifest(entry[:table],entry[:dbid]).each do |record|
                if [:element_hash, :element_array].include?(record[:table])
                  unless structures.include?(record)
                    structures << record
                  end
                else
                  # Review - only set/get/check permissions on persisted arrays/hashes
                  # unless manifest.include?(record)
                  #   manifest << record
                  # end
                end
              end
              manifest << structures.shift
            end
            manifest.each do |record|
              @db_address[:database].assign_element_permission(record[:table], record[:dbid], credential, the_permission)
            end
            #
            true
          else
            log_error({:error => Exception.new("You MUST provide a valid permissions Hash."), :parameters => {:credential => credential, :permission => the_permission}})
            false
          end
        end
      end
      #
      def reservation()
        if self.alive?
          if @reservation.is_any?(::String, ::Symbol)
            @reservation.clone
          end
        end
      end
      #
      def write_permission?()
        @permission[:write]
      end
      #
      def write_reserved?()
        if @reservation or @delegate
          true
        else
          false
        end
      end
      #
      def release_reservation()
        if self.alive?()
          if @reservation
            @db_address[:database].release_element_locks(@reservation)
            @reservation = nil
          end
          if @delegate
            @delegate = nil
          end
          # release write-locks of all sub-items
          @property_links.keys.each do |the_key|
            if @property_links[(the_key)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
              @property_links[(the_key)][:content].release_reservation
            end
          end
        end
        true
      end
      #
      def get_reservation()
        result = false
        # Review : Experimental design change - deprecate @delegate use, require entire structure (and sub-structures) to get solid @reservation (all of them) or this fails.
        # Note : keep your structures small as this opens the door for stack-depth exceptions if it is nested too deep. (say 256 or less layers deep??)
        if @reservation
          result = true
        else
          if self.alive?
            if @permission[:write]
              clean_up_list = []
              # Review : efficiency - write locks only apply to PersistedHashes and PersistedArrays so do we need a full manifest??
              the_reservation = @db_address[:database].reserve_element_locks(@credential, (@db_address[:database].element_manifest(@db_address[:table], @db_address[:dbid])), :write)
              if the_reservation
                @reservation = the_reservation
                result = true
                #
                # @property_links.keys.each do |the_key|
                #   if @property_links[(the_key)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                #     clean_up_list << @property_links[(the_key)][:content]
                #     unless @property_links[(the_key)][:content].get_reservation()
                #       @db_address[:database].release_element_locks(the_reservation)
                #       the_reservation = nil
                #       break
                #     end
                #   end
                # end
                #
              end
              # if the_reservation
              #   result = true
              # else
              #   clean_up_list.each do |the_object|
              #     the_object.release_reservation
              #   end
              # end
            end
          end
        end
        # xxx
        # if (@reservation || @delegate)
        #   result = true
        # else
        #   if self.alive?
        #     if @permission[:write]
        #       @reservation = @db_address[:database].reserve_element_locks(@credential, (@db_address[:database].element_manifest(@db_address[:table], @db_address[:dbid])), :write)
        #       if @reservation
        #         @property_links.keys.each do |the_key|
        #           if @property_links[(the_key)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        #             @property_links[(the_key)][:content].set_delegate((@reservation || @delegate))
        #           end
        #         end
        #         result = true
        #       end
        #       #
        #     end
        #   end
        # end
        # xxx
        result
      end
      #
      def wait_for_reservation(timeout=nil)
        result = true
        the_timeout = Time.now.to_f + (timeout || 30.0).to_f
        until self.get_reservation() == true do
          sleep 1.0
          if Time.now.to_f >= the_timeout
            result = false
            break
          end
        end
        result
      end
      #
      def get_delegate()
        if self.alive?
          if @delegate.is_any?(::String, ::Symbol)
            @delegate.clone
          end
        end
      end
      #
      def set_delegate(the_delegate=nil)
        if self.alive?
          if the_delegate.is_any?([::String, ::Symbol])
            @delegate = the_delegate.to_sym
          end
        end
      end
      #
      def set_format(format_uuid=nil)
        if self.alive?
          unless @format
            if ::GxG::valid_uuid?(format_uuid)
              @format = format_uuid.to_sym
              @db_address[:database].connector()[:element_hash].filter({:dbid => (@db_address[:dbid])}).update({:format => (@format.to_s)})
            end
          end
        end
      end
      #
      def format()
        @format.clone
      end
      #
      def ufs()
        if @format
          record = @db_address[:database].format_load({:uuid => @format.to_s})
          if record
            record[:ufs]
          else
            ""
          end
        else
          ""
        end
      end
      #
      def version(key=nil)
        result = @version
        if key.is_a?(::Symbol)
          if key.to_s.size > 256
            log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
            key = key.to_s[(0..255)].to_sym
          end
          #
          if @property_links[(key.to_s.to_sym)]
            result = @property_links[(key.to_s.to_sym)][:record][:version]
          else
            result = 0.0
          end
          #
        end
        result
      end
      #
      def version=(the_version=nil)
        if the_version.is_a?(::Numeric)
          @version = ::BigDecimal.new(the_version.to_s)
        end
      end
      #
      #
      def parent()
        @parent
      end
      #
      def set_parent(object=nil)
        if self.alive?
          if object.is_any?([::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray])
            unless @parent
              @parent = object
            end
          end
        end
      end
      #
      def refresh_links()
        if self.alive?()
          unless @db_address[:database].element_in_use?(@db_address[:table], @db_address[:dbid])
            @parent = nil
          end
        end
      end
      #
      def increment_version()
        if self.alive?
          if @db_address[:database].open?
            if self.write_reserved?()
              @version += 0.0001
            end
          end
        end
      end
      #
      def save_version()
        @db_address[:database].connector()[:element_hash].filter({:dbid => @db_address[:dbid]}).update({:version => @version})
      end
      #
      def set_version(the_version=0.0)
        if self.write_reserved?()
          @version = (((the_version.to_f) * 10000.0).to_i.to_f / 10000.0)
          self.save_version
        end
      end
      #
      def set_title(the_title=nil)
        if self.alive?
          if @db_address[:database].open?
            if self.write_reserved?()
              if the_title
                @title = the_title.to_s[0..255]
                @db_address[:database].connector()[:element_hash].filter({:dbid => @db_address[:dbid]}).update({:title => @title})
                self.increment_version
              end
            end
          end
        end
      end
      #
      def initialize(settings = {}, options={})
        # mount element: {:database => <database>, :uuid => <uuid>, :credential => <uuid>, :delegate => nil/<uuid>, :parent => nil/<an-object>}
        # create element: {:database => <database>, :credential => <uuid>, :delegate => nil/<uuid>, :parent => nil/<an-object>}
        # 
        if settings.is_a?(::Hash)
          unless ::GxG::valid_uuid?(settings[:credential])
            raise ArgumentError, "You must supply a valid credential UUID (37 character limit) as a String or Symbol"
          end
          @quick = settings[:quick]
          @credential = settings[:credential].to_sym
          @reservation = nil
          @delegate = settings[:delegate]
          if settings[:parent].is_any?([::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray])
            @parent = settings[:parent]
          else
            @parent = nil
          end
          if settings[:database].is_a?(::GxG::Database::Database)
            if settings[:database].open?()
              # note - rewrite.  if create then as subset, eventually will always mount if all checks out.
              the_uuid = settings[:uuid]
              if the_uuid.is_a?(::Symbol)
                the_uuid = the_uuid.to_s
              end
              # TODO: validate uuid pattern
              if settings[:title].is_a?(::String)
                the_title = settings[:title]
              else
                if options[:with_title]
                  the_title = options[:with_title]
                else
                  the_title = ("Untitled PersistedHash " << (settings[:database].connector()[:element_hash].count.to_s))
                end
              end
              @format = settings[:format]
              unless @format
                if options[:with_format]
                  @format = options[:with_format]
                end
              end
              unless the_uuid
                # without specifying a uuid, the implied intent is to create a new PersistedHash
                if ::GxG::valid_uuid?(options[:with_uuid])
                  the_uuid = options[:with_uuid].to_s
                else
                  the_uuid = ::GxG::uuid_generate()
                  while ((settings[:database].connector()[:element_hash].filter({:uuid => the_uuid}).count > 0) or (settings[:database].connector()[:element_array].filter({:uuid => the_uuid}).count > 0))
                    the_uuid = ::GxG::uuid_generate()
                  end
                end
                # creat blank hash record
                new_dbid = settings[:database].connector()[:element_hash].insert({:uuid => (the_uuid), :title => (the_title), :format => (@format.to_s), :version => (options[:with_version] || BigDecimal.new("0.0"))})
                #
                @db_address = {:database => (settings[:database]), :table => :element_hash, :dbid => (new_dbid)}
                if @parent
                  @permission = @parent.get_permissions()
                  # settings[:database].enforce_permission_policy({:action => :extend, :credential => @credential, :source => settings[:parent], :destination => self})
                  # settings[:database].extend_element_permissions(settings[:parent].db_address()[:table], settings[:parent].db_address()[:dbid], :element_hash, new_dbid)
                else
                  # create raw permissions for this element
                  @permission = {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true}
                  # settings[:database].assign_element_permission(:element_hash, new_dbid, @credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                  # settings[:database].enforce_permission_policy({:action => :extend, :credential => @credential, :source => self, :destination => self})
                end
                settings[:database].assign_element_permission(:element_hash, new_dbid, @credential, @permission)
              end
              # mount according to uuid
              if the_uuid
                # mount
                record = settings[:database].connector()[:element_hash].filter({:uuid => (the_uuid)}).first
                if record
                  @uuid = the_uuid.to_sym
                  @title = record[:title].to_s
                  @version = record[:version]
                  @db_address = {:database => (settings[:database]), :table => :element_hash, :dbid => (record[:dbid])}
                  if record[:format].to_s.size > 0
                    @format = record[:format].to_sym
                  end
                  @property_links = {}
                  #
                  unless @permission
                    @permission = @db_address[:database].effective_element_permission(@db_address[:table], @db_address[:dbid], @credential)
                  end
                  # @read_reservation = @db_address[:database].reserve_element_locks(@credential, (@db_address[:database].element_manifest(@db_address[:table], @db_address[:dbid])), :read)
                  #
                  load_property_links
                  #
                else
                  raise Exception, "Unable to mount the PersistedHash record"
                end
              else
                raise Exception, "Unable to mount the PersistedHash record"
              end
              # 
            else
              raise Exception, "Database not available for storage"
            end
            #
          else
            raise Exception, "Invalid Database object"
          end
          #
        else
          raise ArgumentError, "You must supply a hash of details"
        end
        # 
      end
      #
      def inspect()
        # FORNOW: make re-entrant (yes, I know!) Fortunately, circular links are impossible with PersistedHash.
        # TODO: make interative instead of re-entrant.
        result = "(Not Loaded)"
        if @db_address
          if @db_address[:database].element_byte_size(@db_address[:table], @db_address[:dbid]) <= 10485760
            # smaller than 10MB
            inspection_db = []
            last_key = @property_links.keys.last
            result = "{"
            @property_links.keys.each do |element_key|
              if @property_links[(element_key)][:loaded] == true
                result << (":#{element_key.to_s} => " << @property_links[(element_key)][:content].inspect)
              else
                result << (":#{element_key.to_s} => (Not Loaded)")
              end
              unless last_key == element_key
                result << ", "
              end
            end
            result << "}"
          else
            result = "(Too Damned Big)"
          end
          #
          #
          #
        end
        result
      end
      #
      def alive?()
        if @db_address
          true
        else
          false
        end
      end
      #
      def db_address()
        @db_address
      end
      #
      def deactivate()
        if self.alive?()
          @property_links.keys.each do |key|
            element = @property_links[(key)][:content]
            if element.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
              containers = [(element)]
              element.search({:include_inactive => false}) do |the_value, the_selector, the_container|
                if the_value.alive? && the_value.respond_to?(:deactivate)
                  the_value.deactivate
                end
                if the_container.alive?
                  unless containers.include?(the_container)
                      containers.unshift(the_container)
                  end
                end
                nil
              end
              containers.each do |the_container|
                the_container.deactivate
              end
            end
          end
          if self.write_reserved?()
            self.release_reservation()
          end
          @property_links = {}
          @db_address = nil
        end
        true
      end
      #
      def save()
        result = false
        if self.alive?
          begin
            if @db_address[:database].open?()
              @property_links.keys.each do |the_key|
                # Note: only save property data and header if: a) data is still loaded and b) state has changed.
                if @property_links[(the_key)][:loaded] == true
                  if @property_links[(the_key)][:state] != @property_links[(the_key)][:content].hash
                    @property_links[(the_key)][:record][:version] = (((@property_links[(the_key)][:record][:version].to_f + 0.0001) * 10000.0).to_i.to_f / 10000.0)
                    property_write(the_key)
                  end
                end
                #
              end
            else
              raise Exception, "Database not available"
            end
            self.save_version
            result = true
          rescue Exception => the_error
            log_error({:error => the_error})
          end
        end
        result
      end
      #
      def destroy()
        result = false
        if self.alive?
          begin
            unless self.write_reserved?()
              raise Exception, "You do not have a write-lock for this element"
            end
            unless @permission[:destroy]
              raise Exception, "You do not have permission to destory this element"
            end
            if @db_address[:database].open?()
              if @db_address[:database].structure_attached?(@uuid)
                raise Exception, "Element is still linked to a structure.  Use <PersistedHash>.delete(<key>).destroy or <PersistedArray>.delete_at(<index>).destroy"
              else
                if self.write_reserved?()
                  address = @db_address
                  self.deactivate
                  address[:database].element_destroy(@credential, address[:table],address[:dbid])
                  # Review : consider either emptying the db trash now, or adding a flag to manifest records to prevent future loading.
                  result = true
                else
                  raise Exception, "You do not have sufficient privileges to make this change"
                end
              end
            else
              raise Exception, "Database not available"
            end
          rescue Exception => the_error
            log_error({:error => the_error})
          end
        end
        result
      end
      #
      def size()
        @property_links.size
      end
      #
      def structure_attached?()
        @db_address[:database].structure_attached?(@uuid.to_s)
      end
      def structure_detach()
        @db_address[:database].structure_detach(@uuid.to_s)
      end
      #
      def keys()
        @property_links.keys
      end
      #
      def []=(key=nil, value=nil)
        # Only works with Symbols.
        unless self.alive?()
          raise Exception, "Attempted to alter a defunct structure"
        end
        unless @db_address[:database].open?()
          raise Exception, "Database not available"
        end
        result = nil
        if key.is_a?(::Symbol)
          if key.to_s.size > 256
            log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
            key = key.to_s[(0..255)].to_sym
          end
          property_key = key.to_s.to_sym
          # Review : rewrite ????
          if value.is_any?(::GxG::Database::Database::valid_field_classes()) || value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray, ::Hash, ::Array)
            unless self.write_reserved?()
              self.get_reservation()
            end
            if self.write_reserved?()
              # Further screen value provided:
              # ### Check provided PersistedHashes and PersistedArrays
              if value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                unless value.db_address()
                  raise Exception, "The structure you are attaching is Deactivated (not supported)."
                end
                if value.structure_attached?()
                  # Review : experimental - auto-detach from prior structural relationship and reassign here.
                  # raise Exception, "Cross linked structures not supported"
                  unless value.write_reserved?()
                    value.get_reservation()
                  end
                  if value.write_reserved?()
                    value.structure_detach
                  else
                    raise Exception, "Unable to secure write-reservation for this structural change."
                  end
                end
                value.search do |the_value, the_selector, the_container|
                  if the_value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    unless the_value.db_address()
                      raise Exception, "The structure you are attaching has a Deactivated item within it (not supported)."
                    end
                  end
                end
              end
              # ### Check provided Hashes and Arrays
              if value.is_any?(::Hash, ::Array)
                value.search do |the_value, the_selector, the_container|
                  if the_value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    unless the_value.db_address()
                      raise Exception, "The structure you are attaching has a Deactivated item within it (not supported)."
                    end
                    if @db_address[:database].structure_attached?(the_value.uuid.to_s) && the_container.is_any?(::Hash, ::Array)
                      raise Exception, "The structure you are attaching has a cross-linked structure within it (cross linked structures not supported)."
                    end
                  end
                  unless the_value.is_any?(::GxG::Database::Database::valid_field_classes()) || the_value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray, ::Hash, ::Array)
                    raise Exception, "The structure you are attaching has an unpersistable item within it (not supported)."
                  end
                end
              end
              # ### Property Exists?
              if @property_links[(key.to_s.to_sym)]
                # set property to value
                operation = :set_value
              else
                if @format
                  raise Exception, "Formatted - the structure cannot be altered"
                else
                  # add property : value pair
                  operation = :add_value
                end
              end
              # ### Prepare new value
              new_value = {
                :linkid => nil,
                :content => nil,
                :loaded => false,
                :state => 0,
                :record => {
                  :parent_uuid => @uuid.to_s,
                  :property => key.to_s,
                  :ordinal => 0,
                  :version => ::BigDecimal.new("0.0"),
                  :element => "element_boolean",
                  :element_boolean => -1,
                  :element_integer => 0,
                  :element_float => 0.0,
                  :element_bigdecimal => ::BigDecimal.new("0.0"),
                  :element_datetime => ::DateTime.now,
                  :time_offset => 0.0,
                  :time_prior => 0.0,
                  :time_after => 0.0,
                  :length => 0,
                  :element_text => "",
                  :element_text_uuid => "",
                  :element_binary_uuid => "",
                  :element_array_uuid => "",
                  :element_hash_uuid => ""
                }
              }
              #
              if value.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                # ### Assimilate PersistedHash or PersistedArray
                new_value[:content] = value
                new_value[:loaded] = true
                new_value[:state] = new_value[:content].hash
                # Note: version is sync'd here, but don't rely upon property version with linked structures, but use structure's version method.
                new_value[:record][:version] = new_value[:content].version()
                if value.is_a?(::GxG::Database::PersistedHash)
                  new_value[:record][:element] = "element_hash"
                  new_value[:record][:element_hash_uuid] = value.uuid.to_s
                else
                  new_value[:record][:element] = "element_array"
                  new_value[:record][:element_array_uuid] = value.uuid.to_s
                end
              else
                # ### Persist Hashes and Arrays
                if value.is_any?(::Hash, ::Array)
                  new_value[:content] = @db_address[:database].iterative_persist(value,@credential)
                  new_value[:loaded] = true
                  new_value[:state] = new_value[:content].hash
                  # Note: version is sync'd here, but don't rely upon property version with linked structures, but use structure's version method.
                  new_value[:record][:version] = new_value[:content].version()
                  if value.is_a?(::Hash)
                    new_value[:record][:element] = "element_hash"
                    new_value[:record][:element_hash_uuid] = new_value[:content].uuid.to_s
                  else
                    new_value[:record][:element] = "element_array"
                    new_value[:record][:element_array_uuid] = new_value[:content].uuid.to_s
                  end
                else
                  # ### Persist Base Element Values
                  new_value[:record][:element] = ::GxG::Database::Database::element_table_for_instance(value).to_s
                  case new_value[:record][:element]
                  when "element_boolean"
                    if value.class == ::NilClass
                      new_value[:record][:element_boolean] = -1
                      new_value[:content] = nil
                    end
                    if value.class == ::FalseClass
                      new_value[:record][:element_boolean] = 0
                      new_value[:content] = false
                    end
                    if value.class == ::TrueClass
                      new_value[:record][:element_boolean] = 1
                      new_value[:content] = true
                    end
                  when "element_integer"
                    new_value[:record][:element_integer] = value
                    new_value[:content] = value
                  when "element_float"
                    new_value[:record][:element_float] = value
                    new_value[:content] = value
                  when "element_bigdecimal"
                    new_value[:record][:element_bigdecimal] = ::BigDecimal.new(value.to_s)
                    new_value[:content] = new_value[:record][:element_bigdecimal]
                  when "element_datetime"
                    new_value[:record][:element_datetime] = value
                    new_value[:content] = value
                  when "element_text"
                    if value.size > 256
                      # Note: be sure to keep text version & length sync'd with linked text element record
                      if operation == :set_value
                        new_value[:record][:version] = @property_links[(property_key)][:record][:version]
                        new_value[:record][:element_text_uuid] = @property_links[(property_key)][:record][:element_text_uuid]
                      end
                      new_value[:record][:length] = value.size
                    else
                      new_value[:record][:element_text] = value
                      new_value[:record][:length] = value.size
                    end
                    new_value[:content] = value
                  when "element_binary"
                    # Note: be sure to keep version & length sync'd with linked binary element record
                    if operation == :set_value
                      new_value[:record][:version] = @property_links[(property_key)][:record][:version]
                      new_value[:record][:element_binary_uuid] = @property_links[(property_key)][:record][:element_binary_uuid]
                    end
                    new_value[:record][:length] = value.size
                    new_value[:content] = value
                  else
                    raise Exception, "Unable to map an element type for value: #{value.inspect}"
                  end
                end
              end
              # ### Commit Changes
              case operation
              when :set_value
                # Note: Set In-memory value only, don't save unless you have to.
                if new_value[:content].is_a?(@property_links[(property_key)][:content].class) || ([true, false, nil].include?(new_value[:content]) && [true, false, nil].include?(@property_links[(property_key)][:content]))
                  # Replace value directly, but don't save yet unless you have to (:state refers to the last 'loaded-in-from-db' state of the data).
                  new_value[:linkid] = @property_links[(property_key)][:linkid]
                  if new_value[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (@property_links[(property_key)][:record][:version] + 0.0001)
                  end
                  new_value[:record][:ordinal] = @property_links[(property_key)][:record][:ordinal]
                  new_value[:loaded] = true
                  new_value[:state] = @property_links[(property_key)][:state]
                  # ### Did string grow or shrink crossing the threshold??
                  if new_value[:content].is_a?(::String)
                    if (@property_links[(property_key)][:content].size > 256 && new_value[:content].size <= 256)
                      # shrank - delete text object and pages as well as property record (slow)
                      property_destroy(property_key)
                      @property_links[(property_key)] = new_value
                      property_write(property_key)
                    else
                      if (@property_links[(property_key)][:content].size <= 256 && new_value[:content].size > 256)
                        # grew - create text object and pages (a little less slow)
                        @property_links[(property_key)] = new_value
                        property_write(property_key)
                      else
                        # N/A
                        @property_links[(property_key)] = new_value
                      end
                    end
                  else
                    # N/A
                    @property_links[(property_key)] = new_value
                  end
                  if new_value[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    # Note: this ensures attachment to this object
                    property_write(property_key)
                  end
                  #
                else
                  # Other class value being substituted.
                  if new_value[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (@property_links[(property_key)][:record][:version] + 0.0001)
                  end
                  new_value[:record][:ordinal] = @property_links[(property_key)][:record][:ordinal]
                  new_value[:loaded] = true
                  # Destroy old property record on db, and associated linked objects.
                  # Review : this is slow - look into optimizations here.
                  if @property_links[(property_key)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray, ::GxG::ByteArray, ::String)
                    if @property_links[(property_key)][:content].is_a?(::String)
                      if (@property_links[(property_key)][:content].size > 256 && new_value[:content].to_s.size <= 256) || (@property_links[(property_key)][:content].size <= 256 && new_value[:content].to_s.size > 256)
                        property_destroy(property_key)
                      end
                    else
                      property_destroy(property_key)
                    end
                  end
                  #
                  @property_links[(property_key)] = new_value
                  property_write(property_key)
                end
                #
              when :add_value
                # Note: set in-memory value and save.
                if new_value[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                  new_value[:record][:version] = new_value[:content].version()
                else
                  new_value[:record][:version] = ::BigDecimal.new("0.0")
                end
                new_value[:record][:ordinal] = @property_links.keys.size
                new_value[:loaded] = true
                #
                @property_links[(property_key)] = new_value
                # Review : is this wise to do this here??
                property_write(property_key)
                # self.refresh_ordinals ??
              end
              # ### Handle coordination between persisted objects:
              if @property_links[(property_key)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                # ### Extend Reservation to persisted objects ( Review : does this slow it down too much?? )
                @property_links[(property_key)][:content].release_reservation
                @db_address[:database].reservation_add_element((@reservation || @delegate), (@property_links[(property_key)][:content].db_address()[:table]), @property_links[(property_key)][:content].db_address()[:dbid])
                @property_links[(property_key)][:content].set_delegate((@reservation || @delegate))
                # ### Extend Permissions to persisted object
                @db_address[:database].extend_element_permissions(@db_address[:table],@db_address[:dbid],@property_links[(property_key)][:content].db_address()[:table],@property_links[(property_key)][:content].db_address()[:dbid])
                @db_address[:database].enforce_permission_policy({:action => :extend, :credential => @credential, :source => self, :destination => @property_links[(property_key)][:content]})
                #
                @property_links[(property_key)][:content].set_parent(self)
              end
              #
              self.increment_version()
              result = @property_links[(property_key)][:content]
              #
            else
              raise Exception, "You do not have sufficient privileges to make this change. (write-reservation)"
            end
          else
            raise Exception, "The value is not persistable."
          end
        else
          raise Exception, "You must provide a property key in the form of a Symbol."
        end
        result
      end
      #
      def unload(key=nil)
        result = false
        # if key exists
        # if key is loaded, unload element (if String or ByteArray)
        if self.alive?()
          if @db_address[:database].open?()
            if key.is_a?(::Symbol)
              if key.to_s.size > 256
                log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
                key = key.to_s[(0..255)].to_sym
              end
              property_key = key.to_s.to_sym
              if @property_links[(property_key)]
                if @property_links[(property_key)][:content].is_any?(::String, ::GxG::ByteArray)
                  if @property_links[(property_key)][:loaded] == true
                    # ### Unload Base Element contents from memory, leaving reference harness intact and active.
                    @property_links[(property_key)][:content].clear
                    @property_links[(property_key)][:loaded] = false
                  end
                end
                result = true
              end
            else
              raise ArgumentError, "You must specify with a Symbol, not a #{key.class.inspect}"
            end
          else
            raise Exception, "Database not available"
          end
        else
          raise Exception, "Attempted to access a defunct structure"
        end
        result
      end
      #
      def [](key=nil)
        result = nil
        # if key exists
        # if key is not loaded, load element (if String or ByteArray)
        if self.alive?()
          if @db_address[:database].open?()
            if key.is_a?(::Symbol)
              if key.to_s.size > 256
                log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
                key = key.to_s[(0..255)].to_sym
              end
              property_key = key.to_s.to_sym
              if @property_links[(property_key)]
                if @property_links[(property_key)][:content].is_any?(::String, ::GxG::ByteArray)
                  unless @property_links[(property_key)][:loaded] == true
                    # ### Load Base Element contents from the database.
                    if @property_links[(property_key)][:content].is_a?(::String)
                      if @property_links[(property_key)][:record][:element_text_uuid].to_s.size > 0
                        @db_address[:database].connector()[:text_page].filter({:parent_uuid => @property_links[(property_key)][:record][:element_text_uuid].to_s}).order(:ordinal).each do |text_page|
                          @property_links[(property_key)][:content] << text_page[:content]
                        end
                      else
                        @property_links[(property_key)][:content] = @property_links[(property_key)][:record][:element_text].to_s
                      end
                    else
                      @db_address[:database].connector()[:binary_page].filter({:parent_uuid => @property_links[(property_key)][:record][:element_binary_uuid].to_s}).order(:ordinal).each do |binary_page|
                        @property_links[(property_key)][:content] << binary_page[:content]
                      end
                    end
                    @property_links[(property_key)][:loaded] = true
                  end
                end
                result = @property_links[(property_key)][:content]
              end
            else
              raise ArgumentError, "You must specify with a Symbol, not a #{key.class.inspect}"
            end
          else
            raise Exception, "Database not available"
          end
        else
          raise Exception, "Attempted to access a defunct structure"
        end
        result
      end
      #
      def include?(the_key)
        @property_links.include?(the_key)
      end
      #
      def delete(key=nil)
        result = nil
        # if key exists
        # if key is not loaded, load element
        if self.alive?()
          if @db_address[:database].open?()
            if key.is_a?(::Symbol)
              if key.to_s.size > 256
                log_warn({:warning => "Attempted oversized key usage (limited to 256 characters), truncated #{key.inspect} to #{key.to_s[(0..255)].to_sym.inspect}"})
                key = key.to_s[(0..255)].to_sym
              end
              if @format
                raise Exception, "Formatted - the structure cannot be altered"
              else
                if self.write_reserved?()
                  property_key = key.to_s.to_sym
                  #
                  if @property_links[(property_key)]
                    # This will load the unloaded prior to separation.
                    result = self[(property_key)]
                    the_link = @property_links.delete(property_key)
                    if the_link[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                      the_link[:content].save
                      the_link[:content].release_reservation()
                      @db_address[:database].reservation_remove_element((@reservation || @delegate), the_link[:content].db_address()[:table], the_link[:content].db_address()[:dbid])
                    else
                      # Eliminate orphaned text and binary objects in the database. They will exist only in memory.
                      if the_link[:content].is_any?(::String, ::GxG::ByteArray)
                        if the_link[:content].is_a?(::String)
                          if the_link[:content].size > 256
                            # eliminate text object and pages.
                            the_temp_record = @db_address[:database].connector()[:element_text].select(:dbid).where({:uuid => the_link[:record][:element_text_uuid]}).first
                            if the_temp_record
                              @db_address[:database].element_destroy(@credential, :element_text, the_temp_record[:dbid])
                            end
                          end
                        end
                        if the_link[:content].is_a?(::GxG::ByteArray)
                          # eliminate binary object and pages.
                          the_temp_record = @db_address[:database].connector()[:element_binary].select(:dbid).where({:uuid => the_link[:record][:element_binary_uuid]}).first
                          if the_temp_record
                            @db_address[:database].element_destroy(@credential, :element_binary, the_temp_record[:dbid])
                          end
                        end
                      end
                    end
                    @db_address[:database].connector()[:hash_properties].filter({:dbid => the_link[:linkid]}).delete
                    refresh_ordinals
                    self.increment_version()
                  end
                  #
                else
                  raise Exception, "You do not have sufficient privileges to make this change"
                end
              end
            else
              raise ArgumentError, "You must specify with a Symbol, not a #{key.class.inspect}"
            end
          else
            raise Exception, "Database not available"
          end
        else
          raise Exception, "Attempted to access a defunct structure"
        end
        result
      end
      #
      def unpersist()
        result = {}
        if self.alive?
          #
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
          # Build up export_db:
          self.search do |the_value, the_selector, the_container|
            if the_value.is_a?(::GxG::Database::PersistedHash)
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {}}
            else
              if the_value.is_a?(::GxG::Database::PersistedArray)
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => []}
              else
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => the_value}
              end
            end
          end
          # Collect children export content:
          link_db =[(export_db[0])]
          while link_db.size > 0 do
            entry = link_db.shift
            children_of.call(entry[:object]).each do |the_child|
              entry[:record][(the_child[:parent_selector])] = the_child[:record]
              if the_child[:object].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                link_db << the_child
              end
            end
          end
          #
        end
        result
      end
      #
      def import_update(the_record=nil)
        if self.alive?
          if the_record.is_a?(::Hash)
            if @uuid == the_record[:uuid].to_s.to_sym
              if @reservation
                had_reservation = true
                self.release_reservation
              else
                had_reservation = false
              end
              @db_address[:database].synchronize_records([{:operation => :merge, :data => the_record}],@credential)
              @property_links = {}
              load_property_links
              if had_reservation
                self.get_reservation
              end
            end
          end
        end
        self
      end
      #
      def export(options={:exclude_file_segments=>false})
        if self.alive?
          exclude_file_segments = (options[:exclude_file_segments] || false)
          if options[:clone] == true
            # Review : why are cloned objects unformatted? sync issues??
            result = {:type => :element_hash, :uuid => GxG::uuid_generate.to_s.to_sym, :title => @title.clone, :version => ::BigDecimal.new(@version.to_s).to_s("F"), :content => {}}
          else
            result = {:type => :element_hash, :uuid => @uuid.clone, :title => @title.clone, :version => ::BigDecimal.new(@version.to_s).to_s("F"), :format => @format.clone, :content => {}}
          end
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
          # Build up export_db:
          self.search do |the_value, the_selector, the_container|
            if the_value.is_a?(::GxG::Database::PersistedHash)
              if options[:clone] == true
                the_uuid = GxG::uuid_generate.to_s.to_sym
              else
                the_uuid = the_value.uuid().clone
              end
              if (exclude_file_segments == true) && (the_selector == :file_segments || the_selector == :segments || the_selector == :portions)
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => {}, :record => {:type => :element_hash, :uuid => the_uuid, :title => the_value.title().clone, :version => ::BigDecimal.new(the_value.version().to_s).to_s("F"), :format => the_value.format().clone, :content => {}}}
              else
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => :element_hash, :uuid => the_uuid, :title => the_value.title().clone, :version => ::BigDecimal.new(the_value.version().to_s).to_s("F"), :format => the_value.format().clone, :content => {}}}
              end
            end
            if the_value.is_a?(::GxG::Database::PersistedArray)
              if options[:clone] == true
                the_uuid = GxG::uuid_generate.to_s.to_sym
              else
                the_uuid = the_value.uuid().clone
              end
              if (exclude_file_segments == true) && (the_selector == :file_segments || the_selector == :segments || the_selector == :portions)
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => [], :record => {:type => :element_array, :uuid => the_uuid, :title => the_value.title().clone, :version => ::BigDecimal.new(the_value.version().to_s).to_s("F"), :constraint => the_value.constraint().clone, :content => []}}
              else
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => :element_array, :uuid => the_uuid, :title => the_value.title().clone, :version => ::BigDecimal.new(the_value.version().to_s).to_s("F"), :constraint => the_value.constraint().clone, :content => []}}
              end
            end
            if the_value.is_any?(::GxG::Database::Database::valid_field_classes())
              data_type = GxG::Database::Database::element_table_for_instance(the_value)
              case data_type
              when :element_bigdecimal
                data = the_value.to_s("F")
              when :element_datetime
                data = the_value.to_s
              when :element_binary
                data = the_value.to_s.encode64
              when :element_text
                data = the_value.to_s
              else
                data = the_value
              end              
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => data_type, :version => (::BigDecimal.new(the_container.element_version(the_selector).to_s) || ::BigDecimal.new("0.0")).to_s("F"), :content => data}}
            end
          end
          # Collect children export content:
          link_db = [(export_db[0])]
          while link_db.size > 0 do
            entry = link_db.shift
            children_of.call(entry[:object]).each do |the_child|
              entry[:record][:content][(the_child[:parent_selector])] = the_child[:record]
              if the_child[:object].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                link_db << the_child
              end
            end
          end
        else
          result = nil
        end
        #
        result
      end
      #
      def export_package(options={:exclude_file_segments=>false})
        self.save
        result = {:formats => {}, :records => []}
        object_record = self.export(options)
        object_record.search do |item,selector,container|
          if selector == :format || selector == :constraint
            if item.to_s.size > 0
              format_uuid = item
              unless result[:formats][(format_uuid.to_s.to_sym)].is_a?(::Hash)
                format_sample = @db_address[:database].format_load({:uuid => format_uuid.to_s.to_sym})
                format_sample[:content] = format_sample[:content].gxg_export()
                result[:formats][(format_uuid.to_s.to_sym)] = format_sample
              end
            end
          end
        end
        result[:records] << object_record
        result
      end
      #
      def each_pair(&block)
        collection = {}
        @property_links.keys.each do |key|
          collection[(key)] = (self[(key)])
        end
        if block.respond_to?(:call)
          collection.to_enum(:each_pair).each do |key,value|
            block.call(key,value)
          end
        else
          collection.to_enum(:each_pair)
        end
      end
      #
      def iterative(options={:include_inactive => true}, &block)
        result = []
        visit = Proc.new do |the_node=nil, accumulator=[]|
          node_stack = []
          if the_node
            node_stack << ({:parent => nil, :parent_selector => nil, :object => (the_node)})
            while (node_stack.size > 0) do
              a_node = node_stack.shift
              #
              if a_node[:object].is_a?(::GxG::Database::PersistedHash)
                if a_node[:object].alive?
                  a_node[:object].each_pair do |the_key, the_value|
                    node_stack << ({:parent => a_node[:object], :parent_selector => the_key, :object => the_value})
                  end
                else
                  if options[:include_inactive]
                    accumulator << a_node
                  end
                end
              end
              if a_node[:object].is_a?(::GxG::Database::PersistedArray)
                if a_node[:object].alive?
                  a_node[:object].each_with_index do |the_value, the_index|
                    node_stack << ({:parent => a_node[:object], :parent_selector => the_index, :object => the_value})
                  end
                else
                  if options[:include_inactive]
                    accumulator << a_node
                  end
                end
              end
              # Review : is this for a Field??
              if a_node.alive? || options[:include_inactive]
                accumulator << a_node
              end
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
      alias :process :iterative
      #
      def process!(options={:include_inactive => true}, &block)
        self.iterative(options, &block)
        self
      end
      #
      def search(options={:include_inactive => true}, &block)
        results = []
        if block.respond_to?(:call)
          results = self.iterative(options, &block)
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
    end
  end
end
