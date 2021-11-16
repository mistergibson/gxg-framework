# PeristedArray Code:
module GxG
  module Database
    #
    class DetachedArray
      #
      private
      #
      def element_destroy(indexer=nil)
        # Review : develop on-server element destroy command path ??
      end
      # Note: property_read handled by load_property_links
      def element_write(indexer=nil)
        # Review : not needed on webclient version ??
      end
      #
      def load_element_links
        # Review : not needed on webclient version ??
      end
      #
      def refresh_ordinals()
        new_links = []
        @element_links.each_with_index do |the_key, ordinal|
          @element_links[(ordinal)][:record][:ordinal] = ordinal
          new_links << @element_links[(ordinal)]
        end
        @element_links = new_links
      end
      #
      public
      #
      def self.create()
        result = ::GxG::Database::DetachedArray.new
        result.uuid = ::GxG::uuid_generate.to_sym
        result.title = "Untitled #{new_object.uuid.to_s}"
        result
      end
      #
      def self.create_constrained(the_format=nil)
        result = ::GxG::Database::DetachedArray::create()
        format_record = nil
        if ::GxG::valid_uuid?(the_format)
          format_record = ::GxG::DB[:roles][:formats].format_load({:uuid => the_format})
        else
          format_record = ::GxG::DB[:roles][:formats].format_load({:ufs => the_format})
        end
        if format_record
          #
          unless ::GxG::DB_SAFETY.synchronize { GxG::DB[:formats][(format_record[:uuid].to_s.to_sym)] }
            ::GxG::DB_SAFETY.synchronize { GxG::DB[:formats][(format_record[:uuid].to_s.to_sym)] = format_record }
          end
          #
          result.constraint = format_record[:uuid].to_s.to_sym
        end
        result
      end
      #
      def assimilate_detached(detached_object=nil)
        result = false
        if detached_object.is_a?(::GxG::Database::DetachedArray)
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
      #
      def emit_structures(preference=false)
        @as_structures = preference
        preference
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
      def element_version(index=nil)
        result = 0.0
        if index.is_a?(::Numeric)
          #
          if @element_links[(index)]
            result = @element_links[(index)][:record][:version]
          else
            result = 0.0
          end
          #
        end
        result
      end
      #
      def set_element_version(element_index, the_version=nil)
        result = false
        if @element_links[(element_index)]
          if the_version.is_a?(::Numeric)
            @element_links[(element_index)][:record][:version] = (((the_version.to_f) * 10000.0).to_i.to_f / 10000.0)
            result = true
          else
            log_warning("Attempted to set version to an invalid version value #{the_version.inspect} for index #{element_index.inspect} on Object #{@uuid.inspect}")
          end
        else
          log_warning("Attempted to set version with an invalid index #{element_index.inspect} on Object #{@uuid.inspect}")
        end
        result
      end
      #
      def constraint()
        @constraint.clone
      end
      #
      def constraint=(the_format=nil)
        if GxG::valid_uuid?(the_format)
          @constraint = the_format.to_s.to_sym
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
      # Permission Management:
      def get_permissions()
        # Review : not needed on webclient version ??
      end
      #
      def set_permissions(credential=nil, the_permission=nil)            
        # Review : not needed on webclient version ??
      end
      #
      def reservation()
        # Review : not needed on webclient version ??
      end
      #
      def write_permission?()
        true
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
      #
      def get_delegate()
        # Review : not needed on webclient version ??
      end
      #
      def set_delegate(the_delegate=nil)
        # Review : not needed on webclient version ??
      end
      #
      def increment_version()
        if self.alive?
          if self.write_reserved?()
            @version = (((@version + 0.0001) * 10000.0).to_i.to_f / 10000.0)
          end
        end
      end
      #
      def save_version()
        # Review : not needed on webclient version ??
      end
      #
      def clear_constraint()
        if self.alive?
          if @constraint
            @constraint = nil
          end
        end
        true
      end
      #
      def constraint()
        @constraint.clone
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
      def refresh_links()
        # Review : not needed on webclient ??
      end
      #
      def initialize()
        # Review : !
        @as_structures = false
        @active = true
        @uuid = nil
        @title = nil
        @version = 0.0
        @constraint = nil
        @parent = nil
        @data = []
        @element_links = []
        self
      end
      #
      def inspect()
        # FORNOW: make re-entrant (yes, I know!) Fortunately, circular links are impossible with DetachedArray.
        # TODO: make interative instead of re-entrant.
        result = "["
        @element_links.each_index do |element_index|
          result = result + @element_links[(element_index)][:content].inspect
          # if @element_links[(element_index)].is_a?(::Hash)
          #   result = result + @element_links[(element_index)][:content].inspect
          # else
          #   result = result + "(Not Loaded)"
          # end
          unless element_index == (@element_links.size - 1)
            result = result + ", "
          end
        end
        result = result + "]"
        result
      end
      #
      def alive?()
        @active
      end
      #
      def db_address()
        nil
      end
      #
      def save()
        # Review : create a save-to-server command path here.
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
        @element_links.size
      end
      #
      def structure_attached?()
        # Review : not needed on webclient ??
        false
      end
      def structure_detach()
        # Review : not needed on webclient ??
        true
      end
      #
      def []=(indexer=nil, value=nil)
        # Only works with Integer indexes.
        unless self.alive?()
          raise Exception, "Attempted to alter a defunct structure"
        end
        result = nil
        if indexer.is_a?(::Integer)
          if value.is_a?(::OpenStruct)
            value = value.table
          end
          # Review : rewrite ????
          if value.is_any?(::GxG::Database::valid_field_classes()) || value.is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray, ::Hash, ::Array)
            unless self.write_reserved?()
              self.get_reservation()
            end
            if self.write_reserved?()
              # Further screen value provided:
              # ### Check provided DetachedHashes and DetachedArrays
              # ### Check provided Hashes and Arrays
              if value.is_any?(::Hash, ::Array)
                value.search do |the_value, the_selector, the_container|
                  unless the_value.is_any?(::GxG::Database::valid_field_classes()) || the_value.is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray, ::Hash, ::Array)
                    raise Exception, "The structure you are attaching has an unpersistable item within it (not supported)."
                  end
                end
              end
              # ### Property Exists?
              if @element_links[(indexer)]
                # set property to value
                operation = :set_value
              else
                if @constraint
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
                  :ordinal => 0,
                  :version => 0.0,
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
                    case value.class
                    when ::NilClass
                      new_value[:record][:element_boolean] = -1
                      new_value[:content] = nil
                    when ::FalseClass
                      new_value[:record][:element_boolean] = 0
                      new_value[:content] = false
                    when ::TrueClass
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
                      new_value[:record][:version] = @element_links[(indexer)][:record][:version]
                      new_value[:record][:element_binary_uuid] = @element_links[(indexer)][:record][:element_binary_uuid]
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
                if new_value[:content].is_a?(@element_links[(indexer)][:content].class) || ([true, false, nil].include?(new_value[:content]) && [true, false, nil].include?(@element_links[(indexer)][:content]))
                  # Replace value directly, but don't save yet unless you have to (:state refers to the last 'loaded-in-from-db' state of the data).
                  new_value[:linkid] = @element_links[(indexer)][:linkid]
                  if new_value[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (((@element_links[(indexer)][:record][:version].to_f + 0.0001) * 10000.0).to_i.to_f / 10000.0)
                  end
                  new_value[:record][:ordinal] = @element_links[(indexer)][:record][:ordinal]
                  new_value[:loaded] = true
                  new_value[:state] = @element_links[(indexer)][:state]
                  # 
                  if new_value[:content].is_a?(::String)
                    @element_links[(indexer)] = new_value
                  end
                  #
                else
                  # Other class value being substituted.
                  if new_value[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (((@element_links[(indexer)][:record][:version].to_f + 0.0001) * 10000.0).to_i.to_f / 10000.0)
                  end
                  new_value[:record][:ordinal] = @element_links[(indexer)][:record][:ordinal]
                  new_value[:loaded] = true
                  #
                  @element_links[(indexer)] = new_value
                end
                #
              when :add_value
                # Note: set in-memory value and save.
                if new_value[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                  new_value[:record][:version] = new_value[:content].version()
                else
                  new_value[:record][:version] = 0.0
                end
                new_value[:record][:ordinal] = @element_links.size
                new_value[:loaded] = true
                #
                @element_links[(indexer)] = new_value
              end
              # ### Handle coordination between persisted objects:
              if @element_links[(indexer)][:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                @element_links[(indexer)][:content].parent = (self)
              end
              #
              self.increment_version()
              result = @element_links[(indexer)][:content]
              #
            else
              raise Exception, "You do not have sufficient privileges to make this change. (write-reservation)"
            end
          else
            raise Exception, "The value is not persistable."
          end
        else
          raise Exception, "You must provide a index in the form of an Integer."
        end
        result
      end
      #
      #
      def [](indexer=nil)
        result = nil
        # if exists
        # if is not loaded, load element (if String or ByteArray)
        if self.alive?()
          if indexer.is_a?(::Integer)
            if @element_links[(indexer)]
              result = @element_links[(indexer)][:content]
              if @as_structures == true
                if result.is_a?(::GxG::Database::PersistedHash)
                  result = ::OpenStruct.new(result)
                end
              end
            end
          else
            raise ArgumentError, "You must specify with an Integer, not a #{indexer.class.inspect}"
          end              
        else
          raise Exception, "Attempted to access a defunct structure"
        end
        result
      end
      #
      def delete_at(indexer=nil)
        result = nil
        # if exists
        # if is not loaded, load element
        if self.alive?()
          if indexer.is_a?(::Integer)
            if self.write_reserved?()
              #
              if @element_links[(indexer)]
                # This will load the unloaded prior to separation.
                result = self[(indexer)]
                if @as_structures == true
                  if result.is_a?(::GxG::Database::PersistedHash)
                    result = ::OpenStruct.new(result)
                  end
                end
                the_link = @element_links.delete_at(indexer)
                # Review : element-unlink on server side ??
                if the_link[:content].is_any?(::GxG::Database::DetachedHash, ::GxG::Database::DetachedArray)
                  the_link[:content].save
                end
                self.increment_version()
              end
              #
            else
              raise Exception, "You do not have sufficient privileges to make this change"
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
      def <<(*args)
        if args.size > 0
          args.each do |item|
            self[(@element_links.size)] = item
          end
        end
        self
      end
      #
      def push(*args)
        if args.size > 0
          args.each do |item|
            self << item
          end
        end
        self
      end
      #
      def pop()
        self.delete_at((@element_links.size - 1))
      end
      #
      def shift()
        self.delete_at(0)
      end
      #
      def insert(the_index=nil, the_object=nil)
        # resovle the_index : the_index < 0 : the_index = (size - the_index)
        # if the_index == 0 : @element_links.unshift(nil-record);  self[0] = the_object
        # if the_index > size-1 : push(the_object)
        # else: @element_links.insert(the_index, nil-record); self[(the_index)] = the_object
        # vette the_object --> persistable?
        if ::GxG::Database::persistable?(the_object)
          new_value = {
            :linkid => nil,
            :content => nil,
            :loaded => false,
            :state => 0,
            :record => {
              :parent_uuid => @uuid.to_s,
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
          the_index = the_index.to_i
          if the_index < 0
            the_index = (self.size - the_index)
          end
          if the_index == 0
            new_value[:record][:ordinal] = the_index
            @element_links.unshift(new_value)
            refresh_ordinals
            self[0] = the_object
          else
            if the_index > (self.size - 1)
              self.push(the_object)
            else
              new_value[:record][:ordinal] = the_index
              @element_links.insert(the_index, new_value)
              refresh_ordinals
              self[(the_index)] = the_object
            end
          end
        end
        self
      end
      # ???? def insert - ::GxG::Database::persistable?(the_object)
      def unshift(the_object=nil)
        self.insert(0,the_object)
      end
      #
      def swap(first_index=nil, last_index=nil)
        result = false
        if first_index && last_index
          if (0..(self.size - 1)).include?(first_index.to_i) && (0..(self.size - 1)).include?(last_index.to_i)
            if first_index.to_i != last_index.to_i
              record = @element_links[(first_index)]
              @element_links[(first_index)] = @element_links[(last_index)]
              @element_links[(last_index)] = record
              result = true
            end
          end
        end
        result
      end
      #
      def include?(the_value)
        result = false
        if the_value.is_a?(::OpenStruct)
          the_value = the_value.table
        end
        @element_links.each do |element|
          if element[:content] == the_value
            result = true
            break
          end
        end
        result
      end
      #
      def find_index(the_value)
        result = nil
        if the_value.is_a?(::OpenStruct)
          the_value = the_value.table
        end
        @element_links.each_with_index do |element, indexer|
          if element[:content] == the_value
            result = indexer
            break
          end
        end
        result
      end
      #
      def export(options={:exclude_file_segments=>false})
        if self.alive?
          exclude_file_segments = (options[:exclude_file_segments] || false)
          if options[:clone] == true
            # Review : why are cloned objects unconstrained? sync issues??
            result = {:type => :element_array, :uuid => GxG::uuid_generate.to_s.to_sym, :title => @title.clone, :version => @version.clone, :content => []}
          else
            result = {:type => :element_array, :uuid => @uuid.clone, :title => @title.clone, :version => @version.clone, :constraint => @constraint.clone, :content => []}
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
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => {}, :record => {:type => :element_hash, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().clone, :format => the_value.format().clone, :content => {}}}
              else
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => :element_hash, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().clone, :format => the_value.format().clone, :content => {}}}
              end
            end
            if the_value.is_a?(::GxG::Database::DetachedArray)
              if options[:clone] == true
                the_uuid = GxG::uuid_generate.to_s.to_sym
              else
                the_uuid = the_value.uuid().clone
              end
              if (exclude_file_segments == true) && (the_selector == :file_segments || the_selector == :segments || the_selector == :portions)
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => [], :record => {:type => :element_array, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().clone, :constraint => the_value.constraint().clone, :content => []}}
              else
                export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => :element_array, :uuid => the_uuid, :title => the_value.title().clone, :version => the_value.version().clone, :constraint => the_value.constraint().clone, :content => []}}
              end
            end
            if the_value.is_any?(::GxG::Database::valid_field_classes())
              data_type = GxG::Database::element_table_for_instance(the_value)
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
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => data_type, :version => (the_container.version(the_selector) || 0.0), :content => data}}
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
        else
          result = nil
        end
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
      def first()
        if @element_links.size > 0
          self[0]
        else
          nil
        end
      end
      #
      def last()
        if @element_links.size > 0
          self[(@element_links.size - 1)]
        else
          nil
        end
      end
      #
      def each(&block)
        if block.respond_to?(:call)
          load_element_links
          if @element_links.size > 0
            @element_links.each_index do |index|
              block.call(self[(index)])
            end
          end
          self
        else
          self.to_enum(:each)
        end
      end
      #
      def each_index(&block)
        if block.respond_to?(:call)
          load_element_links
          if @element_links.size > 0
            @element_links.each_index do |index|
              block.call(index)
            end
          end
          self
        else
          self.to_enum(:each_index)
        end
      end
      #
      def each_with_index(offset=0,&block)
        if block.respond_to?(:call)
          load_element_links
          if @element_links.size > 0
            @element_links.to_enum(:each).with_index(offset).each do |entry, index|
              block.call(self[(index)], index)
            end
          end
          self
        else
          self.to_enum(:each_with_index,offset)
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
              #
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
        if the_object.is_a?(::OpenStruct)
          the_object = the_object.table
        end
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
      def unpersist()
        result = []
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
    end
    #
    class PersistedArray
      #
      private
      #
      def element_destroy(indexer=nil)
        # Destroy database property record, but leave in-memory property intact - for now. (preserves key-ordinal position)
        result = false
        if indexer
          if @element_links[(indexer)]
            element = @element_links[(indexer)]
            # ### Delete sub-object linked to.
            the_table = nil
            the_uuid = nil
            if element[:record][:element_text_uuid].size > 0
              the_table = :element_text
              the_uuid = property[:record][:element_text_uuid]
            end
            if element[:record][:element_binary_uuid].size > 0
              the_table = :element_binary
              the_uuid = element[:record][:element_binary_uuid]
            end
            if element[:record][:element_array_uuid].size > 0
              the_table = :element_array
              the_uuid = element[:record][:element_array_uuid]
            end
            if element[:record][:element_hash_uuid].size > 0
              the_table = :element_hash
              the_uuid = element[:record][:element_hash_uuid]
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
            @db_address[:database].connector()[:array_elements].filter({:dbid => element[:linkid]}).delete
            result = true
          end
        end
        result
      end
      # Note: property_read handled by load_property_links
      def element_write(indexer=nil)
        result = false
        if indexer
          if @element_links[(indexer)]
            element = @element_links[(indexer)]
            # Save out text and binary pages if needed.
            if element[:content].is_a?(::String)
              if element[:content].size > 256
                unless element[:record][:element_text_uuid].size > 0
                  # create text header
                  the_uuid = ::GxG::uuid_generate
                  while @db_address[:database].connector()[:element_text].filter({:uuid => the_uuid.to_s}).count > 0 do
                    the_uuid = ::GxG::uuid_generate
                  end
                  element[:record][:length] = element[:content].size
                  the_dbid = @db_address[:database].connector()[:element_text].insert({:uuid => the_uuid.to_s, :version => element[:record][:version], :length => element[:record][:length]})
                  #
                  element[:record][:element_text_uuid] = the_uuid
                end
              end
            else
              if element[:content].is_a?(::GxG::ByteArray)
                unless element[:record][:element_binary_uuid].size > 0
                  # create binary header
                  the_uuid = ::GxG::uuid_generate
                  while @db_address[:database].connector()[:element_binary].filter({:uuid => the_uuid.to_s}).count > 0 do
                    the_uuid = ::GxG::uuid_generate
                  end
                  element[:record][:length] = element[:content].size
                  # format field??
                  the_dbid = @db_address[:database].connector()[:element_binary].insert({:uuid => the_uuid.to_s, :version => element[:record][:version], :length => element[:record][:length]})
                  #
                  element[:record][:element_binary_uuid] = the_uuid
                end
              end
            end
            # Store text pages
            if element[:record][:element_text_uuid].size > 0
              header_record = @db_address[:database].connector()[:element_text].filter({:uuid => element[:record][:element_text_uuid].to_s}).first
              if header_record
                old_segments = []
                @db_address[:database].connector()[:text_page].filter({:parent_uuid => header_record[:uuid].to_s}).order(:ordinal).each do |entry|
                  old_segments << entry[:dbid]
                end
                if element[:content].size == 0
                  # delete all text_pages if count > 0
                  if old_segments.size > 0
                    @db_address[:database].connector()[:text_page].filter({:parent_uuid => (header_record[:uuid])}).order(:ordinal).delete
                  end
                else
                  new_segments = ::GxG::apportioned_ranges(element[:content].size, 4096)
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
                      @db_address[:database].element_update(:text_page,{:dbid => action[:dbid]},{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => element[:content][(action[:portion])].size, :content => element[:content][(action[:portion])]})
                      # @db_address[:database].connector()[:text_page].filter({:dbid => (action[:dbid])}).update({:ordinal => (action[:ordinal]), :length => (@content[(action[:portion])].size), :content => (@content[(action[:portion])])})
                    when :create
                      new_dbid = @db_address[:database].element_create(:text_page,{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => element[:content][(action[:portion])].size, :content => element[:content][(action[:portion])]})
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
              if element[:record][:element_binary_uuid].size > 0
                header_record = @db_address[:database].connector()[:element_binary].filter({:uuid => element[:record][:element_binary_uuid].to_s}).first
                if header_record
                  old_segments = []
                  @db_address[:database].connector()[:binary_page].filter({:parent_uuid => header_record[:uuid].to_s}).order(:ordinal).each do |entry|
                    old_segments << entry[:dbid]
                  end
                  if element[:content].size == 0
                    # delete all text_pages if count > 0
                    if old_segments.size > 0
                      @db_address[:database].connector()[:binary_page].filter({:parent_uuid => (header_record[:uuid])}).order(:ordinal).delete
                    end
                  else
                    new_segments = ::GxG::apportioned_ranges(element[:content].size, 65536)
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
                        @db_address[:database].element_update(:binary_page,{:dbid => action[:dbid]},{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => element[:content][(action[:portion])].size, :content => element[:content][(action[:portion])]})
                        # @db_address[:database].connector()[:text_page].filter({:dbid => (action[:dbid])}).update({:ordinal => (action[:ordinal]), :length => (@content[(action[:portion])].size), :content => (@content[(action[:portion])])})
                      when :create
                        new_dbid = @db_address[:database].element_create(:binary_page,{:parent_uuid => header_record[:uuid], :ordinal => action[:ordinal], :length => element[:content][(action[:portion])].size, :content => element[:content][(action[:portion])]})
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
            if element[:linkid] == nil || element[:linkid] == 0
              element[:linkid] = @db_address[:database].connector()[:array_elements].insert(element[:record])
            else
              @db_address[:database].connector()[:array_elements].filter({:dbid => element[:linkid]}).update(element[:record])
            end
            #
            element[:state] = element[:content].hash
            result = true
          end
        end
        result
      end
      #
      def load_element_links
        #
        result = true
        begin
          if @db_address
            if @db_address[:database].is_a?(::GxG::Database::Database)
              if @db_address[:database].open?()
                new_links = []
                the_records = @db_address[:database].connector()[:array_elements].filter({:parent_uuid => @uuid.to_s}).order(:ordinal)
                the_records.each_with_index do |entry, indexer|
                  # (element indexer) => {:linkid => 0, :content => nil, :loaded => false, :state => 0, :record => {}}
                  new_links[(indexer)] = {:linkid => entry.delete(:dbid), :content => nil, :loaded => false, :state => 0, :record => entry}
                  # Load indicated :content
                  case new_links[(indexer)][:record][:element]
                  when "element_boolean"
                    case new_links[(indexer)][:record][:element_boolean]
                    when -1
                      new_links[(indexer)][:content] = nil
                      new_links[(indexer)][:loaded] = true
                    when 0
                      new_links[(indexer)][:content] = false
                      new_links[(indexer)][:loaded] = true
                    when 1
                      new_links[(indexer)][:content] = true
                      new_links[(indexer)][:loaded] = true
                    end
                  when "element_integer"
                    new_links[(indexer)][:content] = new_links[(indexer)][:record][:element_integer]
                    new_links[(indexer)][:loaded] = true
                  when "element_float"
                    new_links[(indexer)][:content] = new_links[(indexer)][:record][:element_float]
                    new_links[(indexer)][:loaded] = true
                  when "element_bigdecimal"
                    new_links[(indexer)][:content] = ::BigDecimal.new(new_links[(indexer)][:record][:element_bigdecimal].to_s)
                    new_links[(indexer)][:loaded] = true
                  when "element_datetime"
                    new_links[(indexer)][:content] = new_links[(indexer)][:record][:element_datetime]
                    if new_links[(indexer)][:content].is_a?(::Time)
                      new_links[(indexer)][:content] = new_links[(indexer)][:content].to_datetime()
                    end
                    new_links[(indexer)][:loaded] = true
                  when "element_text"
                    if new_links[(indexer)][:record][:element_text_uuid].size > 0
                      # Load full text content from pages
                      new_links[(indexer)][:content] = ""
                      @db_address[:database].connector()[:text_page].filter({:parent_uuid => new_links[(indexer)][:record][:element_text_uuid].to_s}).order(:ordinal).each do |text_page|
                        new_links[(indexer)][:content] << text_page[:content]
                     end
                    else
                      new_links[(indexer)][:content] = new_links[(indexer)][:record][:element_text]
                    end
                    new_links[(indexer)][:loaded] = true
                  when "element_binary"
                    # Load binary data
                    new_links[(indexer)][:content] = ::GxG::ByteArray.new
                    new_links[(indexer)][:loaded] = false
                    # Review : support on-read segment loading and element unloading. (thinking of large binary files here)
                  when "element_array"
                    # Load PersistedArray
                    new_links[(indexer)][:content] = @db_address[:database].retrieve_by_uuid(new_links[(indexer)][:record][:element_array_uuid].to_s.to_sym, @credential, (@reservation || @delegate))
                    if new_links[(indexer)][:content].is_a?(::GxG::Database::PersistedArray)
                      new_links[(indexer)][:loaded] = true
                      new_links[(indexer)][:state] = new_links[(indexer)][:content].hash
                      new_links[(indexer)][:content].set_parent(self)
                    else
                      new_links[(indexer)][:loaded] = false
                    end
                  when "element_hash"
                    # Load PersistedHash
                    new_links[(indexer)][:content] = @db_address[:database].retrieve_by_uuid(new_links[(indexer)][:record][:element_hash_uuid].to_s.to_sym, @credential, (@reservation || @delegate))
                    if new_links[(indexer)][:content].is_a?(::GxG::Database::PersistedHash)
                      new_links[(indexer)][:loaded] = true
                      new_links[(indexer)][:state] = new_links[(indexer)][:content].hash
                      new_links[(indexer)][:content].set_parent(self)
                    else
                      new_links[(indexer)][:loaded] = false
                    end
                  end
                end
                @element_links = new_links
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
            @element_links.each_with_index do |the_key, ordinal|
              @element_links[(ordinal)][:record][:ordinal] = ordinal
              @db_address[:database].connector()[:array_elements].filter({:dbid => @element_links[(ordinal)][:linkid]}).update({:ordinal => (ordinal)})
            end
          end
        end
      end
      #
      public
      #
      def emit_structures(preference=false)
        @as_structures = preference
        preference
      end
      # Supplimental Supports
      def element_byte_map(class_filter = ::GxG::ByteArray)
        result = []
        manifest = []
        @element_links.each_with_index do |record, index|
          element_type = nil
          if class_filter
            if record[:content].is_a?(class_filter)
              element_type = @db_address[:database].element_table_for_instance(record[:content]).to_s
            end
          else
            element_type = @db_address[:database].element_table_for_instance(record[:content]).to_s
          end
          if element_type
            manifest << {:index => index, :type => element_type}
          end
        end
        manifest.each do |reference|
          record = @db_address[:database].connector()[:array_elements].filter({:parent_uuid => @uuid.to_s, :element => reference[:type], :ordinal => reference[:index]}).first
          if record
            result << {:index => record[:ordinal], :size => record[:length]}
          end
        end
        result
      end
      # Permission Management:
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
            manifest.each do |entry|
              @db_address[:database].assign_element_permission(entry[:table], entry[:dbid], credential, the_permission)
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
          @element_links.each_index do |ordinal|
            if @element_links[(ordinal)][:content].is_any?([::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray])
              @element_links[(ordinal)][:content].release_reservation
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
                @element_links.each_index do |ordinal|
                  if @element_links[(ordinal)][:content].is_any?([::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray])
                    clean_up_list << @element_links[(ordinal)][:content]
                    unless @element_links[(ordinal)][:content].get_reservation()
                      @db_address[:database].release_element_locks(the_reservation)
                      the_reservation = nil
                      break
                    end
                  end
                end
                #
              end
              if the_reservation
                @reservation = the_reservation
                result = true
              else
                clean_up_list.each do |the_object|
                  the_object.release_reservation
                end
              end
            end
          end
        end
        # xxx keep old code for now
        # if (@reservation || @delegate)
        #   result = true
        # else
        #   if self.alive?
        #     if @permission[:write]
        #       @reservation = @db_address[:database].reserve_element_locks(@credential, (@db_address[:database].element_manifest(@db_address[:table], @db_address[:dbid])), :write)
        #       if @reservation
        #         @element_links.each_index do |ordinal|
        #           if @element_links[(ordinal)][:content].is_any?([::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray])
        #             @element_links[(ordinal)][:content].set_delegate((@reservation || @delegate))
        #           end
        #         end
        #         result = true
        #       end
        #       #
        #     end
        #   end
        # end
        # xxx end old code
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
      def uuid()
        @uuid.clone
      end
      #
      def version(input=nil)
        @version.clone
      end
      #
      def version=(the_version=nil)
        if the_version.is_a?(::Numeric)
          @version = ::BigDecimal.new(the_version.to_s)
        end
      end
      #
      def element_version(index=nil)
        result = 0.0
        if index.is_a?(::Numeric)
          if @element_links[(index)]
            result = @element_links[(index)][:record][:version]
          end
          #
        end
        result
      end
      #
      def set_element_version(element_index, the_version=nil)
        result = false
        if @element_links[(element_index)]
          if the_version.is_a?(::Numeric)
            @element_links[(element_index)][:record][:version] = the_version.to_s("F").to_d
            result = true
          else
            log_warning("Attempted to set version to an invalid version value #{the_version.inspect} for index #{element_index.inspect} on Object #{@uuid.inspect}")
          end
        else
          log_warning("Attempted to set version with an invalid index #{element_index.inspect} on Object #{@uuid.inspect}")
        end
        result
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
        @db_address[:database].connector()[:element_array].filter({:dbid => @db_address[:dbid]}).update({:version => @version})
      end
      #
      def set_version(the_version=0.0)
        if self.write_reserved?()
          @version = the_version.to_s("F").to_d
          self.save_version
        end
      end
      #
      def title()
        @title.clone
      end
      #
      def set_title(the_title=nil)
        if self.alive?
          if @db_address[:database].open?
            if self.write_reserved?()
              if the_title
                @title = the_title.to_s[0..256]
                @db_address[:database].connector()[:element_array].filter({:dbid => @db_address[:dbid]}).update({:title => @title})
                self.increment_version
              end
            end
          end
        end
      end
      alias :title= :set_title
      #
      def set_constraint(format_uuid=nil)
        if self.alive?
          unless @constraint
            if ::GxG::valid_uuid?(format_uuid)
              @constraint = format_uuid.to_sym
              @db_address[:database].connector()[:element_array].filter({:dbid => (@db_address[:dbid])}).update({:constraint => (@constraint.to_s)})
            end
          end
        end
      end
      alias :constraint= :set_constraint
      #
      def clear_constraint()
        if self.alive?
          if @constraint
            @constraint = nil
            @db_address[:database].connector()[:element_array].filter({:dbid => (@db_address[:dbid])}).update({:constraint => ""})
          end
        end
        true
      end
      #
      def constraint()
        @constraint.clone
      end
      #
      def ufs()
        if @constraint
          record = @db_address[:database].format_load({:uuid => @constraint.to_s})
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
      def initialize(settings = {}, options={})
        # mount element: {:database => <database>, :uuid => <uuid>, :credential => <uuid>, :delegate => nil/<uuid>, :parent => nil/<an-object>}
        # create element: {:database => <database>, :credential => <uuid>, :delegate => nil/<uuid>, :parent => nil/<an-object>}
        # 
        if settings.is_a?(::Hash)
          unless ::GxG::valid_uuid?(settings[:credential])
            raise ArgumentError, "You must supply a valid credential UUID (37 character limit) as a String or Symbol"
          end
          @as_structures = false
          @quick = settings[:quick]
          @credential = settings[:credential].to_sym
          @reservation = nil
          @delegate = settings[:delegate]
          if settings[:parent].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
            @parent = settings[:parent]
          else
            @parent = nil
          end
          @constraint = settings[:constraint]
          unless @constraint
            if options[:with_constraint]
              @constraint = options[:with_constraint]
            end
          end
          if settings[:database].is_a?(::GxG::Database::Database)
            if settings[:database].open?()
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
                  the_title = ("Untitled PersistedArray " << (settings[:database].connector()[:element_array].count.to_s))
                end
              end
              unless ::GxG::valid_uuid?(the_uuid)
                # without specifying a uuid, the implied intent is to create a new PersistedArray
                if ::GxG::valid_uuid?(options[:with_uuid])
                  the_uuid = options[:with_uuid].to_s
                else
                  the_uuid = ::GxG::uuid_generate()
                  while ((settings[:database].connector()[:element_array].filter({:uuid => the_uuid}).count > 0) or (settings[:database].connector()[:element_array].filter({:uuid => the_uuid}).count > 0))
                    the_uuid = ::GxG::uuid_generate()
                  end
                end
                # create blank array record
                new_dbid = settings[:database].connector()[:element_array].insert({:uuid => (the_uuid), :title => (the_title), :constraint => (@constraint.to_s), :version => (options[:with_version] || BigDecimal.new("0.0"))})
                #
                @db_address = {:database => (settings[:database]), :table => :element_array, :dbid => (new_dbid)}
                if @parent
                  @permission = @parent.get_permissions()
                  # settings[:database].enforce_permission_policy({:action => :extend, :credential => @credential, :source => settings[:parent], :destination => self})
                  #                  settings[:database].extend_element_permissions(settings[:parent].db_address()[:table], settings[:parent].db_address()[:dbid], :element_array, new_dbid)
                else
                  # create raw permissions for this element
                  @permission = {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true}
                  # settings[:database].assign_element_permission(:element_array, new_dbid, @credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                  # settings[:database].enforce_permission_policy({:action => :extend, :credential => @credential, :source => self, :destination => self})
                end
                settings[:database].assign_element_permission(:element_array, new_dbid, @credential, @permission)
              end
              # mount according to uuid
              if the_uuid
                # mount
                record = settings[:database].connector()[:element_array].filter({:uuid => (the_uuid)}).first
                if record
                  @uuid = the_uuid.to_sym
                  @title = record[:title].to_s
                  @version = record[:version]
                  @db_address = {:database => (settings[:database]), :table => :element_array, :dbid => (record[:dbid])}
                  @element_links = []
                  if record[:constraint].to_s.size > 0
                    @constraint = record[:constraint].to_sym
                  else
                    @constraint = nil
                  end
                  unless @permission
                    @permission = @db_address[:database].effective_element_permission(@db_address[:table], @db_address[:dbid], @credential)
                  end
                  # @read_reservation = @db_address[:database].reserve_element_locks(@credential, (@db_address[:database].element_manifest(@db_address[:table], @db_address[:dbid])), :read)
                  #
                  load_element_links
                  #
                else
                  raise Exception, "Unable to mount the PersistedArray record"
                end
              else
                raise Exception, "Unable to mount the PersistedArray record"
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
        # FORNOW: make re-entrant (yes, I know!) Fortunately, circular links are impossible with PersistedArray.
        # TODO: make interative instead of re-entrant.
        result = "(Not Loaded)"
        if @db_address
          if @db_address[:database].element_byte_size(@db_address[:table], @db_address[:dbid]) <= 10485760
            # smaller than 10MB
            result = "["
            @element_links.each_index do |element_index|
              if @element_links[(element_index)].is_a?(::Hash)
                result << @element_links[(element_index)][:content].inspect
              else
                result << "(Not Loaded)"
              end
              unless element_index == (@element_links.size - 1)
                result << ", "
              end
            end
            result << "]"
          else
            result = "(Too Damned Big)"
          end
          #
        end
        result
      end
      #
      def alive?()
        if @db_address
          if @db_address[:database].element_exists?(@db_address[:table],@db_address[:dbid])
            true
          else
            false
          end
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
          @element_links.each_index do |index|
            element = @element_links[(index)][:content]
            if element.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
              containers = [(element)]
              element.search({:include_inactive => false}) do |the_value, the_selector, the_container|
                if the_value.alive?
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
          @element_links = []
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
              @element_links.each_index do |index|
                # Note: only save property data and header if: a) data is still loaded and b) state has changed.
                if @element_links[(index)][:loaded] == true
                  if @element_links[(index)][:state] != @element_links[(index)][:content].hash
                    @element_links[(index)][:record][:version] = (@element_links[(index)][:record][:version].to_s("F").to_d + 0.0001)
                    element_write(index)
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
              if @db_address[:database].element_in_use?(@db_address[:table], @db_address[:dbid])
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
        @element_links.size
      end
      #
      def structure_attached?()
        @db_address[:database].structure_attached?(@uuid.to_s)
      end
      def structure_detach()
        @db_address[:database].structure_detach(@uuid.to_s)
      end
      #
      def []=(indexer=nil, value=nil)
        # Only works with Integer indexes.
        unless self.alive?()
          raise Exception, "Attempted to alter a defunct structure"
        end
        unless @db_address[:database].open?()
          raise Exception, "Database not available"
        end
        result = nil
        if value.is_a?(::OpenStruct)
          value = value.table
        end
        if indexer.is_a?(::Integer)
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
                  value.structure_detach
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
              if @element_links[(indexer)]
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
                    case value.class
                    when ::NilClass
                      new_value[:record][:element_boolean] = -1
                      new_value[:content] = nil
                    when ::FalseClass
                      new_value[:record][:element_boolean] = 0
                      new_value[:content] = false
                    when ::TrueClass
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
                        new_value[:record][:version] = @element_links[(indexer)][:record][:version]
                        new_value[:record][:element_text_uuid] = @element_links[(indexer)][:record][:element_text_uuid]
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
                      new_value[:record][:version] = @element_links[(indexer)][:record][:version]
                      new_value[:record][:element_binary_uuid] = @element_links[(indexer)][:record][:element_binary_uuid]
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
                if new_value[:content].is_a?(@element_links[(indexer)][:content].class) || ([true, false, nil].include?(new_value[:content]) && [true, false, nil].include?(@element_links[(indexer)][:content]))
                  # Replace value directly, but don't save yet unless you have to (:state refers to the last 'loaded-in-from-db' state of the data).
                  new_value[:linkid] = @element_links[(indexer)][:linkid]
                  if new_value[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    new_value[:record][:version] = new_value[:content].version()
                  else
                    new_value[:record][:version] = (@element_links[(indexer)][:record][:version] + 0.0001)
                  end
                  new_value[:record][:ordinal] = @element_links[(indexer)][:record][:ordinal]
                  new_value[:loaded] = true
                  new_value[:state] = @element_links[(indexer)][:state]
                  # ### Did string grow or shrink crossing the threshold??
                  if new_value[:content].is_a?(::String)
                    if (@element_links[(indexer)][:content].size > 256 && new_value[:content].size <= 256)
                      # shrank - delete text object and pages as well as property record (slow)
                      element_destroy(indexer)
                      @element_links[(indexer)] = new_value
                      element_write(indexer)
                    else
                      if (@element_links[(indexer)][:content].size <= 256 && new_value[:content].size > 256)
                        # grew - create text object and pages (a little less slow)
                        @element_links[(indexer)] = new_value
                        element_write(indexer)
                      else
                        # N/A
                        @element_links[(indexer)] = new_value
                      end
                    end
                  else
                    # N/A
                    @element_links[(indexer)] = new_value
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
                    new_value[:record][:version] = (@element_links[(indexer)][:record][:version] + 0.0001)
                  end
                  new_value[:record][:ordinal] = @element_links[(indexer)][:record][:ordinal]
                  new_value[:loaded] = true
                  # Destroy old property record on db, and associated linked objects.
                  # Review : this is slow - look into optimizations here.
                  if @element_links[(indexer)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray, ::GxG::ByteArray, ::String)
                    if @element_links[(indexer)][:content].is_a?(::String)
                      if (@element_links[(indexer)][:content].size > 256 && new_value[:content].size <= 256) || (@element_links[(indexer)][:content].size <= 256 && new_value[:content].size > 256)
                        element_destroy(indexer)
                      end
                    else
                      element_destroy(indexer)
                    end
                  end
                  #
                  @element_links[(indexer)] = new_value
                  element_write(indexer)
                end
                #
              when :add_value
                # Note: set in-memory value and save.
                if new_value[:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                  new_value[:record][:version] = new_value[:content].version()
                else
                  new_value[:record][:version] = ::BigDecimal.new("0.0")
                end
                new_value[:record][:ordinal] = @element_links.size
                new_value[:loaded] = true
                #
                @element_links[(indexer)] = new_value
                # Review : is this wise to do this here??
                element_write(indexer)
              end
              # ### Handle coordination between persisted objects:
              if @element_links[(indexer)][:content].is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                # ### Extend Reservation to persisted objects ( Review : does this slow it down too much?? )
                @element_links[(indexer)][:content].release_reservation
                @db_address[:database].reservation_add_element((@reservation || @delegate), (@element_links[(indexer)][:content].db_address()[:table]), @element_links[(indexer)][:content].db_address()[:dbid])
                @element_links[(indexer)][:content].set_delegate((@reservation || @delegate))
                # ### Extend Permissions to persisted object
                @db_address[:database].extend_element_permissions(@db_address[:table],@db_address[:dbid],@element_links[(indexer)][:content].db_address()[:table],@element_links[(indexer)][:content].db_address()[:dbid])
                @db_address[:database].enforce_permission_policy({:action => :extend, :credential => @credential, :source => self, :destination => @element_links[(indexer)][:content]})
                #
                @element_links[(indexer)][:content].set_parent(self)
              end
              #
              self.increment_version()
              result = @element_links[(indexer)][:content]
              #
            else
              raise Exception, "You do not have sufficient privileges to make this change. (write-reservation)"
            end
          else
            raise Exception, "The value is not persistable."
          end
        else
          raise Exception, "You must provide a index in the form of an Integer."
        end
        result
      end
      #
      def unload(indexer=nil)
        result = false
        # if key exists
        # if key is loaded, unload element (if String or ByteArray)
        if self.alive?()
          if @db_address[:database].open?()
            if indexer.is_a?(::Integer)
              if @element_links[(indexer)]
                if @element_links[(indexer)][:content].is_any?(::String, ::GxG::ByteArray)
                  if @element_links[(indexer)][:loaded] == true
                    # ### Unload Base Element contents from memory, leaving reference harness intact and active.
                    @element_links[(indexer)][:content].clear
                    @element_links[(indexer)][:loaded] = false
                  end
                end
                result = true
              end
            else
              raise ArgumentError, "You must specify with an Integer, not a #{indexer.class.inspect}"
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
      def [](indexer=nil)
        result = nil
        # if exists
        # if is not loaded, load element (if String or ByteArray)
        if self.alive?()
          if @db_address[:database].open?()
            if indexer.is_a?(::Integer)
              if @element_links[(indexer)]
                if @element_links[(indexer)][:content].is_any?(::String, ::GxG::ByteArray)
                  unless @element_links[(indexer)][:loaded] == true
                    # ### Load Base Element contents from the database.
                    if @element_links[(indexer)][:content].is_a?(::String)
                      if @element_links[(indexer)][:record][:element_text_uuid].to_s.size > 0
                        @db_address[:database].connector()[:text_page].filter({:parent_uuid => @element_links[(indexer)][:record][:element_text_uuid].to_s}).order(:ordinal).each do |text_page|
                          @element_links[(indexer)][:content] << text_page[:content]
                        end
                      else
                        @element_links[(indexer)][:content] = @element_links[(indexer)][:record][:element_text].to_s
                      end
                    else
                      @db_address[:database].connector()[:binary_page].filter({:parent_uuid => @element_links[(indexer)][:record][:element_binary_uuid].to_s}).order(:ordinal).each do |binary_page|
                        @element_links[(indexer)][:content] << binary_page[:content]
                      end
                    end
                    @element_links[(indexer)][:loaded] = true
                  end
                end
                result = @element_links[(indexer)][:content]
                if @as_structures == true
                  if result.is_a?(::GxG::Database::PersistedHash)
                    result = ::OpenStruct.new(result)
                  end
                end
              end
            else
              raise ArgumentError, "You must specify with an Integer, not a #{indexer.class.inspect}"
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
      def delete_at(indexer=nil)
        result = nil
        # if exists
        # if is not loaded, load element
        if self.alive?()
          if @db_address[:database].open?()
            if indexer.is_a?(::Integer)
              if self.write_reserved?()
                property_key = key.to_s.to_sym
                #
                if @element_links[(indexer)]
                  # This will load the unloaded prior to separation.
                  result = self[(indexer)]
                  if @as_structures == true
                    if result.is_a?(::GxG::Database::PersistedHash)
                      result = ::OpenStruct.new(result)
                    end
                  end
                  the_link = @element_links.delete_at(indexer)
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
                  @db_address[:database].connector()[:array_elements].filter({:dbid => the_link[:linkid]}).delete
                  refresh_ordinals
                  self.increment_version()
                end
                #
              else
                raise Exception, "You do not have sufficient privileges to make this change"
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
      def <<(*args)
        if args.size > 0
          args.each do |item|
            self[(@element_links.size)] = item
          end
        end
        self
      end
      #
      def push(*args)
        if args.size > 0
          args.each do |item|
            self << item
          end
        end
        self
      end
      #
      def pop()
        self.delete_at((@element_links.size - 1))
      end
      #
      def shift()
        self.delete_at(0)
      end
      #
      def insert(the_index=nil, the_object=nil)
        # resovle the_index : the_index < 0 : the_index = (size - the_index)
        # if the_index == 0 : @element_links.unshift(nil-record);  self[0] = the_object
        # if the_index > size-1 : push(the_object)
        # else: @element_links.insert(the_index, nil-record); self[(the_index)] = the_object
        # vette the_object --> persistable?
        if @db_address
          if @db_address[:database].persistable?(the_object)
            new_value = {
              :linkid => nil,
              :content => nil,
              :loaded => false,
              :state => 0,
              :record => {
                :parent_uuid => @uuid.to_s,
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
            the_index = the_index.to_i
            if the_index < 0
              the_index = (self.size - the_index)
            end
            if the_index == 0
              new_value[:record][:ordinal] = the_index
              @element_links.unshift(new_value)
              element_write(the_index)
              refresh_ordinals
              self[0] = the_object
            else
              if the_index > (self.size - 1)
                self.push(the_object)
              else
                new_value[:record][:ordinal] = the_index
                 @element_links.insert(the_index, new_value)
                 element_write(the_index)
                 refresh_ordinals
                 self[(the_index)] = the_object
              end
            end
          else
            log_warning("Ignoring attempt to insert a non-persistable object.")
          end
        end
        self
      end
      #
      def unshift(the_object=nil)
        self.insert(0,the_object)
      end
      #
      def swap(first_index=nil, last_index=nil)
        result = false
        if first_index && last_index
          if (0..(self.size - 1)).include?(first_index.to_i) && (0..(self.size - 1)).include?(last_index.to_i)
            if first_index.to_i != last_index.to_i
              record = @element_links[(first_index)]
              @element_links[(first_index)] = @element_links[(last_index)]
              @element_links[(last_index)] = record
              refresh_ordinals
              result = true
            end
          end
        end
        result
      end
      #
      def include?(the_value)
        result = false
        if the_value.is_a?(::OpenStruct)
          the_value = the_value.table
        end
        @element_links.each do |element|
          if element[:content] == the_value
            result = true
            break
          end
        end
        result
      end
      #
      def find_index(the_value)
        result = nil
        if the_value.is_a?(::OpenStruct)
          the_value = the_value.table
        end
        @element_links.each_with_index do |element, indexer|
          if element[:content] == the_value
            result = indexer
            break
          end
        end
        result
      end
      #
      def export(options={:exclude_file_segments=>false})
        if self.alive?
          exclude_file_segments = (options[:exclude_file_segments] || false)
          if options[:clone] == true
            # Review : why are cloned objects unconstrained? sync issues??
            result = {:type => :element_array, :uuid => GxG::uuid_generate.to_s.to_sym, :title => @title.clone, :version => @version.to_s("F"), :content => []}
          else
            result = {:type => :element_array, :uuid => @uuid.clone, :title => @title.clone, :version => @version.to_s("F"), :constraint => @constraint.clone, :content => []}
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
                data = the_value.to_s
              when :element_datetime
                data = the_value.to_s
              when :element_binary
                data = the_value.to_s.encode64
              when :element_text
                data = the_value.to_s
              else
                data = the_value
              end              
              export_db << {:parent => the_container, :parent_selector => the_selector.clone, :object => the_value, :record => {:type => data_type, :version => (::BigDecimal.new(the_container.version(the_selector).to_s) || ::BigDecimal.new("0.0")).to_s("F"), :content => data}}
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
      def first()
        if @element_links.size > 0
          self[0]
        else
          nil
        end
      end
      #
      def last()
        if @element_links.size > 0
          self[(@element_links.size - 1)]
        else
          nil
        end
      end
      #
      def each(&block)
        if block.respond_to?(:call)
          load_element_links
          if @element_links.size > 0
            @element_links.each_index do |index|
              block.call(self[(index)])
            end
          end
          self
        else
          self.to_enum(:each)
        end
      end
      #
      def each_index(&block)
        if block.respond_to?(:call)
          load_element_links
          if @element_links.size > 0
            @element_links.each_index do |index|
              block.call(index)
            end
          end
          self
        else
          self.to_enum(:each_index)
        end
      end
      #
      def each_with_index(offset=0,&block)
        if block.respond_to?(:call)
          load_element_links
          if @element_links.size > 0
            @element_links.to_enum(:each).with_index(offset).each do |entry, index|
              block.call(self[(index)], index)
            end
          end
          self
        else
          self.to_enum(:each_with_index,offset)
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
              #
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
      def unpersist()
        result = []
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
    end
  end
end
