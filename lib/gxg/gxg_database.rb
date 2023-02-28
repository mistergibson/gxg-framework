# require sequel here to ensure other mods are underneath it
require "sequel"
require "securerandom"
require "openssl"
require "base64"
require "net/ldap"
module GxG
  DB_SAFETY = ::Mutex.new
  DB = {:cache => {}, :formats => {}, :authority => nil, :administrator => nil, :roles => {}}
  #
  module Database
    # Class Place-holder Definitions
    class DetachedArray
      #
    end
    class DetachedHash
      #
    end
    class PersistedArray
      #
    end
    class PersistedHash
      #
    end
    #
    def self.element_tables()
      {
      :unspecified => nil,
      :element_boolean => [::TrueClass, ::FalseClass, ::NilClass],
      :element_integer => [::Integer],
      :element_float => [::Float],
      :element_bigdecimal => [::BigDecimal],
      :element_datetime => [::DateTime],
      :element_text => [::String],
      :element_binary => [::GxG::ByteArray],
      :element_array => [::Array],
      :element_hash => [::Hash]
      }
    end
    #
    def self.valid_field_classes()
      [::TrueClass, ::FalseClass, ::NilClass, ::Integer, ::Float, ::BigDecimal, ::DateTime, ::String, ::GxG::ByteArray]
    end
    def self.element_table_index(the_key=:unspecified)
      (::GxG::Database::element_tables().keys.index(the_key.to_sym) || 0)
    end
    #
    def self.element_table_by_index(the_index=0)
      (::GxG::Database::element_tables().keys[(the_index)] || :unspecified)
    end
    #
    def self.element_table_for_instance(the_instance=nil)
      result = :unspecified
      #
      table = ::GxG::Database::element_tables()
      table.keys.each do |the_key| 
        unless the_key == :unspecified
          if the_instance.is_any?(table[(the_key)])
            result = the_key
            break
          end
        end
      end
      #
      result
    end
    #
    def self.persistable?(the_object)
      result = true
      unless the_object.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
        if the_object.is_any?(::Hash, ::Array)
          the_object.search do |item, selector, container|
            if result
              if ::GxG::Database::element_table_for_instance(item) == :unspecified
                result = false
                break
              end
            end
            nil
          end
        else
          if ::GxG::Database::element_table_for_instance(the_object) == :unspecified
            result = false
          end
        end
      end
      result
    end
    #
    def self.iterative_detached_persist(old_root=nil)
      # New PersistedArray, or PersistedHash interface:
      # 
      result = nil
      begin
        # db open?
        # write permissions on db?
        unless old_root.is_any?(::Array, ::Hash)
          raise ArgumentError, "You MUST provide either an Array or a Hash."
        end
        unless GxG::Database::persistable?(old_root)
          raise ArgumentError, "The object you are attempting to persist contains a non-persistable item."
        end
        #
        if old_root.is_a?(::Array)
          original_partner = ::GxG::Database::DetachedArray.new()
          #
        end
        if old_root.is_a?(::Hash)
          original_partner = ::GxG::Database::DetachedHash.new()
        end
        #
        paring_data = [{:parent => nil, :parent_selector => nil, :object => old_root, :partner => original_partner}]
        children_of = Proc.new do |the_parent=nil|
          list = []
          paring_data.each do |node|
            if node[:parent].object_id == the_parent.object_id
              list << node
            end
          end
          list
        end
        #
        parent_of = Proc.new do |the_parent=nil|
          output = nil
          paring_data.each do |entry|
            if entry[:object].object_id == the_parent.object_id
              output = entry
            end
          end
          output
        end
        find_partner = Proc.new do |the_object|
          found_partner = nil
          paring_data.each do |the_record|
            if the_record.is_a?(::Hash)
              if the_record[:object].object_id == the_object.object_id
                found_partner = the_record[:partner]
                break
              end
            end
          end
          found_partner
        end
        # build paring data:
        delegate_permission = nil
        old_root.search do |the_value, the_selector, the_container|
          if the_value.is_a?(::Array)
            paring_data << {:parent => the_container, :parent_selector => the_selector, :object => the_value, :partner => ::GxG::Database::DetachedArray.new()}
          else
            if the_value.is_a?(::Hash)
              paring_data << {:parent => the_container, :parent_selector => the_selector, :object => the_value, :partner => ::GxG::Database::DetachedHash.new()}
            else
              paring_data << {:parent => the_container, :parent_selector => the_selector, :object => the_value, :partner => the_value}
            end
          end
        end
        #
        # Assign objects to structure in order by parent / parent_selector
        link_db = [(paring_data[0])]
        while link_db.size > 0
          entry = link_db.shift
          if entry.is_a?(::Hash)
            if entry[:object].is_any?(::Array, ::Hash)
              # get children and assign
              children = children_of.call(entry[:object])
              children.each do |child|
                entry[:partner][(child[:parent_selector])] = child[:partner]
                if child[:partner].is_any?(::GxG::Database::DetachedArray, ::GxG::Database::DetachedHash)
                  link_db << child
                end
              end
            end
          end
        end
        result = original_partner
      rescue Exception => the_error
        log_error({:error => the_error, :parameters => {:object => old_root}})
      end
      result
    end
    #
    def self.detached_format_find(the_criteria={})
      result = nil
      tests = {}
      [:uuid, :ufs, :title, :version].each do |the_key|
        if the_criteria[(the_key)]
          tests[(the_key)] = the_criteria[(the_key)]
        end
      end
      GxG::DB[:formats].each_pair do |uuid,record|
        score = 0
        tests.keys.each do |the_test|
          if record[(the_test)] == tests[(the_test)]
            score += 1
          end
        end
        if tests.keys.size == score
          result = record
          break
        end
      end
      result
    end
    #
    def self.detached_format_load(the_criteria={}, &block)
      # If already loaded and block provided: return an Array of format records.
      # Load any missing formats from server, and call block if provided.
      # Note: results are in NO particular order (DO NOT INDEX into the result set from source criteria)
      success = false
      needed = []
      results = []
      if the_criteria.is_a?(::Hash)
        loaded = ::GxG::Database::detached_format_find(the_criteria)
        if loaded
          results << loaded
          if block.respond_to?(:call)
            block.call(results)
          end
          success = true
        else
          needed << the_criteria
        end
      else
        if the_criteria.is_a?(::Array)
          the_criteria.each do |the_specifier|
            loaded = ::GxG::Database::detached_format_find(the_specifier)
            if loaded
              results << loaded
            else
              needed << the_specifier
            end
          end
        end
      end
      if needed.size > 0
        if ::GxG::DB[:roles][:format].is_a?(::GxG::Database::Database)
          needed.each do |the_specifier|
            format_record = ::GxG::DB[:roles][:format].format_load({:uuid => the_specifier.to_s.to_sym})
            if format_record
              GxG::DB[:formats][(format_record[:uuid].to_sym)] = format_record
              results << format_record
            end
          end
          if block.respond_to?(:call)
            block.call(results)
          end
          success = true
        end
      else
        if results.size > 0
          if block.respond_to?(:call)
            block.call(results)
          end
          success = true
        end
      end
      #
      success
    end
    #
    def self.process_detached_import(import_manifest=nil, options={})
        result = []
        if import_manifest.is_a?(::Hash)
            if import_manifest[:formats].size > 0
                # import formats: GxG::DB[:formats]
                import_manifest[:formats].keys.each do |the_key|
                    unless GxG::DB[:formats][(the_key)]
                      # Review do ::Hash.gxg_import on format content
                      format_record = import_manifest[:formats][(the_key)]
                      if format_record[:version].is_a?(::String)
                        format_record[:version] = BigDecimal.new(format_record[:version])
                      end
                      format_record[:content] = ::Hash.gxg_import(format_record[:content])
                      GxG::DB[:formats][(the_key)] = format_record
                    end
                end
            end
            #
            if import_manifest[:records].size > 1
              import_manifest[:records].each do |the_record|
                result << GxG::Database::DetachedHash::import(the_record)
              end
            else
              result << GxG::Database::DetachedHash::import(import_manifest[:records][0])
            end
        end
        result
    end
    #
    def self.process_import(import_manifest=nil, credential=nil, options={})
      # sync_import(credential=nil, the_records={:formats => {}, :records => []}, options={})
      result = false
      if import_manifest.is_a?(::Hash) && ::GxG::valid_uuid?(credential) && options.is_a?(::Hash)
        options = {:role => :data}.merge!(options)
        database = ::GxG::DB[:roles][(options[:role])]
        if database.is_a?(::GxG::Database::Database)
          if ::GxG::DB[:roles][:format].is_a?(::GxG::Database::Database)
            unless database == ::GxG::DB[:roles][:format]
              ::GxG::DB[:roles][:format].sync_import(credential, {:formats => import_manifest[:formats], :records => []}, options)
            end
          end
          #
          result = database.sync_import(credential, import_manifest, options)
        else
          log_warn("No suitable database of role #{options[:role].inspect} could be found for the import request : Ignoring Request")
        end
      else
        log_warn("Invalid parameters to import request : Ignoring Request")
      end
      result
    end
    #
    def self.as_import_record(records=[], options={})
      result = {:formats => {}, :records => []}
      if records.is_any?(::GxG::Database::DetachedHash, ::GxG::Database::PersistedHash)
        records = [(records)]
      end
      if records.is_any?(::Array, ::GxG::Database::DetachedArray, ::GxG::Database::PersistedArray)
        records.each do |the_object|
          if the_object.is_any?(::GxG::Database::DetachedHash, ::GxG::Database::PersistedHash)
            object_record = the_object.export()
            object_record.search do |item,selector,container|
              if selector == :format || selector == :constraint
                if item.to_s.size > 0
                  format_uuid = item
                  unless result[:formats][(format_uuid.to_s.to_sym)].is_a?(::Hash)
                    if ::GxG::DB[:roles][:format].is_a?(::GxG::Database::Database)
                      format_sample = ::GxG::DB[:roles][:format].format_load({:uuid => format_uuid.to_s.to_sym})
                      format_sample[:content] = format_sample[:content].gxg_export()
                      result[:formats][(format_uuid.to_s.to_sym)] = format_sample
                    end
                  end
                end
              end
            end
            result[:records] << object_record
            #
          end
        end
      end
      result
    end
    #
    def self.connect(the_url, options={})
      # TODO: require :credential (access privs)
      result = nil
      begin
        # check for URI ipv6 [format] compatibility
        db_url = ::URI::parse(the_url.to_s)
        the_path = db_url.path.to_s
        if the_path == ""
          the_path = db_url.hostname.to_s
        end
        if ::RUBY_ENGINE == "jruby"
          # jdbc:sqlite::memory:
          # jdbc:postgresql://localhost/database?user=username
          # jdbc:mysql://localhost/test?user=root&password=root
          # jdbc:h2:mem:
          # jdbc:hsqldb:mem:mymemdb
          # jdbc:derby:memory:myDb;create=true
          # jdbc:sqlserver://localhost;database=sequel_test;integratedSecurity=true
          # jdbc:jtds:sqlserver://localhost/sequel_test;user=sequel_test;password=sequel_test
          # jdbc:oracle:thin:user/password@localhost:1521:database
          # jdbc:db2://localhost:3700/database:user=user;password=password;
          # jdbc:sqlanywhere://localhost?DBN=Test;UID=user;PWD=password
          case db_url.scheme.to_sym
          when :sqlite, :sqlite3
            if ["/memory", "memory"].include?(the_path)
              result = Sequel.connect("jdbc:sqlite::memory:")
            else
              result = Sequel.connect("jdbc:sqlite:" + the_path)
            end
          when :mysql, :mysql2, :mariadb
            result = Sequel.connect(("jdbc:mysql://" + db_url.hostname.to_s + "/" + db_url.path.to_s.split("/").last.to_s + "?user=" + db_url.user.to_s + "&password=" + db_url.password.to_s + "&serverTimezone=UTC"))
          else
            raise Exception, "As-yet unsupported adapter type --> Under Construction"
          end
          #
        else
          case db_url.scheme.to_sym
          when :sqlite, :sqlite3
            if ["/memory", "memory"].include?(the_path)
              result = Sequel.connect("sqlite::memory:")
            else
              result = Sequel.connect("sqlite://" + the_path)
            end
          else
            # auto-forward to mysql2 gem if mysql:// scheme
            if db_url.scheme.to_s == "mysql"
              #
              result = Sequel.connect({:adapter => "mysql2", :host => (db_url.hostname.to_s), :database => (db_url.path.to_s.split("/").last), :user => (db_url.user.to_s), :password => (db_url.password.to_s)})
              #
            else
              #
              result = Sequel.connect({:adapter => (db_url.scheme.to_s), :host => (db_url.hostname.to_s), :database => (db_url.path.to_s.split("/").last), :user => (db_url.user.to_s), :password => (db_url.password.to_s)})
              #
            end
          end
        end
        result = ::GxG::Database::Database.new(result, options.merge({:url => (db_url)}))
      rescue => the_error
        log_error({:error => the_error, :parameters => {:url => (the_url), :options => (options)}})
      end
      result
    end
    # External Authority (Such as LDAP)
    class ExternalAuthority
      def alive?()
        true
      end
    end
    #
    class LDAPAuthority < ::GxG::Database::ExternalAuthority
      #
      def initialize(settings={})
        # Settings: {:host => "localhost", :port => 389, :base_dn => "cn=admin, dc=my-domain, dc=com", :password => "secret-word"}
        @active = false
        @connector = ::Net::LDAP.new
        @connector.host = ::TCPSocket.getaddress(settings[:host].to_s)
        @connector.port = settings[:port].to_s.to_i
        @connector.auth settings[:base_dn].to_s, settings[:password].to_s
        if @connector.bind
          @active = true
        else
          raise "Unable to bind to LDAP host."
        end        
        self
      end
      #
      def open?()
        @active
      end
      #
    end
    # Database class proper
    class Database
      def self.connect(the_url, options={})
        ::GxG::Database::connect(the_url, options)
      end
      #
      def self.element_tables()
        {
          :unspecified => nil,
          :element_boolean => [::TrueClass, ::FalseClass, ::NilClass],
          :element_integer => [::Integer],
          :element_float => [::Float],
          :element_bigdecimal => [::BigDecimal],
          :element_datetime => [::DateTime],
          :element_text => [::String],
          :element_binary => [::GxG::ByteArray],
          :element_array => [::Array],
          :element_hash => [::Hash]
        }
      end
      #
      def self.valid_field_classes()
        [::TrueClass, ::FalseClass, ::NilClass, ::Integer, ::Float, ::BigDecimal, ::DateTime, ::String, ::GxG::ByteArray]
      end
      #
      def self.element_table_index(the_key=:unspecified)
        (::GxG::Database::Database::element_tables().keys.index(the_key.to_sym) || 0)
      end
      #
      def self.element_table_by_index(the_index=0)
        (::GxG::Database::Database::element_tables().keys[(the_index)] || :unspecified)
      end
      #
      def self.element_table_for_instance(the_instance=nil)
        # Review : rewrite - in use
        result = :unspecified
        #
        table = ::GxG::Database::Database::element_tables()
        table.keys.each do |the_key| 
          unless the_key == :unspecified
            if the_instance.is_any?(table[(the_key)])
              result = the_key
              break
            end
          end
        end
        #
        result
      end
      #
      def db_migration()
        # Review : Consider adding support for a ::Symbol class as well. (ease-of-use implications later)
        # Internal mapping of the database format
        # Datatypes - See: http://sequel.jeremyevans.net/rdoc/files/doc/schema_modification_rdoc.html
        # Column Options - See: http://sequel.jeremyevans.net/rdoc/classes/Sequel/Database.html#method-i-add_column
        # See also : http://ruby-doc.org/core-2.2.0/Array.html#method-i-pack
        {
          :element_text => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :length => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)}
            },
          :text_page => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :parent_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :ordinal => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :length => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :content => {:type => :varchar, :options => {:size => 4099, :default => "", :null => false}, :bytes => 4099}
            },
          :element_binary => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :format => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :length => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)}
            },
          :binary_page => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :parent_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :ordinal => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :length => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :content => {:type => :blob, :options => {:size => 65536}, :bytes => 65536}
            },
          :element_array => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :constraint => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :title => {:type => :varchar, :options => {:size => 259, :null => false, :default => "Untitled"}, :bytes => 259},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
            },
          :array_elements => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :parent_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :ordinal => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :element => {:type => :varchar, :options => {:size => 259, :default => "element_boolean", :null => false}, :bytes => 259},
            :element_boolean => {:type => :integer, :options => {:size => 1, :default => -1}, :bytes => ([ -1 ].pack('l!').length)},
            :element_integer => {:type => :integer, :options => {}, :bytes => ([ -1 ].pack('l!').length)},
            :element_float => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :element_bigdecimal => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :element_datetime => {:type => :datetime, :options => {}, :bytes => 16},
            :time_offset => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :time_prior => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :time_after => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :length => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :element_text => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :element_text_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_binary_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_array_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_hash_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40}
          },
          :element_hash => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :format => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :title => {:type => :varchar, :options => {:size => 259, :null => false, :default => "Untitled"}, :bytes => 259},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
            },
          :hash_properties => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :parent_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :property => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :ordinal => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :element => {:type => :varchar, :options => {:size => 259, :default => "element_boolean", :null => false}, :bytes => 259},
            :element_boolean => {:type => :integer, :options => {:size => 1, :default => -1}, :bytes => ([ -1 ].pack('l!').length)},
            :element_integer => {:type => :integer, :options => {}, :bytes => ([ -1 ].pack('l!').length)},
            :element_float => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :element_bigdecimal => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :element_datetime => {:type => :datetime, :options => {}, :bytes => 16},
            :time_offset => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :time_prior => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :time_after => {:type => :float, :options => {:default => 0.0}, :bytes => ([ 0.1 ].pack('d').length)},
            :length => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :element_text => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :element_text_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_binary_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_array_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_hash_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40}
          },
          :element_locks => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :type => {:type => :varchar, :options => {:size => 40,:default => "", :null => false}, :bytes => 40},
            :reservation => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :credential => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :element_table => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :elementid => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)}
          },
          :trash => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :element_table => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :elementid => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)}
          },
          :users => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :user_id => {:type => :varchar, :options => {:size => 259, :null => false, :default => ""}, :bytes => 259},
            :password_hash => {:type => :varchar, :options => {:size => 259, :null => false, :default => ""}, :bytes => 259},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
          },
          :roles => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :seo => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :title => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
          },
          :user_roles => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :user_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :role_uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
          },
          :permissions => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :credential => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :execute => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :rename => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :move => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :destroy => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :create => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :write => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :read => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :element_table => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :elementid => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
          },
          :file_permissions => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :file_id => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :credential => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :execute => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :rename => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :move => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :destroy => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :create => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :write => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :read => {:type => :integer, :options => {:default => 0}, :bytes => ([ -1 ].pack('l!').length)},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
          },
          :formats => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :type => {:type => :varchar, :options => {:size => 40, :null => false, :default => "structure"}, :bytes => 40},
            :ufs => {:type => :varchar, :options => {:size => 4099, :default => "", :null => false}, :bytes => 4099},
            :title => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256},
            :mime_types => {:type => :varchar, :options => {:size => 4099, :default => "", :null => false}, :bytes => 4099}
          },
          :settings => {
            :dbid => {:type => :integer, :options => {:unique => true, :primary_key => true, :auto_increment => true}, :bytes => ([ -1 ].pack('l!').length)},
            :uuid => {:type => :varchar, :options => {:size => 40, :default => "", :null => false}, :bytes => 40},
            :title => {:type => :varchar, :options => {:size => 259, :default => "", :null => false}, :bytes => 259},
            :version => {:type => :numeric, :options => {:default => ::BigDecimal.new("0.0")}, :bytes => 256}
          }
        }
      end
      #
      def db_format(format_options={})
        # MySql stuff:
        # ALTER TABLE tbl_name MAX_ROWS=1000000000 AVG_ROW_LENGTH=nnn;
        # See: https://dev.mysql.com/doc/refman/5.0/en/table-size-limit.html
        result = true
        #
        begin
          if @connector.is_a?(::Sequel::Database)
            case @scheme
            when :sqlite
              @connector.run("PRAGMA page_size=65536")
              @connector.run("PRAGMA max_page_count=281474976710656")
              @connector.run("PRAGMA encoding='UTF-8'")
            when :mysql, :mysql2
              @connector.run("SET GLOBAL max_allowed_packet = 17825792;")
              @connector.run("SET NAMES 'utf8' COLLATE 'utf8_general_ci';")
              @connector.run("SET collation_connection = 'utf8_general_ci';")
            when :postgres
              # place holder
            end
            migration = db_migration()
            migration.keys.each do |the_table|
              unless @connector.table_exists?(the_table)
                  @connector.create_table(the_table) do
                  primary_key :dbid
                end
              end
              used_bytes = 0
              #
              existing_columns = @connector[(the_table)].columns
              migration[(the_table)].keys.each do |the_column|
                used_bytes += (migration[(the_table)][(the_column)][:bytes]).to_i
                if existing_columns.include?(the_column)
                  # TODO: figure out a way to inspect columns for attributes -> detailed verification
                else
                  # collation for mysql
                  if @scheme == :mysql
                    # Note: might have to specify :collate first, use -> {:collate => ""}.merge(migration[(the_table)][(the_column)][:options])
                    if migration[(the_table)][(the_column)][:type] == :varchar
                      # migration[(the_table)][(the_column)][:options] = {:collate => "utf8_general_ci"}.merge(migration[(the_table)][(the_column)][:options])
                      migration[(the_table)][(the_column)][:options][:collate] = "utf8_general_ci"
                    end
                    if migration[(the_table)][(the_column)][:type] == :blob
                      # migration[(the_table)][(the_column)][:options] = {:collate => "binary"}.merge(migration[(the_table)][(the_column)][:options])
                      # Note: MySQL 5 doesn't like putting collation on blobs! (blows up)
                      # migration[(the_table)][(the_column)][:options][:collate] = "binary"
                    end
                  else
                  end
                  # do the deed
                  @connector.add_column((the_table), (the_column), (migration[(the_table)][(the_column)][:type]), (migration[(the_table)][(the_column)][:options]))
                  #
                end
              end
              #
              if @scheme == :mysql
                # @connector.run("ALTER TABLE #{the_table.to_s} MAX_ROWS=18446744073709551616 AVG_ROW_LENGTH=#{used_bytes.to_s};")
              end
              #
            end
          else
            raise Exception, "Invalid db connection"
          end
        rescue Exception => the_error
          result = false
          log_error({:error => the_error, :parameters => format_options})
        end
        #
        result
      end
      #
      def db_formatted?()
        result = true
        #
        begin
          if @connector.is_a?(::Sequel::Database)
            migration = db_migration()
            migration.keys.each do |the_table|
              unless @connector.table_exists?(the_table)
                result = false
                break
              end
              #columns
              existing_columns = @connector[(the_table)].columns
              migration[(the_table)].keys.each do |the_column|
                unless existing_columns.include?(the_column)
                  result = false
                  break
                end
              end
              #
              unless (result)
                break
              end
            end
          else
            raise Exception, "Invalid db connection"
          end
        rescue Exception => the_error
          result = false
          log_error({:error => the_error, :parameters => nil})
        end
        #
        result
      end
      #
      def open?()
        begin
          @connector.synchronize do |connection|
            @active = @connector.valid_connection?(connection)
          end
        rescue => the_error
          @active = false
          log_error({:error => the_error, :parameters => nil})
        end
        @active
      end
      #
      def close()
        # place holder for now.
        if @authority
          @authority.db_unregister(self)
        end
      end
      #
      def connector()
        @connector
      end
      #
      #
      def to_uri()
        ::URI.parse(@url.to_s)
      end
      #
      def inspect()
        "<Database: #{self.to_uri()}>"
      end
      # ### Permission Handling methods
      def db_permissions
        @base_permissions.clone
      end
      # ### Authority support
      def db_register(the_db)
        if the_db.is_a?(::GxG::Database::Database)
          unless @db_list.find_index(the_db)
            @db_list << the_db
          end
        end
      end
      #
      def db_unregister(the_db)
        if the_db.is_a?(::GxG::Database::Database)
          if @db_list.find_index(the_db)
            @db_list.delete_at(@db_list.find_index(the_db))
          end
        end
      end
      #
      def db_list()
        result = []
        @db_list.each do |the_db|
          result << the_db
        end
        result
      end
      # ### User, Role, and Group methods
      #
      def user_manifest(include_password=false)
        result = []
        if @authority
          result = @authority.user_manifest(include_password)
        else
          if self.alive?
            if self.open?
              begin
                if include_password == true
                  dataset = @connector[:users].select(:uuid, :user_id, :password_hash, :version).all
                else
                  dataset = @connector[:users].select(:uuid, :user_id, :version).all
                end
                dataset.each do |entry|
                  result << entry
                end
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {}})
              end
            end
          end
        end
        result
      end
      #
      def user_id_available?(the_user_id)
        result = false
        if @authority
          result = @authority.user_id_available?(the_user_id)
        else
          if self.alive?
            if self.open?
              begin
                if the_user_id.to_s.size <= 256
                  if @connector[:users].filter({:user_id => (the_user_id.to_s)}).count == 0
                    result = true
                  end
                else
                  raise ArgumentError, "Oversized UserID attempted: #{the_user_id}"
                end
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:user_id => the_user_id}})
              end
            end
          end
        end
        result
      end
      #
      def user_exist?(the_user_id)
        result = false
        if @authority
          result = @authority.user_exist?(the_user_id)
        else
          if self.alive?
            if self.open?
              begin
                if ::GxG::valid_uuid?(the_user_id)
                  if @connector[:users].filter({:uuid => (the_user_id.to_s)}).count > 0
                    result = true
                  end
                else
                  if the_user_id.to_s.size <= 256
                    if @connector[:users].filter({:user_id => (the_user_id.to_s)}).count > 0
                      result = true
                    end
                  else
                    raise ArgumentError, "Oversized UserID attempted: #{the_user_id}"
                  end
                end
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:user_id => the_user_id}})
              end
            end
          end
        end
        result
      end
      #
      def user_credential(the_user_id="", the_password="")
        result = nil
        if @authority
          result = @authority.user_credential(the_user_id, the_password)
        else
          if self.alive?
            if self.open?
              begin
                if the_user_id.to_s.size <= 256
                  if the_password.to_s.size > 0
                    record = @connector[:users].select(:uuid, :user_id, :password_hash).where({:user_id => (the_user_id.to_s)}).first
                    if record
                      salt = record[:password_hash].split("\t")[0].to_s
                      pbkdf2 = ::Base64.decode64(record[:password_hash].split("\t")[1].to_s)
                      tester = ::OpenSSL::PKCS5::pbkdf2_hmac_sha1(the_password.to_s, salt, 1000, pbkdf2.length)
                      if pbkdf2 == tester
                        result = record[:uuid].to_sym
                      else
                        log_warn("Password attempt invalid for #{the_user_id}")
                      end
                    else
                      raise Exception, "UserID not found: #{the_user_id}"
                    end
                  else
                    raise Exception, "Empty password not supported"
                  end
                else
                  raise Exception, "Oversized UserID attempted: #{the_user_id}"
                end
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:user_id => the_user_id}})
              end
            end
          end
        end
        result
      end
      #
      def user_create(the_user_id="", the_password="", use_credential=nil)
        result = false
        if @authority
          result = @authority.user_create(the_user_id, the_password)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if the_user_id.to_s.size <= 256
                    if the_password.to_s.size > 0
                      if self.user_id_available?(the_user_id)
                        if ::GxG::valid_uuid?(use_credential)
                          the_uuid = use_credential.to_s
                          if (@connector[:users].filter({:uuid => (the_uuid.to_s)}).count > 0)
                            raise Exception, "That credential UUID is already in use"
                          end
                        else
                          the_uuid = ::GxG::uuid_generate()
                          while (@connector[:users].filter({:uuid => (the_uuid.to_s)}).count > 0)
                            the_uuid = ::GxG::uuid_generate()
                          end
                        end
                        salt = ::SecureRandom.base64(24)
                        pbkdf2 = ::OpenSSL::PKCS5::pbkdf2_hmac_sha1(the_password, salt, 1000, 24)
                        the_pass_hash = [salt, ::Base64.strict_encode64(pbkdf2)].join("\t")
                        @connector[:users].insert({:uuid => (the_uuid), :user_id => (the_user_id.to_s), :password_hash => (the_pass_hash)})
                        result = true
                      else
                        raise Exception, "UserID not available: #{the_user_id}"
                      end
                    else
                      raise ArgumentError, "Empty password not supported"
                    end
                  else
                    raise ArgumentError, "Oversized UserID attempted: #{the_user_id}"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:user_id => the_user_id}})
                end
              end
            end
          end
        end
        result
      end
      #
      def user_update(credential=nil, user_id=nil)
        result = false
        if @authority
          result = @authority.user_update(credential, user_id)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if ::GxG::valid_uuid?(credential)
                    if self.user_id_available?(user_id.to_s)
                      record = @connector[:users].filter({:uuid => (credential.to_s)}).first
                      if record
                        @connector[:users].filter({:uuid => (credential.to_s)}).update({:user_id => (user_id), :version => (record[:version] + 0.0001)})
                        result = true
                      else
                        raise Exception, "User record not found"
                      end
                    else
                      log_warn("UserID is not available: #{user_id.to_s}")
                    end
                  else
                    raise ArgumentError, "You must supply a valid user credential (as a String or Symbol)"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:credential => credential, :user_id => user_id}})
                end
              end
            end
          end
        end
        result
      end
      #
      def user_set_password(credential=nil, old_password="", new_password="")
        result = false
        if @authority
          result = @authority.user_set_password(credential, old_password, new_password)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if ::GxG::valid_uuid?(credential)
                    if new_password.to_s.size > 0
                      if @connector[:users].filter({:uuid => (credential.to_s)}).count > 0
                        record = @connector[:users].filter({:uuid => (credential.to_s)}).first
                        if record
                          if self.user_credential(record[:user_id], old_password).to_s == credential.to_s
                            salt = ::SecureRandom.base64(24)
                            pbkdf2 = ::OpenSSL::PKCS5::pbkdf2_hmac_sha1(new_password, salt, 1000, 24)
                            the_pass_hash = [salt, ::Base64.strict_encode64(pbkdf2)].join("\t")
                            @connector[:users].filter({:uuid => (credential.to_s)}).update({:password_hash => (the_pass_hash), :version => (BigDecimal(record[:version].to_s) + 0.0001)})
                            result = true
                          else
                            log_warn("Invalid password change attempted for #{credential}")
                          end
                        else
                          raise Exception, "Could not retrieve user record: #{credential}"
                        end
                      else
                        raise Exception, "No user with that credential exists"
                      end
                    else
                      raise ArgumentError, "Empty password not supported"
                    end
                  else
                    raise ArgumentError, "Invalid credential argument: #{credential}"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:credential => credential}})
                end
              end
            end
          end
        end
        result
      end
      #
      def user_destroy(credential=nil)
        result = false
        if @authority
          result = @authority.user_destroy(credential)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if ::GxG::valid_uuid?(credential)
                    if @connector[:users].filter({:uuid => (credential.to_s)}).count > 0
                      the_list = self.db_list()
                      the_list << (self)
                      the_list.each do |the_db|
                        the_db.connector()[:permissions].filter({:credential => (credential.to_s)}).delete
                        the_db.connector()[:user_roles].filter({:user_uuid => (credential.to_s)}).delete
                      end
                      @connector[:users].filter({:uuid => (credential.to_s)}).delete
                      result = true
                    end
                  else
                    raise ArgumentError, "Invalid credential argument: #{credential}"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:credential => credential}})
                end
              end
            end
          end
        end
        result
      end
      #
      def user_fetch(search_options={})
        result = nil
        if @authority
          result = @authority.user_fetch(search_options)
        else
          if self.alive?
            if self.open?
              begin
                result = @connector[:users].filter(search_options).first
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:credential => (credential)}})
              end
            end
          end
        end
        result
      end
      #
      def user_roles(credential=nil)
        result = []
        if @authority
          result = @authority.user_roles(credential)
        else
          if self.alive?
            if self.open?
              begin
                if ::GxG::valid_uuid?(credential)
                  memberships = @connector[:user_roles].select(:role_uuid).where({:user_uuid => (credential.to_s)})
                  pull_list = []
                  memberships.each do |record|
                    unless pull_list.find_index(record[:role_uuid].to_sym)
                      pull_list << record[:role_uuid].to_sym
                    end
                  end
                  pull_list.each do |role_uuid|
                    record = @connector[:roles].filter({:uuid => (role_uuid.to_s)})
                    if record
                      result << {:credential => (role_uuid), :title => (record[:title]), :seo => (record[:seo])}
                    end
                  end
                else
                  raise ArgumentError, "You must supply a valid user credential (as a String or Symbol)"
                end
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:credential => (credential)}})
              end
            end
          end
        end
        result
      end
      #
      def role_manifest()
        result = []
        #
        if @authority
          result = @authority.roles()
        else
          if self.alive?
            if self.open?
              @connector[:roles].all.each do |record|
                result << {:uuid => record[:uuid].to_s.to_sym, :title => record[:title], :seo => record[:seo], :version => BigDecimal(record[:version].to_s)}
              end
            end
          end
        end
        #
        result
      end
      #
      def role_exist?(credential=nil)
        result = nil
        if @authority
          result = @authority.role_exist?(credential)
        else
          if self.alive?
            if self.open?
              if ::GxG::valid_uuid?(credential)
                if @connector[:roles].filter({:uuid => (credential.to_s)}).count > 0
                  result = true
                end
              else
                if @connector[:roles].filter({:title => (credential.to_s)}).count > 0
                  result = true
                end
              end
            end
          end
        end
        result
      end
      #
      def role_create(title="", seo="")
        result = nil
        if @authority
          result = @authority.role_create(title,seo)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  #
                  if title.to_s.size <= 256
                    #
                    if title.to_s.size == 0
                      raise ArgumentError, "You MUST supply a title for the role."
                    end
                    unless seo.to_s.size <= 256
                      raise ArgumentError, "Oversized SEO attempted (256 Character Limit): #{seo}"
                    end
                    if seo.to_s.size == 0
                      seo = title.downcase.gsub(" ","_")[0..255]
                    end
                    the_uuid = ::GxG::uuid_generate()
                    while (@connector[:roles].filter({:uuid => (the_uuid.to_s)}).count > 0)
                      the_uuid = ::GxG::uuid_generate()
                    end
                    @connector[:roles].insert({:uuid => (the_uuid.to_s), :title => (title.to_s), :seo => (seo.to_s)})
                    result = the_uuid.to_sym
                  else
                    raise ArgumentError, "Oversized title attempted (256 Character Limit): #{title}"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:title => (title), :seo => (seo)}})
                end
              end
            end
          end
        end
        result
      end
      #
      def role_update(role_uuid=nil, data={})
        # data: :title, :seo
        result = false
        if @authority
          result = @authority.role_update(role_uuid,data)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  unless data.is_a?(::Hash)
                    raise Exception, "Update data must be passed in a Hash"
                  end
                  if ::GxG::valid_uuid?(role_uuid)
                    record = @connector[:roles].filter({:uuid => (role_uuid.to_s)}).first
                    if record
                      the_title = (data[:title] || record[:title].to_s)
                      the_seo = (data[:seo] || the_title.downcase.gsub(" ", "_"))
                      #
                      @connector[:roles].filter({:uuid => (role_uuid.to_s)}).update({:title => (the_title), :seo => (the_seo), :version => (BigDecimal(record[:version].to_s) + 0.0001)})
                      result = true
                    else
                      raise Exception, "Attempted to update a non-existent role: #{role_uuid}"
                    end
                  else
                    raise ArgumentError, "You must specify a valid role UUID (as a String or Symbol)"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:role_uuid => (role_uuid), :data => (data)}})
                end
              end
            end
          end
        end
        result
      end
      #
      def role_destroy(role_uuid=nil)
        result = false
        if @authority
          result = @authority.role_destroy(role_uuid)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if ::GxG::valid_uuid?(role_uuid)
                    # cannot destroy if still linked as group's default role
                    record = @connector[:roles].filter({:uuid => (role_uuid.to_s)}).first
                    if record
                      the_list = self.db_list()
                      the_list << (self)
                      the_list.each do |the_db|
                        the_db.connector()[:permissions].filter({:credential => (role_uuid.to_s)}).delete
                        the_db.connector()[:user_roles].filter({:role_uuid => (role_uuid.to_s)}).delete
                      end
                      @connector[:roles].filter({:uuid => (role_uuid.to_s)}).delete
                      result = true
                    end
                  else
                    raise ArgumentError, "You must specify a valid role UUID (as a String or Symbol)"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:role_uuid => (role_uuid)}})
                end
              end
            end
          end
        end
        result
      end
      #
      def role_add_user(role_uuid=nil, credential=nil)
        result = false
        if @authority
          result = @authority.role_add_user(role_uuid, credential)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if ::GxG::valid_uuid?(role_uuid)
                    if ::GxG::valid_uuid?(credential)
                      if @connector[:user_roles].filter({:role_uuid => (role_uuid.to_s), :user_uuid => (credential.to_s)}).count == 0
                        @connector[:user_roles].insert({:role_uuid => (role_uuid.to_s), :user_uuid => (credential.to_s)})
                      end
                      result = true
                    else
                      raise ArgumentError, "You must specify a valid user credential UUID (as a String or Symbol)"
                    end
                  else
                    raise ArgumentError, "You must specify a valid role UUID (as a String or Symbol)"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:role_uuid => (role_uuid), :credential => (credential)}})
                end
              end
            end
          end
        end
        result
      end
      #
      def role_remove_user(role_uuid=nil, credential=nil)
        result = false
        if @authority
          result = @authority.role_remove_user(role_uuid, credential)
        else
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                begin
                  if ::GxG::valid_uuid?(role_uuid)
                    if ::GxG::valid_uuid?(credential)
                      if @connector[:user_roles].filter({:role_uuid => (role_uuid.to_s), :user_uuid => (credential.to_s)}).count > 0
                        @connector[:user_roles].filter({:role_uuid => (role_uuid.to_s), :user_uuid => (credential.to_s)}).delete
                      end
                      result = true
                    else
                      raise ArgumentError, "You must specify a valid user credential UUID (as a String or Symbol)"
                    end
                  else
                    raise ArgumentError, "You must specify a valid role UUID (as a String or Symbol)"
                  end
                rescue Exception => the_error
                  log_error({:error => the_error, :parameters => {:role_uuid => (role_uuid), :credential => (credential)}})
                end
              end
            end
          end
        end
        result
      end
      #
      def role_member?(role_uuid=nil, credential=nil)
        result = false
        if @authority
          result = @authority.role_member?(role_uuid, credential)
        else
          if self.alive?
            if self.open?
              begin
                if ::GxG::valid_uuid?(role_uuid)
                  if ::GxG::valid_uuid?(credential)
                    if @connector[:user_roles].filter({:role_uuid => (role_uuid.to_s), :user_uuid => (credential.to_s)}).count > 0
                      result = true
                    end
                  else
                    raise ArgumentError, "You must specify a valid user credential UUID (as a String or Symbol)"
                  end
                else
                  raise ArgumentError, "You must specify a valid role UUID (as a String or Symbol)"
                end
              rescue Exception => the_error
                log_error({:error => the_error, :parameters => {:role_uuid => (role_uuid), :credential => (credential)}})
              end
            end
          end
        end
        result
      end
      #
      def role_members(role_uuid=nil)
        result = []
        if @authority
          result = @authority.role_members(role_uuid)
        else
          if self.alive?
            if self.open?
              if GxG::valid_uuid?(role_uuid)
                @connector[:user_roles].filter({:role_uuid => (role_uuid.to_s)}).each do |the_record|
                  unless result.include?(the_record[:user_uuid].to_s.to_sym)
                    result << the_record[:user_uuid].to_s.to_sym
                  end
                end
              end
            end
          end
        end
        result
      end
      #
      def role_fetch(search_options={})
        result = nil
        if @authority
          result = @authority.role_fetch(search_options)
        else
          if self.alive?
            if self.open?
              result = @connector[:roles].filter(search_options).first
            end
          end
        end
        result
      end
      #
      # ### Raw Permission Handling methods
      def element_permissions(table=:unspecified, dbid=0, options={})
        result = []
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless dbid.is_a?(::Integer)
            raise ArgumentError, "dbid must be specified with a Integer"
          end
          unless options.is_a?(::Hash)
            raise ArgumentError, "options must be specified with a Hash"
          end
          credential = options[:credential]
          if credential
            unless ::GxG::valid_uuid?(credential)
              raise ArgumentError, "This option requires a valid credential UUID (as a String or Symbol)"
            end
          end
          if table.is_a?(::Integer)
            table = ::GxG::Database::Database::element_table_by_index(table)
          end
          # Review : change in permission policy
          # if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(table)
          if [:element_array, :element_hash].include?(table)
            if credential
              list = @connector[:permissions].filter({:element_table => (table.to_s), :elementid => (dbid), :credential => (credential.to_s)})
            else
              list = @connector[:permissions].filter({:element_table => (table.to_s), :elementid => (dbid)})
            end
            list.each do |record|
              # [:execute, :rename, :move, :destroy, :create, :write, :read]
              entry = {:credential => (record[:credential].to_sym), :table => (record[:element_table].to_sym), :dbid => (record[:elementid]), :permissions => {}}
              [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                if record[(the_permission)] == 1
                  entry[:permissions][(the_permission)] = true
                else
                  entry[:permissions][(the_permission)] = false
                end
              end
              result << entry
            end
          else
            raise ArgumentError, "Invalid table specified"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid), :options => (options)}})
        end
        result
      end
      #
      def revoke_element_permissions(table=:unspecified, dbid=0, credential=nil)
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless dbid.is_a?(::Integer)
            raise ArgumentError, "dbid must be specified with a Integer"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "This option requires a valid credential UUID (as a String or Symbol)"
          end
          if table.is_a?(::Integer)
            table = ::GxG::Database::Database::element_table_by_index(table)
          end
          # Review : change in permission policy
          # if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(table)
          if [:element_array, :element_hash].include?(table)
            @connector[:permissions].filter({:element_table => (table.to_s), :elementid => (dbid), :credential => (credential.to_s)}).delete
            result = true
          else
            raise ArgumentError, "Invalid table specified"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid), :options => (options)}})
        end
        result
      end
      #
      #
      def element_permissions_manifest(table=:unspecified, dbid=0, options={})
        result = []
        self.element_permissions(table,dbid,options).each do |entry|
          the_record = {:credential => nil, :permissions => {}, :details => {}}
          #
          the_record[:credential] = entry[:credential]
          the_record[:permissions] = entry[:permissions]
          if self.role_exist?(entry[:credential])
            role = self.role_fetch({:uuid => entry[:credential].to_s})
            group = self.group_fetch({:uuid => role[:group_uuid].to_s})
            the_record[:details][:role_title] = role[:title]
            the_record[:details][:group] = group[:uuid].to_s.to_sym
            the_record[:details][:group_title] = group[:title]
          else
            if self.user_exist?(entry[:credential])
              user = self.user_fetch({:uuid => entry[:credential].to_s})
              the_record[:details][:user_title] = user[:user_id]
            else
              log_warn("Invalid User Credential Detected: #{entry[:credential].to_s.to_sym.inspect}")
              the_record[:details][:user_title] = "Invalid User Credential #{entry[:credential].to_s.to_sym.inspect} !"
            end
          end
          result << the_record
        end
        result
      end
      #
      def element_permissions_by_uuid(the_uuid=nil,options={})
        result = []
        begin
          if self.alive?
            if self.open?
              found = @connector[:element_hash].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
              if found
                result = self.element_permissions_manifest(:element_hash,(found[:dbid]),options)
              else
                found = @connector[:element_array].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
                if found
                  result = self.element_permissions_manifest(:element_array,(found[:dbid]),options)
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:uuid => (the_uuid)}})
        end
        result
      end
      #
      def revoke_permissions_by_uuid(the_uuid=nil, credential=nil)
        result = false
        begin
          if self.alive?
            if self.open?
              found = @connector[:element_hash].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
              if found
                result = self.revoke_element_permissions(:element_hash,(found[:dbid]),credential)
              else
                found = @connector[:element_array].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
                if found
                  result = self.revoke_element_permissions(:element_array,(found[:dbid]),credential)
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:uuid => (the_uuid)}})
        end
        result
      end
      #
      def assign_element_permission(table=:unspecified, dbid=0, credential=nil, permissions={})
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless dbid.is_a?(::Integer)
            raise ArgumentError, "dbid must be specified with a Integer"
          end
          unless permissions.is_a?(::Hash)
            raise ArgumentError, "permissions must be specified with a Hash"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
          end
          if table.is_a?(::Integer)
            table = ::GxG::Database::Database::element_table_by_index(table)
          end
          # Review : change in permission policy
          # if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(table)
          if [:element_array, :element_hash].include?(table)
            record = @connector[:permissions].filter({:element_table => (table.to_s), :elementid => (dbid), :credential => (credential.to_s)}).first
            if record
              # update
              the_update = {:execute => 0, :rename => 0, :move => 0, :destroy => 0, :create => 0, :write => 0, :read => 0}
              [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                if record[(the_permission)] == 1
                  the_update[(the_permission)] = 1
                end
              end
              [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                if permissions[(the_permission)].is_a?(::TrueClass)
                  the_update[(the_permission)] = 1
                end
                if permissions[(the_permission)].is_a?(::FalseClass)
                  the_update[(the_permission)] = 0
                end
              end
              the_update[:version] = record[:version] + 0.0001
              @connector[:permissions].filter({:dbid => (record[:dbid])}).update(the_update)
            else
              # create
              new_record = {:credential => (credential.to_s), :element_table => (table.to_s), :elementid => (dbid), :execute => 0, :rename => 0, :move => 0, :destroy => 0, :create => 0, :write => 0, :read => 0}
              [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                if permissions[(the_permission)]
                  new_record[(the_permission)] = 1
                end
              end
              @connector[:permissions].insert(new_record)
            end
            result = true
          else
            raise ArgumentError, "Invalid table specified"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid), :credential => (credential), :permissions => (permissions)}})
        end
        result
      end
      #
      def extend_element_permissions(source_table=:unspecified, source_dbid=0, dest_table=:unspecified, dest_dbid=0)
        permissions = self.element_permissions(source_table, source_dbid)
        permissions.each do |entry|
          if [:persisted_array, :persisted_hash].include?(dest_table)
            self.assign_element_permission(dest_table, dest_dbid, entry[:credential], entry[:permissions])
          end
        end
      end
      #
      def remove_element_permissions(table=:unspecified, dbid=0, options={})
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless dbid.is_a?(::Integer)
            raise ArgumentError, "dbid must be specified with a Integer"
          end
          unless options.is_a?(::Hash)
            raise ArgumentError, "permissions must be specified with a Hash"
          end
          credential = options[:credential]
          if credential
            unless ::GxG::valid_uuid?(credential)
              raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
            end
          end
          if table.is_a?(::Integer)
            table = ::GxG::Database::Database::element_table_by_index(table)
          end
          # Review : change in permission policy
          # if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(table)
          if [:element_array, :element_hash].include?(table)
            if credential
              @connector[:permissions].filter({:element_table => (table.to_s), :elementid => (dbid), :credential => (credential.to_s)}).delete
            else
              @connector[:permissions].filter({:element_table => (table.to_s), :elementid => (dbid)}).delete
            end
            result = true
          else
            raise ArgumentError, "Invalid table specified"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid), :options => (options)}})
        end
        result
      end
      # ### Effective Permission Handling methods
      # ### VFS File permission mappings
      def vfs_permission_exist?(file_id=nil, credential=nil)
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless file_id.is_a?(::String)
            raise ArgumentError, "file_id must be specified with a String"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
          end
          #
          if @connector[:file_permissions].filter({:file_id => file_id.to_s, :credential => credential.to_s}).count > 0
            result = true
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_id => (file_id), :credential => (credential)}})
        end
        result
      end
      #
      def vfs_permission(file_id=nil, credential=nil)
        result = []
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless file_id.is_a?(::String)
            raise ArgumentError, "dbid must be specified with a String"
          end
          if credential
            unless ::GxG::valid_uuid?(credential)
              raise ArgumentError, "This option requires a valid credential UUID (as a String or Symbol)"
            end
          end
          #
          if credential
            list = @connector[:file_permissions].filter({:file_id => (file_id.to_s), :credential => (credential.to_s)})
          else
            list = @connector[:file_permissions].filter({:file_id => (file_id.to_s)})
          end
          list.each do |record|
            # [:execute, :rename, :move, :destroy, :create, :write, :read]
            entry = {:credential => (record[:credential].to_sym), :permissions => {}}
            [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
              if record[(the_permission)] == 1
                entry[:permissions][(the_permission)] = true
              else
                entry[:permissions][(the_permission)] = false
              end
            end
            result << entry
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_id => (file_id), :credential => (credential)}})
        end
        result
      end
      #
      def vfs_permission_manifest(file_id=nil, credential=nil)
        result = []
        self.vfs_permission(file_id, credential).each do |entry|
          the_record = {:credential => nil, :permissions => {}, :details => {}}
          #
          the_record[:credential] = entry[:credential]
          the_record[:permissions] = entry[:permissions]
          if self.role_exist?(entry[:credential])
            role = self.role_fetch({:uuid => entry[:credential].to_s})
            the_record[:details][:role_title] = role[:title]
          else
            if self.user_exist?(entry[:credential])
              user = self.user_fetch({:uuid => entry[:credential].to_s})
              the_record[:details][:user_title] = user[:user_id]
            else
              log_warn("Invalid User Credential Detected: #{entry[:credential].to_s.to_sym.inspect}")
              the_record[:details][:user_title] = "Invalid User Credential #{entry[:credential].to_s.to_sym.inspect} !"
            end
          end
          result << the_record
        end
        result
      end
      #
      def effective_vfs_permission(file_id=nil, credential=nil)
        result = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false}
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless file_id.is_a?(::String)
            raise ArgumentError, "file_id must be specified with a String"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
          end
          # ### VFS Permissions
          raw_permissions = []
          credentials = ["00000000-0000-4000-0000-000000000000"]
          if self.user_exist?(credential)
            credentials << credential
            role_list = self.user_roles(credential)
            role_list.each do |entry|
              credentials << entry[:credential]
            end
            #
          else
            if self.role_exist?(credential)
              credentials << credential
            else
              raise ArgumentError, "Invalid credential.  It is neither a user nor a role UUID"
            end
          end
          credentials.each do |entry|
            manifest = @connector[:file_permissions].filter({:file_id => file_id.to_s, :credential => (entry.to_s)})
            manifest.each do |record|
              new_permission = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false}
              [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                if record[(the_permission)] == 1
                  new_permission[(the_permission)] = true
                end
              end
              raw_permissions << new_permission
            end
          end
          raw_permissions.each do |entry|
            [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
              if entry[(the_permission)]
                result[(the_permission)] = true
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_id => (file_id), :credential => (credential)}})
        end
        result
      end
      #
      def create_vfs_permission(file_id=nil, credential=nil, permission={:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false})
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless file_id.is_a?(::String)
            raise ArgumentError, "file_id must be specified with a String"
          end
          unless permission.is_a?(::Hash)
            raise ArgumentError, "permission must be specified with a Hash"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
          end
          #
          record = @connector[:file_permissions].filter({:file_id => file_id.to_s, :credential => credential.to_s}).first
          if record
            update = true
            dbid = record.delete(:dbid)
          else
            update = false
            dbid = nil
            record = {:file_id => file_id.to_s, :credential => credential.to_s, :execute => 0, :rename => 0, :move => 0, :destroy => 0, :create => 0, :write => 0, :read => 0}
          end
          permission.keys.each do |the_permission_key|
            if permission[(the_permission_key)] == true
              record[(the_permission_key)] = 1
            else
              record[(the_permission_key)] = 0
            end
          end
          if update == true
            @connector[:file_permissions].filter({:dbid => dbid}).update(record)
          else
            @connector[:file_permissions].insert(record)
          end
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_id => (file_id), :credential => (credential)}})
        end
        result
      end
      #
      def update_vfs_permission(file_id=nil, credential=nil, permission={:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false})
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless file_id.is_a?(::String)
            raise ArgumentError, "file_id must be specified with a String"
          end
          unless permission.is_a?(::Hash)
            raise ArgumentError, "permission must be specified with a Hash"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
          end
          #
          record = @connector[:file_permissions].filter({:file_id => file_id.to_s, :credential => credential.to_s}).first
          if record
            update = true
            dbid = record.delete(:dbid)
          else
            update = false
            dbid = nil
            record = {:file_id => file_id.to_s, :credential => credential.to_s, :execute => 0, :rename => 0, :move => 0, :destroy => 0, :create => 0, :write => 0, :read => 0}
            # Review : should we update the version ??
          end
          permission.keys.each do |the_permission_key|
            if permission[(the_permission_key)] == true
              record[(the_permission_key)] = 1
            else
              record[(the_permission_key)] = 0
            end
          end
          if update == true
            @connector[:file_permissions].filter({:dbid => dbid}).update(record)
          else
            @connector[:file_permissions].insert(record)
          end
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_id => (file_id), :credential => (credential)}})
        end
        result
      end
      #
      def destroy_vfs_permission(file_id=nil, credential=nil)
        result = false
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless file_id.is_a?(::String)
            raise ArgumentError, "file_id must be specified with a String"
          end
          # ### Review : make more efficient
          if credential
            unless ::GxG::valid_uuid?(credential)
              raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
            end
            record = @connector[:file_permissions].filter({:file_id => file_id.to_s, :credential => credential.to_s}).first
            if record
              @connector[:file_permissions].filter({:file_id => file_id.to_s, :credential => credential.to_s}).delete
            end
          else
            record = @connector[:file_permissions].filter({:file_id => file_id.to_s}).first
            if record
              @connector[:file_permissions].filter({:file_id => file_id.to_s}).delete
            end
          end
          result = true
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:file_id => (file_id), :credential => (credential)}})
        end
        result
      end
      # ### DB Objects
      def effective_element_permission(table=:unspecified, dbid=0, credential=nil)
        result = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false}
        begin
          unless self.alive?
            raise Exception, "Database inactive"
          end
          unless self.open?
            raise Exception, "Database not available"
          end
          unless dbid.is_a?(::Integer)
            raise ArgumentError, "dbid must be specified with a Integer"
          end
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must specify a valid credential UUID (as a String or Symbol)"
          end
          if table.is_a?(::Integer)
            table = ::GxG::Database::Database::element_table_by_index(table)
          end
          # Review : change in permission policy
          # if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(table)
          if [:element_array, :element_hash].include?(table)
            # is credential a user or role?
            raw_permissions = []
            # Include PUBLIC credential
            credentials = ["00000000-0000-4000-0000-000000000000"]
            #
            if self.user_exist?(credential)
              credentials << credential
              role_list = self.user_roles(credential)
              role_list.each do |entry|
                credentials << entry[:credential]
              end
              #
            else
              if self.role_exist?(credential)
                credentials << credential
              else
                raise ArgumentError, "Invalid credential.  It is neither a user nor a role UUID"
              end
            end
            credentials.each do |entry|
              manifest = @connector[:permissions].filter({:credential => (entry.to_s), :element_table => (table.to_s), :elementid => (dbid)})
              manifest.each do |record|
                new_permission = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false}
                [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                  if record[(the_permission)] == 1
                    new_permission[(the_permission)] = true
                  end
                end
                raw_permissions << new_permission
              end
            end
            permission = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false}
            raw_permissions.each do |entry|
              [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
                if entry[(the_permission)]
                  permission[(the_permission)] = true
                end
              end
            end
            db_limits = self.db_permissions()
            [:execute, :rename, :move, :destroy, :create, :write, :read].each do |the_permission|
              if db_limits[(the_permission)] and permission[(the_permission)]
                result[(the_permission)] = true
              end
            end
            #
          else
            raise ArgumentError, "Invalid table specified"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid), :credential => (credential)}})
        end
        result
      end
      #
      def  effective_uuid_permission(uuid=nil, credential=nil)
        result = nil
        begin
          if self.alive?
            if self.open?
              address = nil
              record = @connector[:element_hash].filter({:uuid => (uuid.to_s)}).first
              if record
                address = {:database => self, :table => :element_hash, :dbid => (record[:dbid])}
              else
                record = @connector[:element_array].filter({:uuid => (uuid.to_s)}).first
                if record
                  address = {:database => self, :table => :element_array, :dbid => (record[:dbid])}
                end
              end
              if address
                result = self.effective_element_permission(address[:table], address[:dbid], credential)
              else
                # ### Review : Experimental Code - attempt to seemlessly integrate dbs of different roles into in-memory structures.
                already_checked = [(self)]
                ::GxG::DB[:roles].each_pair do |the_db_role, the_database|
                  unless already_checked.include?(the_database)
                    record = the_database.connector[:element_hash].filter({:uuid => (uuid.to_s)}).first
                    if record
                      address = {:database => the_database, :table => :element_hash, :dbid => (record[:dbid])}
                      result = the_database.effective_element_permission(address[:table], address[:dbid], credential)
                      break
                    else
                      record = the_database.connector[:element_array].filter({:uuid => (uuid.to_s)}).first
                      if record
                        address = {:database => the_database, :table => :element_array, :dbid => (record[:dbid])}
                        result = the_database.effective_element_permission(address[:table], address[:dbid], credential)
                        break
                      end
                    end
                    already_checked << the_database
                  end
                end
                # 
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:uuid => (uuid), :credential => (credential)}})
        end
        result
      end
      # ### Data Handling methods
      #
      def element_exists?(the_table=:unspecified, the_dbid=0)
        result = false
        if the_table.is_a?(::Integer)
          the_table = ::GxG::Database::Database::element_table_by_index(the_table)
        end
        if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(the_table)
          begin
            record = @connector[(the_table)].select(:dbid).where({:dbid => (the_dbid)}).first
            if record
              result = true
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:table => (the_table), :dbid => (the_dbid)}})
          end
        end
        result
      end
      #
      def element_retrieve(the_table=:unspecified, the_filter={}, options={})
        result = []
        begin
          if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :text_page, :element_binary,:binary_page, :element_array, :element_hash].include?(the_table)
            #
            if the_filter.is_a?(::Hash)
              if options[:order]
                raw_result = @connector[(the_table)].filter(the_filter).order(options[:order])
              else
                raw_result = @connector[(the_table)].filter(the_filter)
              end
              # Review : UTF-8 Encoding Error Fix
              if options[:single_record] == true
                result = raw_result.first
                # utf8 fix
                if the_table == :text_page
                  if result[:content].is_a?(::String)
                    if result[:content].base64?
                      result[:content] = result[:content].decode64
                    end
                  end
                end
                #
              else
                # utf8 fix
                raw_result.each do |the_record|
                  if the_record[:content].is_a?(::String)
                    if the_record[:content].base64?
                      the_record[:content] = the_record[:content].decode64
                    end
                  end
                  result << the_record
                end
                # result = raw_result
              end
              #
            else
              raise ArguementError, "You MUST provide a record selection filter as a Hash. "
            end
          else
            raise ArgumentError, "The table specified is unknown - Check your code."
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => the_table, :filter => the_filter, :options => options}})
        end
        result
      end
      #
      def element_create(the_table=:unspecified, the_record=nil)
        # Review : rewrite - in use
        result = nil
        begin
          unless the_table.is_a?(::Symbol)
            raise ArgumentError, "You MUST provide the table specifier as a Symbol."
          end
          unless the_record.is_a?(::Hash)
            raise ArgumentError, "You MUST provide a record in the form of a Hash."
          end
          if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :text_page, :element_binary, :binary_page, :element_array, :element_hash].include?(the_table)
            # Review : UTF8 fix
            begin
              result = @connector[(the_table)].insert(the_record)
            rescue Exception
              if the_table == :text_page
                the_record[:content] = the_record[:content].encode64
              end
              result = @connector[(the_table)].insert(the_record)
            end
          else
            raise ArgumentError, "The table specified is unknown - Check your code."
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (the_table), :record => (the_record)}})
        end
        result
      end
      #
      def element_update(the_table=:unspecified, the_filter={}, the_record=nil)
        result = false
        begin
          unless the_table.is_a?(::Symbol)
            raise ArgumentError, "You MUST provide the table specifier as a Symbol."
          end
          unless the_filter.is_a?(::Hash)
            raise ArgumentError, "You MUST provide a selection filter in the form of a Hash."
          end
          unless the_record.is_a?(::Hash)
            raise ArgumentError, "You MUST provide a record in the form of a Hash."
          end
          if [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :text_page, :element_binary, :binary_page, :element_array, :element_hash].include?(the_table)
            # Review : shim to eliminate UTF-8 encoding errors
            begin
              @connector[(the_table)].filter(the_filter).update(the_record)
            rescue Exception
              if the_table == :text_page
                the_record[:content] = the_record[:content].encode64
              end
              @connector[(the_table)].filter(the_filter).update(the_record)
            end
            result = true
          else
            raise ArgumentError, "The table specified is unknown - Check your code."
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => the_table, :filter => the_filter, :record => the_record}})
        end
        result
      end
      #
      def structure_detach(the_uuid=nil)
        if ::GxG::valid_uuid?(the_uuid)
          record = self.structural_link(the_uuid)
          if record
            record[:database].connector()[(record[:table])].filter({:dbid => record[:dbid]}).update({:element => "element_boolean", :element_boolean => -1, :element_hash_uuid => "", :element_array_uuid => ""})
            true
          else
            false
          end
        else
          false
        end
      end
      #
      def structural_link(the_uuid=nil)
        # Review : rewrite - in use
        result = nil
        if ::GxG::valid_uuid?(the_uuid)
          search_queue = [(self)]
          ::GxG::DB[:roles].each_pair do |the_role, the_database|
            unless search_queue.include?(the_database)
              search_queue << the_database
            end
          end
          search_queue.each do |the_database|
            found = the_database.connector()[:hash_properties].filter({:element_hash_uuid => the_uuid.to_s}).first
            if found
              result = {:database => the_database, :table => :hash_properties, :dbid => found[:dbid]}
              break
            end
            found = the_database.connector()[:hash_properties].filter({:element_array_uuid => the_uuid.to_s}).first
            if found
              result = {:database => the_database, :table => :hash_properties, :dbid => found[:dbid]}
              break
            end
            found = the_database.connector()[:array_elements].filter({:element_hash_uuid => the_uuid.to_s}).first
            if found
              result = {:database => the_database, :table => :hash_properties, :dbid => found[:dbid]}
              break
            end
            found = the_database.connector()[:array_elements].filter({:element_array_uuid => the_uuid.to_s}).first
            if found
              result = {:database => the_database, :table => :hash_properties, :dbid => found[:dbid]}
              break
            end
          end
        end
        result
      end
      #      
      def structure_attached?(the_uuid=nil)
        # Review : rewrite - in use
        result = false
        record = self.structural_link(the_uuid)
        if record
          result = true
        end
        result
      end
      #
      def element_in_use?(db_table=:unspecified, dbid = 0)
        # Review : rewrite - in use for now.
        # Review : rewrite - todo (alter to reflect the new architecture : perhaps limit to structures only)
        unless db_table.is_any?(::Integer, ::Symbol)
          raise ArgumentError, "Table needs to be specified as a Symbol, or a table code Integer"
        end
        unless dbid.is_a?(::Integer)
          raise ArgumentError, "Record ID needs to be specified with an Integer"
        end
        result = false
        begin
          if db_table == :element_hash || db_table == :element_array
            # Review : make more efficient in later revs of this.
            the_record = @connector[(db_table)].filter({:dbid => (dbid)}).select(:uuid).first
            if the_record
              if @connector[:hash_properties].filter({:element_hash_uuid => the_record[:uuid]}).count > 0 || @connector[:array_elements].filter({:element_array_uuid => the_record[:uuid]}).count > 0
                result = true
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table_code => (db_table), :dbid => (dbid)}})
        end
        result
      end
      #
      def element_parent_address(the_table=:unspecified, the_dbid=0)
        result = nil
        if self.element_in_use?(the_table,the_dbid)
          begin
            link = @connector[:hash_links].select(:parent_uuid).where({:element => (::GxG::Database::Database::element_table_index(the_table)), :elementid => (the_dbid)}).first
            if link
              record = @connector[:element_hash].select(:dbid).where({:uuid => link[:parent_uuid]}).first
              if record
                result = {:table => :element_hash, :dbid => (record[:dbid])}
              end
            else
              link = @connector[:array_links].select(:parent_uuid).where({:element => (::GxG::Database::Database::element_table_index(the_table)), :elementid => (the_dbid)}).first
              if link
                record = @connector[:element_array].select(:dbid).where({:uuid => link[:parent_uuid]}).first
                if record
                  result = {:table => :element_array, :dbid => (record[:dbid])}
                end
              end
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:table => (the_table), :dbid => (the_dbid)}})
          end
        end
        result
      end
      #
      def element_manifest(the_table=:unspecified, the_dbid=0, everything=false)
        # Review : rewrite - in use
        # returns an Array of tables and dbid pairs and sub-item pairs if they exist
        result = []
        #
        begin
          unless the_dbid > 0
            raise ArgumentError, "dbid specified must be greater than zero"
          end
          case the_table
          when :element_text
            the_record = @connector[:element_text].select(:uuid, :dbid).where({:dbid => (the_dbid)}).first
            if the_record
              result << {:table => :element_text, :dbid => the_record[:dbid]}
              if everything
                the_pages = @connector[:text_page].select(:dbid, :ordinal).where({:parent_uuid => (the_record[:uuid])}).order(:ordinal)
                the_pages.each do |entry|
                  result << {:table => :text_page, :dbid => entry[:dbid]}
                end
              end
            end
          when :element_binary
            the_record = @connector[:element_binary].select(:uuid, :dbid).where({:dbid => (the_dbid)}).first
            if the_record
              result << {:table => :element_binary, :dbid => the_record[:dbid]}
              if everything
                the_pages = @connector[:binary_page].select(:dbid, :ordinal).where({:parent_uuid => (the_record[:uuid])}).order(:ordinal)
                the_pages.each do |entry|
                  result << {:table => :binary_page, :dbid => entry[:dbid]}
                end
              end
            end
          when :element_array, :element_hash
            record_db = [{:table => the_table, :dbid => the_dbid}]
            while record_db.size > 0 do
              item = record_db.shift
              case item[:table]
              when :element_text
                the_record = @connector[:element_text].select(:uuid, :dbid).where({:dbid => item[:dbid]}).first
                if the_record
                  result << {:table => :element_text, :dbid => the_record[:dbid]}
                  if everything
                    the_pages = @connector[:text_page].select(:dbid, :ordinal).where({:parent_uuid => (the_record[:uuid])}).order(:ordinal)
                    the_pages.each do |entry|
                      result << {:table => :text_page, :dbid => entry[:dbid]}
                    end
                  end
                end
              when :element_binary
                the_record = @connector[:element_binary].select(:uuid, :dbid).where({:dbid => item[:dbid]}).first
                if the_record
                  result << {:table => :element_binary, :dbid => the_record[:dbid]}
                  if everything
                    the_pages = @connector[:binary_page].select(:dbid, :ordinal).where({:parent_uuid => (the_record[:uuid])}).order(:ordinal)
                    the_pages.each do |entry|
                      result << {:table => :binary_page, :dbid => entry[:dbid]}
                    end
                  end
                end
              when :element_array
                result << {:table => item[:table], :dbid => item[:dbid]}
                array_record = @connector[:element_array].select(:uuid).where({:dbid => item[:dbid]}).first
                if array_record
                  @connector[:array_elements].filter({:parent_uuid => (array_record[:uuid])}).order(:ordinal).each do |entry|
                    if entry[:element_text_uuid].size > 0
                      the_temp_record = @connector[:element_text].select(:dbid).where({:uuid => entry[:element_text_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_text, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    if entry[:element_binary_uuid].size > 0
                      the_temp_record = @connector[:element_binary].select(:dbid).where({:uuid => entry[:element_binary_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_binary, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    if entry[:element_array_uuid].size > 0
                      the_temp_record = @connector[:element_array].select(:dbid).where({:uuid => entry[:element_array_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_array, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    if entry[:element_hash_uuid].size > 0
                      the_temp_record = @connector[:element_hash].select(:dbid).where({:uuid => entry[:element_hash_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_hash, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    result << {:table => :array_elements, :dbid => entry[:dbid]}
                  end
                end
              when :element_hash
                result << {:table => item[:table], :dbid => item[:dbid]}
                hash_record = @connector[:element_hash].select(:uuid).where({:dbid => item[:dbid]}).first
                if hash_record
                  @connector[:hash_properties].filter({:parent_uuid => (hash_record[:uuid])}).order(:ordinal).each do |entry|
                    if entry[:element_text_uuid].size > 0
                      the_temp_record = @connector[:element_text].select(:dbid).where({:uuid => entry[:element_text_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_text, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    if entry[:element_binary_uuid].size > 0
                      the_temp_record = @connector[:element_binary].select(:dbid).where({:uuid => entry[:element_binary_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_binary, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    if entry[:element_array_uuid].size > 0
                      the_temp_record = @connector[:element_array].select(:dbid).where({:uuid => entry[:element_array_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_array, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    if entry[:element_hash_uuid].size > 0
                      the_temp_record = @connector[:element_hash].select(:dbid).where({:uuid => entry[:element_hash_uuid]}).first
                      if the_temp_record
                        record_db << {:table => :element_hash, :dbid => the_temp_record[:dbid]}
                      end
                    end
                    result << {:table => :hash_properties, :dbid => entry[:dbid]}
                  end
                end
              else
                the_record = @connector[(item[:table])].select(:dbid).where({:dbid => (item[:dbid])}).first
                if the_record
                  result << {:table => item[:table], :dbid => item[:dbid]}
                end
              end
            end
            #
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (the_table), :dbid => (the_dbid)}})
        end
        result
      end
      #
      def element_destroy(credential=nil,table=:unspecified,dbid=0, options={})
        # Review : rewrite for new arch.
        # Review : rewrite - in use
        result = false
        begin
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                # if credential has :destroy permission on this element?
                if ::GxG::valid_uuid?(credential)
                  if [:persisted_array, :persisted_hash].include?(table.to_s.to_sym)
                    go_ahead = self.effective_element_permission(table, dbid, credential)[:destroy]
                  else
                    go_ahead = true
                  end
                  # xxx Quick fix : BETA: clean all this up!
                  if go_ahead
                    # Review : DB overhaul / rewrite - allow delete if object has write lock in place? I think not. (return false)
                    # Note: BETA - bring back read-locks? it was 9x slower with them ... not sure.
                    elements = self.element_manifest(table, dbid, false)
                    elements.each do |entry|
                      #
                      unless self.element_in_trash?(entry[:table], entry[:dbid])
                        @connector[:trash].insert({:element_table => entry[:table].to_s, :elementid => entry[:dbid]})
                      end
                      #
                      #if @connector[:element_locks].filter({:type => "read", :element_table => entry[:table].to_s, :elementid => entry[:dbid]}).count > 0
                        # put in trash
                        #unless self.element_in_trash?(entry[:table], entry[:dbid])
                          #@connector[:trash].insert({:element_table => entry[:table].to_s, :elementid => entry[:dbid]})
                        #end
                      #else
                        # delete now
                        #manifest = self.element_manifest(entry[:table], entry[:dbid], true)
                        #manifest.each do |item|
                          #@connector[:permissions].filter({:element_table => (item[:table].to_s), :elementid => (item[:dbid])}).delete
                          #@connector[(item[:table])].filter({:dbid => item[:dbid]}).delete
                        #end
                      #end
                    end
                    result = true
                  else
                    raise Exception, "You do not have permission to destory this element"
                  end
                else
                  raise ArgumentError, "You must supply a valid credential UUID (as a String or Symbol)"
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:credential => (credential), :table => (table), :dbid => (dbid)}})
        end
        result
      end
      #
      def destroy_by_uuid(credential=nil, the_uuid=nil)
        # Review : rewrite - in use
        # element_destroy(credential=nil,table=:unspecified,dbid=0, options={})
        # .effective_uuid_permission(data["location"].to_s.to_sym,@credential)
        result = false
        begin
          if self.alive?
            if self.open?
              if self.db_permissions()[:destroy] == true
                if ::GxG::valid_uuid?(credential)
                  found = @connector[:element_hash].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
                  if found
                    self.element_destroy(credential, :element_hash,(found[:dbid]))
                    result = true
                  else
                    found = @connector[:element_array].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
                    if found
                      self.element_destroy(credential, :element_array,(found[:dbid]))
                      result = true
                    end
                  end
                else
                  raise ArgumentError, "You must supply a valid credential UUID (as a String or Symbol)"
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:credential => (credential), :uuid => (the_uuid)}})
        end
        result
      end
      #
      def element_byte_size(table=:unspecified, dbid=0)
        #
        result = 0
        begin
          if self.alive?
            if self.open?
              migration = self.db_migration()
              elements = self.element_manifest(table, dbid, true)
              elements.each do |entry|
                table_definition = migration[(entry[:table])]
                if table_definition
                  table_definition.keys.each do |the_field|
                    result += table_definition[(the_field)][:bytes].to_i
                  end
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid)}})
        end
        result
      end
      #
      def byte_size_by_uuid(the_uuid=nil)
        result = 0
        begin
          if self.alive?
            if self.open?
              found = @connector[:element_hash].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
              if found
                result += self.element_byte_size(:element_hash,(found[:dbid]))
              else
                found = @connector[:element_array].select(:dbid, :uuid).filter({:uuid => the_uuid.to_s}).first
                if found
                  result += self.element_byte_size(:element_array,(found[:dbid]))
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:uuid => (the_uuid)}})
        end
        result
      end
      #
      def persistable?(the_object)
        result = true
        unless the_object.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
          if the_object.is_any?(::Hash, ::Array)
            the_object.search do |item, selector, container|
              if result
                if ::GxG::Database::Database::element_table_for_instance(item) == :unspecified
                  result = false
                  break
                end
              end
              nil
            end
          else
            if ::GxG::Database::Database::element_table_for_instance(the_object) == :unspecified
              result = false
            end
          end
        end
        result
      end
      #
      def iterative_persist(old_root=nil, credential=nil, options={})
        # New PersistedArray, or PersistedHash interface:
        # mount element: {:database => <database>, :uuid => <uuid>, :credential => <uuid>, :delegate => nil/<uuid>, :parent => nil/<an-object>}
        # create element: {:database => <database>, :credential => <uuid>, :delegate => nil/<uuid>, :parent => nil/<an-object>}
        # 
        result = nil
        begin
          # db open?
          # write permissions on db?
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You MUST provide a valid UUID as a credential."
          end
          unless old_root.is_any?(::Array, ::Hash)
            raise ArgumentError, "You MUST provide either an Array or a Hash."
          end
          unless self.persistable?(old_root)
            raise ArgumentError, "The object you are attempting to persist contains a non-persistable item."
          end
          if old_root.is_a?(::Array)
            original_partner = ::GxG::Database::PersistedArray.new({:database => self, :credential => credential}, options)
            original_partner.get_reservation()
            self.enforce_permission_policy({:action => :extend, :credential => credential, :source => original_partner, :destination => original_partner})
            #
          end
          if old_root.is_a?(::Hash)
            original_partner = ::GxG::Database::PersistedHash.new({:database => self, :credential => credential}, options)
            original_partner.get_reservation()
            self.enforce_permission_policy({:action => :extend, :credential => credential, :source => original_partner, :destination => original_partner})
          end
          if old_root.is_any?(::GxG::Database::PersistedArray, ::GxG::Database::PersistedHash)
            # TODO: support subsuming already persisted objects.
          end
          paring_data = [{:parent => nil, :parent_selector => nil, :object => old_root, :partner => original_partner}]
          children_of = Proc.new do |the_parent=nil|
            list = []
            paring_data.each do |node|
              if node[:parent].object_id == the_parent.object_id
                list << node
              end
            end
            list
          end
          #
          parent_of = Proc.new do |the_parent=nil|
            output = nil
            paring_data.each do |entry|
              if entry[:object].object_id == the_parent.object_id
                output = entry
              end
            end
            output
          end
          find_partner = Proc.new do |the_object|
            found_partner = nil
            paring_data.each do |the_record|
              if the_record.is_a?(::Hash)
                if the_record[:object].object_id == the_object.object_id
                  found_partner = the_record[:partner]
                  break
                end
              end
            end
            found_partner
          end
          # build paring data:
          delegate_permission = nil
          old_root.search do |the_value, the_selector, the_container|
            if the_value.is_a?(::Array)
              paring_data << {:parent => the_container, :parent_selector => the_selector, :object => the_value, :partner => ::GxG::Database::PersistedArray.new({:database => self, :credential => credential})}
            else
              if the_value.is_a?(::Hash)
                paring_data << {:parent => the_container, :parent_selector => the_selector, :object => the_value, :partner => ::GxG::Database::PersistedHash.new({:database => self, :credential => credential})}
              else
                paring_data << {:parent => the_container, :parent_selector => the_selector, :object => the_value, :partner => the_value}
              end
            end
          end
          # Assign objects to structure in order by parent / parent_selector
          link_db = [(paring_data[0])]
          while link_db.size > 0
            entry = link_db.shift
            if entry.is_a?(::Hash)
              if entry[:object].is_any?(::Array, ::Hash)
                # get children and assign
                children = children_of.call(entry[:object])
                children.each do |child|
                  entry[:partner][(child[:parent_selector])] = child[:partner]
                  if child[:partner].is_any?(::GxG::Database::PersistedArray, ::GxG::Database::PersistedHash)
                    link_db << child
                  end
                end
              end
            end
          end
          result = original_partner
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:object => old_root, :credential => credential}})
        end
        result
      end
      #
      def try_persist(the_object=nil, credential=nil, options={})
        result = nil
        if the_object.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
          result = the_object
        else
          begin
            unless ::GxG::valid_uuid?(credential)
              raise ArgumentError, "You must supply a credential (36 character limit) as a String or Symbol"
            end
            unless options.is_a?(::Hash)
              raise ArgumentError, "You must supply persisting options as a Hash"
            end
            table = ::GxG::Database::Database::element_table_for_instance(the_object)
            if table == :unspecified
              raise ArgumentError, "You provided an object that cannot be persisted."
            end
            if [:element_hash, :element_array].include?(table)
              result = self.iterative_persist(the_object, credential, options)
            else
              result = the_object
            end
          rescue Exception => the_error
            log_error({:error => the_error, :parameters => {:object => the_object, :credential => credential, :options => options}})
          end
        end
        result
      end
      #
      def retrieve_by_address(the_address={}, credential=nil, delegate=nil)
        result = nil
        begin
          unless ::GxG::valid_uuid?(credential)
            raise ArgumentError, "You must supply a valid credential UUID (as a String or Symbol)"
          end
          if self.alive?
            if self.open?
              address = {}
              if the_address[:database]
                unless the_address[:database] == self
                  raise ArgumentError, "Database mismatch.  Call this method on database #{the_address[:database].inspect}"
                end
                address[:database] = the_address[:database]
              else
                address[:database] = self
              end
              unless ((the_address[:table]) and (the_address[:dbid].is_a?(::Integer)))
                raise ArgumentError, "Invalid database address: #{the_address.inspect}"
              end
              if the_address[:table].is_a?(::Integer)
                address[:table] = ::GxG::Database::Database::element_table_by_index(the_address[:table])
              else
                address[:table] = the_address[:table]
              end
              address[:dbid] = the_address[:dbid]
              unless self.element_in_trash?(address[:table], address[:dbid])
                if [:persisted_array, :persisted_hash].include?(address[:table])
                  the_permission = address[:database].effective_element_permission(address[:table], address[:dbid], credential)
                else
                  the_permission = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => true}
                end
                # Review ????
                # puts "Effective Permission: #{the_permission.inspect} for #{address[:table].inspect},#{address[:dbid].inspect}"
                if the_permission[:read] == true
                  case address[:table]
                  when :element_array
                    record = address[:database].connector()[(address[:table].to_s.to_sym)].select(:uuid).where({:dbid => (address[:dbid])}).first
                    if record
                      result = ::GxG::Database::PersistedArray.new({:database => (address[:database]), :uuid => (record[:uuid].to_sym), :credential => (credential), :delegate => (delegate)})
                    else
                      raise Exception, "Unable to retrieve PersistedArray"
                    end
                  when :element_hash
                    record = address[:database].connector()[:element_hash].select(:uuid, :format).where({:dbid => (address[:dbid])}).first
                    if record
                      result = ::GxG::Database::PersistedHash.new({:database => (address[:database]), :uuid => (record[:uuid].to_sym), :credential => (credential), :delegate => (delegate)})
                      if result
                        if record[:format].to_s.size > 0
                          result.set_format(record[:format].to_sym)
                        end
                      end
                    else
                      raise Exception, "Unable to retrieve PersistedHash"
                    end
                  else
                    raise Exception, "Invalid table specifier: #{address[:table].inspect}"
                  end
                else
                  # At this point the idea is that if you don't have permissions to read it, you never see it
                  # raise Exception, "You don't have permission to retrieve this element"
                end
                #
              end
              #
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:address => (the_address), :credential => (credential), :delegate => (delegate)}})
        end
        result
      end
      #
      def retrieve_by_uuid(uuid=nil, credential=nil, delegate=nil)
        result = nil
        begin
          if self.alive?
            if self.open?
              address = nil
              record = @connector[:element_hash].filter({:uuid => (uuid.to_s)}).first
              if record
                address = {:database => self, :table => :element_hash, :dbid => (record[:dbid])}
              else
                record = @connector[:element_array].filter({:uuid => (uuid.to_s)}).first
                if record
                  address = {:database => self, :table => :element_array, :dbid => (record[:dbid])}
                end
              end
              if address
                result = self.retrieve_by_address(address, credential, delegate)
              else
                # ### Review : Experimental Code - attempt to seemlessly integrate dbs of different roles into in-memory structures.
                already_checked = [(self)]
                ::GxG::DB[:roles].each_pair do |the_db_role, the_database|
                  unless already_checked.include?(the_database)
                    record = the_database.connector[:element_hash].filter({:uuid => (uuid.to_s)}).first
                    if record
                      address = {:database => the_database, :table => :element_hash, :dbid => (record[:dbid])}
                      result = the_database.retrieve_by_address(address, credential, delegate)
                      break
                    else
                      record = the_database.connector[:element_array].filter({:uuid => (uuid.to_s)}).first
                      if record
                        address = {:database => the_database, :table => :element_array, :dbid => (record[:dbid])}
                        result = the_database.retrieve_by_address(address, credential, delegate)
                        break
                      end
                    end
                    already_checked << the_database
                  end
                end
                # 
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:uuid => (uuid), :credential => (credential), :delegate => (delegate)}})
        end
        result
      end
      # Element Write-Lock Handling methods
      def reserve_element_locks(credential=nil, manifest=[], type=:read)
        result = nil
        begin
          if self.alive?
            if self.open?
              unless ::GxG::valid_uuid?(credential)
                raise ArgumentError, "You must supply a valid credential UUID to reserve locks"
              end
              unless manifest.is_a?(::Array)
                raise ArguementError, "You must supply an Array of tables and record ids to reserve for writing"
              end
              unless [:write, :read].include?(type)
                raise ArgumentError, "You must specify a type of reservation: either :write or :read are supported"
              end
              if manifest.size > 0
                reservation_uuid = ::GxG::uuid_generate()
                while @connector[:element_locks].filter({:reservation => (reservation_uuid.to_s)}).count > 0
                  reservation_uuid = ::GxG::uuid_generate()
                end
                if type == :write
                  if self.db_permissions()[:write]
                    # Write-lock must be unique to the elements
                    manifest.each do |entry|
                      if @connector[:element_locks].filter({:type => (type.to_s), :element_table => entry[:table].to_s, :elementid => entry[:dbid]}).count > 0
                        self.release_element_locks(reservation_uuid)
                        # raise Exception, "A reservation already exists for element #{entry[:table]}:#{entry[:dbid]}"
                        # Note - just silently fail and return Nil - no reservation for you.
                        break
                      else
                        @connector[:element_locks].insert({:type => (type.to_s), :reservation => reservation_uuid.to_s, :credential => credential.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]})
                      end
                    end
                    # if write-reservation was made
                    if @connector[:element_locks].filter({:reservation => reservation_uuid.to_s}).count > 0
                      result = reservation_uuid.to_sym
                    end
                  end
                else
                  # Read-lock reservation - can share elements
                  if self.db_permissions()[:write]
                    manifest.each do |entry|
                      @connector[:element_locks].insert({:type => (type.to_s), :reservation => reservation_uuid.to_s, :credential => credential.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]})
                      #
                    end
                  end
                  # Note - on a read-only db it will act as though it has a read-reservation since no deletions can be made.
                  result = reservation_uuid.to_sym
                end
              end
              #
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:credential => (credential), :manifest => (manifest), :type => (type)}})
        end
        result
      end
      #
      def release_element_locks(reservation_uuid=nil)
        result = false
        begin
          if self.alive?
            if self.open?
              unless ::GxG::valid_uuid?(reservation_uuid)
                raise ArgumentError, "You must supply a valid reservation UUID (as a String or Symbol) to release locks"
              end
              if self.db_permissions()[:write]
                @connector[:element_locks].filter({:reservation => reservation_uuid.to_s}).delete
              end
              # on read-only db, no reservation was made so mission accomplished
              result = true
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:reservation => (reservation_uuid)}})
        end
        result
      end
      #
      def reservation_add_element(reservation_uuid=nil, table=:unspecified, dbid=0)
        result = false
        #
        begin
          if self.alive?
            if self.open?
              unless ::GxG::valid_uuid?(reservation_uuid)
                raise ArgumentError, "You must supply a valid reservation UUID (as a String or Symbol) to add an element to the reserve locks"
              end
              record = @connector[:element_locks].select(:type, :reservation, :credential).where({:reservation => reservation_uuid.to_s}).first
              if record
                type = record[:type].to_sym
                credential = record[:credential].to_sym
                manifest = self.element_manifest(table, dbid, false)
                if type == :write
                  if self.db_permissions()[:write]
                    #
                    manifest.each do |entry|
                      if @connector[:element_locks].filter({:type => (type.to_s), :reservation => reservation_uuid.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]}).count == 0
                        @connector[:element_locks].insert({:type => (type.to_s), :reservation => reservation_uuid.to_s, :credential => credential.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]})
                      end
                    end
                    result = true
                  end
                else
                  # read
                  if self.db_permissions()[:write]
                    #
                    manifest.each do |entry|
                      @connector[:element_locks].insert({:type => (type.to_s), :reservation => reservation_uuid.to_s, :credential => credential.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]})
                    end
                    result = true
                  end
                end
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:reservation => (reservation_uuid)}})
        end
        #
        result
      end
      #
      def reservation_remove_element(reservation_uuid=nil, table=:unspecified, dbid=0)
        result = false
        #
        begin
          if self.alive?
            if self.open?
              unless ::GxG::valid_uuid?(reservation_uuid)
                raise ArgumentError, "You must supply a valid reservation UUID (as a String or Symbol) to remove element from reserve locks"
              end
              record = @connector[:element_locks].select(:reservation).where({:reservation => reservation_uuid.to_s}).first
              if record
                manifest = self.element_manifest(table, dbid, false)
                if self.db_permissions()[:write]
                  #
                  manifest.each do |entry|
                    if @connector[:element_locks].filter({:reservation => reservation_uuid.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]}).count > 0
                      @connector[:element_locks].filter({:reservation => reservation_uuid.to_s, :element_table => entry[:table].to_s, :elementid => entry[:dbid]}).delete
                    end
                  end
                  result = true
                end
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Database not available (defunct)"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:reservation => (reservation_uuid)}})
        end
        #
        result
      end
      #
      def empty_trash()
        result = false
        begin
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                scrub_list = []
                @connector[:trash].filter({}).each do |entry|
                  the_table = entry[:element_table].to_sym
                  the_dbid = entry[:elementid]
                  if @connector[:element_locks].filter({:type => "write", :element_table => the_table.to_s, :elementid => the_dbid}).count == 0
                    # delete full manifest
                    manifest = self.element_manifest(the_table, the_dbid, true)
                    manifest.each do |item|
                      @connector[:permissions].filter({:element_table => (item[:table].to_s), :elementid => (item[:dbid])}).delete
                      @connector[(item[:table])].filter({:dbid => item[:dbid]}).delete
                    end
                    scrub_list << entry[:dbid]
                  end
                end
                scrub_list.each do |entry|
                  @connector[:trash].filter({:dbid => entry}).delete
                end
                if @connector[:trash].filter({}).count == 0
                  result = true
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error})
        end
        result
      end
      #
      def element_in_trash?(table=:unspecified, dbid=0)
        result = false
        begin
          if self.alive?
            if self.open?
              if @connector[:trash].filter({:element_table => table.to_s, :elementid => dbid}).count > 0
                result = true
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid)}})
        end
        result
      end
      #
      def element_recover(table=:unspecified, dbid=0)
        # recover an element from the trash
        result = false
        begin
          if self.alive?
            if self.open?
              if self.db_permissions()[:write]
                unless [:element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime, :element_text, :element_binary, :element_array, :element_hash].include?(table)
                  raise ArgumentError, "Invalid table specified"
                end
                unless dbid > 0
                  raise ArgumentError, "dbid must be greater than zero"
                end
                if self.element_in_trash?(table, dbid)
                  scrub_list = []
                  manifest = self.element_manifest(table, dbid)
                  manifest.each do |entry|
                    if @connector[:trash].filter({:element_table => (entry[:table].to_s), :elementid => (entry[:dbid])}).count > 0
                      record = @connector[:trash].select(:dbid).where({:element_table => (entry[:table].to_s), :elementid => (entry[:dbid])}).first
                      if record
                        scrub_list << record[:dbid]
                      end
                    end
                  end
                  scrub_list.each do |entry|
                    @connector[:trash].filter({:dbid => entry}).delete
                  end
                  result = true
                else
                  # it was never in the trash, so mission accomplished
                  result = true
                end
              end
            end
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:table => (table), :dbid => (dbid)}})
        end
        result
      end
      # ### Format handing methods
      def format_template(type=:structure)
        result = nil
        begin
          if self.alive?
            if self.open?
              unless type.is_any?(::String, ::Symbol)
                raise ArgumentError, "You must supply a type as a String or Symbol:  :structure or :binary"
              end
              the_uuid = ::GxG::uuid_generate()
              while (@connector[:formats].filter({:uuid => (the_uuid)}).count > 0 or @connector[:element_text].filter({:uuid => (the_uuid)}).count > 0)
                the_uuid = ::GxG::uuid_generate()
              end
              result = {:uuid => (the_uuid.to_sym), :type => (type.to_s), :ufs => "unspecified", :title => "", :version => BigDecimal(0.0), :mime_types => [], :content => nil}
              case type
              when :structure
                result[:content] = {}
              when :binary
                result[:content] = {:sample_size => 0, :recognition => "", :import => "", :export => ""}
              else
                raise Exception, "Invalid format type specified: #{type.inspect}.  Use :structure or :binary"
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          result = nil
          log_error({:error => the_error, :parameters => {:type => (type)}})
        end
        result
      end
      #
      def format_list(search_options={})
        result = []
        begin
          if self.alive?
            if self.open?
              unless search_options.is_a?(::Hash)
                raise ArgumentError, "You must specify search options as a Hash"
              end
              the_filter = {}
              if search_options[:uuid]
                the_filter[:uuid] = search_options[:uuid].to_s
              end
              if search_options[:type]
                the_filter[:type] = search_options[:type].to_s
              end
              if search_options[:ufs]
                the_filter[:ufs] = search_options[:ufs].to_s[0..4096]
              end
              if search_options[:title]
                the_filter[:title] = search_options[:title].to_s[0..256]
              end
              if search_options[:version].is_a?(::Numeric)
                the_filter[:version] = ::BigDecimal.new(search_options[:version].to_s)
              end
              mime_type = search_options[:mime_type].to_s
              if mime_type.size > 0
                @connector[:formats].filter(the_filter).where(::Sequel.like(:mime_types, ("%" + mime_type + "%"))).order(::Sequel[:version].desc).each do |entry|
                  result << {:uuid => entry[:uuid].to_sym, :type => entry[:type].to_sym, :ufs => entry[:ufs].to_sym, :title => entry[:title], :version => entry[:version]}
                end
              else
                @connector[:formats].filter(the_filter).order(::Sequel[:version].desc).each do |entry|
                  result << {:uuid => entry[:uuid].to_sym, :type => entry[:type].to_sym, :ufs => entry[:ufs].to_sym, :title => entry[:title], :version => entry[:version]}
                end
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:search_options => (search_options)}})
        end
        result
      end
      #
      def format_load(search_options={})
        result = nil
        begin
          if self.alive?()
            if self.open?
              format_stub = self.format_list(search_options).first
              if format_stub
                format_record = @connector[:formats].filter({:uuid => (format_stub[:uuid].to_s)}).first
                if format_record
                  content = ""
                  @connector[:text_page].filter({:parent_uuid => (format_stub[:uuid].to_s)}).order(:ordinal).each do |entry|
                    content << entry[:content]
                  end
                  format_record.delete(:dbid)
                  format_record[:ufs] = format_stub[:ufs]
                  format_record[:type] = format_stub[:type]
                  if content.size > 0
                    if content.base64?
                      content = content.decode64
                    end
                    if content.json?
                      content = ::JSON::parse(content.to_s, {:symbolize_names => true})
                    end
                    if content[:type]
                      content = ::Hash.gxg_import(content)
                    end
                    format_record[:content] = content
                  else
                    format_record[:content] = nil
                  end
                  #
                  if format_record[:mime_types].size > 0
                    if format_record[:mime_types].include?(",")
                      format_record[:mime_types] = format_record[:mime_types].split(",")
                    else
                      format_record[:mime_types] = [(format_record[:mime_types])]
                    end
                  end
                  #
                  result = format_record
                end
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:search_options => (search_options)}})
        end
        result
      end
      #
      def new_structure_from_format(credential=nil, search_options={})
        result = nil
        begin
          if self.alive?()
            if self.open?
              unless ::GxG::valid_uuid?(credential)
                raise ArgumentError, "You must supply a valid credential UUID (as a String or Symbol)"
              end
              format = self.format_load(search_options)
              if format
                # TODO: add support for :binary formats.
                unless format[:type] == :structure
                  raise Exception, "Only formats of type :structure are supported"
                end
                result = self.try_persist(format[:content], credential)
                if result.is_a?(::GxG::Database::PersistedHash)
                  result.set_format(format[:uuid].to_sym)
                  @connector[:element_hash].filter({:uuid => result.uuid.to_s}).update({:format => format[:uuid].to_s})
                end
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:search_options => (search_options)}})
        end
        result
      end
      #
      def format_create(format_record=nil)
        result = false
        begin
          if self.alive?()
            if self.open?
              unless self.db_permissions()[:write]
                raise Exception, "Unable to write to database"
              end
              if format_record.is_a?(::Hash)
                unless ::GxG::valid_uuid?(format_record[:uuid])
                  raise Exception, "Invalid UUID passed for the format"
                end
                unless format_record[:type].is_any?([::String, ::Symbol])
                  raise Exception, "You must pass the format_record[:type] as a String or Symbol"
                end
                unless format_record[:ufs].is_any?([::String, ::Symbol])
                  raise Exception, "You must pass the format_record[:ufs] as a String or Symbol"
                end
                unless format_record[:title].is_a?(::String)
                  raise Exception, "You must pass the format_record[:title] as a String"
                end
                unless format_record[:version].is_a?(::Numeric)
                  raise Exception, "You must pass the format_record[:version] as a Numeric"
                end
                unless format_record[:mime_types].is_any?(::String, ::Array)
                  raise Exception, "You must pass the format_record[:mime_types] as a String"
                end
                unless format_record[:content].is_a?(::Hash)
                  raise Exception, "You must pass the format_record[:content] as a Hash"
                end
                unless self.persistable?(format_record[:content])
                  raise Exception, "You must pass the format_record[:content] as a Hash of persistable elements"
                end
                if (@connector[:settings].filter({:uuid => format_record[:uuid].to_s}).count == 0 and @connector[:formats].filter({:uuid => format_record[:uuid].to_s}).count == 0 and @connector[:element_text].filter({:uuid => format_record[:uuid].to_s}).count == 0)
                  new_record = {:uuid => (format_record[:uuid].to_s)}
                  new_record[:type] = format_record[:type].to_s
                  new_record[:ufs] = format_record[:ufs].to_s
                  new_record[:title] = format_record[:title].to_s[0..256]
                  new_record[:version] = ::BigDecimal.new(format_record[:version].to_s)
                  if format_record[:mime_types].is_a?(::Array)
                    the_mimes = format_record[:mime_types].join(",").to_s[0..4096]
                  else
                    the_mimes = format_record[:mime_types].to_s[0..4096]
                  end
                  new_record[:mime_types] = the_mimes
                  content = format_record[:content].gxg_export.to_json.encode64
                  new_dbid = @connector[:formats].insert(new_record)
                  if content.size > 0
                    ::GxG::apportioned_ranges(content.size, 4096).each_with_index do |portion, ordinal|
                      @connector[:text_page].insert({:parent_uuid => (new_record[:uuid].to_s), :ordinal => (ordinal), :length => (content[(portion)].size), :content => (content[(portion)])})
                    end
                  end
                  if new_dbid
                    result = true
                  end
                  #
                  if result == true && ::GxG::DB[:roles][:formats] == self
                    already = [(self)]
                    GxG::DB[:roles].values.each do |the_db|
                        unless already.include?(the_db)
                            the_db.format_create(format_record)
                            already << the_db
                        end
                    end
                  end
                  #
                else
                  raise Exception, "That format UUID is already in use, please generate another"
                end
                #
              else
                raise ArgumentError, "You must supply a valid format record as a Hash"
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:format_record => (format_record)}})
        end
        result
      end
      #
      def format_update(format_record=nil)
        format_record = format_record.clone
        result = false
        begin
          if self.alive?()
            if self.open?
              unless self.db_permissions()[:write]
                raise Exception, "Unable to write to database"
              end
              if format_record.is_a?(::Hash)
                unless ::GxG::valid_uuid?(format_record[:uuid])
                  raise Exception, "Invalid UUID passed for the format"
                end
                record = @connector[:formats].filter({:uuid => format_record[:uuid].to_s}).first
                if record
                  format_update = {}
                  record.keys.each do |the_key|
                    if [:type, :ufs, :title, :version, :mime_types].include?(the_key)
                      case the_key
                      when :type
                        unless format_record[:type].is_any?(::String, ::Symbol)
                          raise Exception, "You must pass the format_record[:type] as a String or Symbol"
                        end
                      when :ufs
                        unless format_record[:ufs].is_any?(::String, ::Symbol)
                          raise Exception, "You must pass the format_record[:ufs] as a String or Symbol"
                        end
                      when :title
                        unless format_record[:title].is_a?(::String)
                          raise Exception, "You must pass the format_record[:title] as a String"
                        end
                      when :version
                        unless format_record[:version].is_a?(::Numeric)
                          raise Exception, "You must pass the format_record[:version] as a Numeric"
                        end
                      when :mime_types
                        unless format_record[:mime_types].is_any?(::String, ::Array)
                          raise Exception, "You must pass the format_record[:mime_types] as a String"
                        end
                      end
                      #
                      if the_key == :mime_types
                        if format_record[:mime_types].is_a?(::Array)
                          the_mimes = format_record[:mime_types].join(",").to_s[0..4096]
                        else
                          the_mimes = format_record[:mime_types].to_s[0..4096]
                        end
                        format_record[:mime_types] = the_mimes
                      end
                      #
                      if format_record[(the_key)] != record[(the_key)]
                        format_update[(the_key)] = format_record[(the_key)]
                      end
                    end
                  end                  
                  if format_update.keys.size > 0
                    # FIXME: :type and :ufs are being passed as a Symbols, but DB requires them to be a strings:
                    if format_update[:type].is_a?(::Symbol)
                      format_update[:type] = format_update[:type].to_s
                    end
                    if format_update[:ufs].is_a?(::Symbol)
                      format_update[:ufs] = format_update[:ufs].to_s
                    end
                    @connector[:formats].filter({:uuid => format_record[:uuid].to_s}).update(format_update)
                  end
                  if format_record[:content].is_a?(::Hash)
                    unless self.persistable?(format_record[:content])
                      raise Exception, "You must pass the format_record[:content] as a Hash of persistable elements"
                    end
                    old_segments = []
                    content = format_record[:content].gxg_export.to_json.encode64
                    @connector[:text_page].select(:dbid).where({:parent_uuid => format_record[:uuid].to_s}).order(:ordinal).each do |entry|
                      old_segments << entry[:dbid]
                    end
                    if content.size == 0
                      if old_segments.size > 0
                        @connector[:text_page].filter({:parent_uuid => format_record[:uuid].to_s}).delete
                      end
                    else
                      new_segments = ::GxG::apportioned_ranges(content.size, 4096)
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
                      manifest.each do |action|
                        case action[:operation]
                        when :overwrite
                          @connector[:text_page].filter({:dbid => (action[:dbid])}).update({:ordinal => (action[:ordinal]), :length => (content[(action[:portion])].size), :content => (content[(action[:portion])])})
                        when :create
                          @connector[:text_page].insert({:parent_uuid => (record[:uuid]), :ordinal => (action[:ordinal]), :length => (content[(action[:portion])].size), :content => (content[(action[:portion])])})
                        when :delete
                          @connector[:text_page].filter({:dbid => (action[:dbid])}).delete
                        end
                      end
                      @connector[:formats].filter({:uuid => format_record[:uuid].to_s}).update({:version => (::BigDecimal.new(format_record[:version].to_s) + 0.0001)})
                      #
                    end
                  end
                  #
                  result = true
                  #
                  if result == true && ::GxG::DB[:roles][:formats] == self
                    already = [(self)]
                    GxG::DB[:roles].values.each do |the_db|
                        unless already.include?(the_db)
                            the_db.format_update(format_record)
                            already << the_db
                        end
                    end
                  end
                  #
                else
                  result = self.format_create(format_record)
                end
              else
                raise ArgumentError, "You must supply a valid format record as a Hash"
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:format_record => (format_record)}})
        end
        result
      end
      #
      def format_destroy(search_options={})
        result = false
        begin
          if self.alive?()
            if self.open?
              unless self.db_permissions()[:write]
                raise Exception, "Unable to write to database"
              end
              format_stub = self.format_list(search_options).first
              if format_stub
                @connector[:formats].filter({:uuid => (format_stub[:uuid].to_s)}).delete
                if @connector[:text_page].filter({:parent_uuid => (format_stub[:uuid].to_s)}).count > 0
                  @connector[:text_page].filter({:parent_uuid => (format_stub[:uuid].to_s)}).delete
                end
                result = true
                #
                if result == true && ::GxG::DB[:roles][:formats] == self
                  already = [(self)]
                  GxG::DB[:roles].values.each do |the_db|
                      unless already.include?(the_db)
                          the_db.format_destroy(search_options)
                          already << the_db
                      end
                  end
                end
                #
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:search_options => (search_options)}})
        end
        result
      end
      # Settings methods
      def setting_keys()
        result = []
        begin
          if self.alive?()
            if self.open?()
              @connector[:settings].all.each do |the_entry|
                result << the_entry[:title].to_sym
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:setting_key => setting_key}})
        end
        result
      end
      #
      def [](setting_key=nil)
        result = nil
        begin
          if self.alive?()
            if self.open?()
              record = @connector[:settings].filter({:title => setting_key.to_s}).first
              if record
                content = ""
                @connector[:text_page].select(:content).where({:parent_uuid => record[:uuid].to_s}).order(:ordinal).each do |entry|
                  content << entry[:content]
                end
                if content.size > 0
                  result = content.unserialize()
                end
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:setting_key => setting_key}})
        end
        result
      end
      #
      def []=(setting_key=nil, object=nil)
        result = object
        begin
          if self.alive?()
            if self.open?()
              unless self.db_permissions()[:write]
                raise Exception, "Unable to write to database"
              end
              unless setting_key.is_a?(::Symbol)
                raise ArgumentError, "You must supply a setting key as a Symbol"
              end
              unless setting_key.to_s.size > 0
                raise ArgumentError, "You must supply a setting key whose length is greater than zero"
              end
              record = @connector[:settings].filter({:title => setting_key.to_s}).first
              unless record
                new_uuid = ::GxG::uuid_generate().to_s
                while (@connector[:settings].filter({:uuid => (new_uuid)}).count > 0 or @connector[:formats].filter({:uuid => (new_uuid)}).count > 0 or @connector[:element_text].filter({:uuid => (new_uuid)}).count > 0)
                  new_uuid = ::GxG::uuid_generate().to_s
                end
                @connector[:settings].insert({:title => setting_key.to_s, :uuid => new_uuid.to_s})
                record = @connector[:settings].filter({:uuid => (new_uuid)}).first
              end
              if record
                @connector[:settings].filter({:dbid => (record[:dbid])}).update({:version => (record[:version] + 0.0001)})
                content = object.serialize()
                old_segments = []
                @connector[:text_page].select(:dbid).where({:parent_uuid => record[:uuid].to_s}).order(:ordinal).each do |entry|
                  old_segments << entry[:dbid]
                end
                if content.size == 0
                  if old_segments.size > 0
                    @connector[:text_page].filter({:parent_uuid => record[:uuid].to_s}).delete
                  end
                else
                  new_segments = ::GxG::apportioned_ranges(content.size, 4096)
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
                  manifest.each do |action|
                    case action[:operation]
                    when :overwrite
                      @connector[:text_page].filter({:dbid => (action[:dbid])}).update({:ordinal => (action[:ordinal]), :length => (content[(action[:portion])].size), :content => (content[(action[:portion])])})
                    when :create
                      @connector[:text_page].insert({:parent_uuid => (record[:uuid]), :ordinal => (action[:ordinal]), :length => (content[(action[:portion])].size), :content => (content[(action[:portion])])})
                    when :delete
                      @connector[:text_page].filter({:dbid => (action[:dbid])}).delete
                    end
                  end
                  #
                end
              else
                raise Exception, "Internal Error - could not retrieve setting record: #{setting_key.inspect}"
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:setting => setting_key, :object => object}})
        end
        result
      end
      #
      # Permission policy support:
      def permission_policy()
        result = nil
        begin
          if self.alive?()
            if self.open?()
              if @authority
                result = @authority.permission_policy()
              else
                result = @permission_policy
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def permission_policy_load()
        result = false
        begin
          if self.alive?()
            if self.open?()
              if @authority
                result = @authority.permission_policy_load()
              else
                @permission_policy = (self[:permission_policy] || [])
                result = true
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def permission_policy_save()
        result = false
        begin
          if self.alive?()
            if self.open?()
              if @authority
                result = @authority.permission_policy_save()
              else
                self[:permission_policy] = (@permission_policy || [])
                result = true
              end
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {}})
        end
        result
      end
      #
      def enforce_permission_policy(event={})
        # Event format: enforce_permission_policy({:action => :extend, :credential => nil, :source => nil, :destination => nil})
        # Rule format: {:event => :create, :credential => :any, :action => {:extend_permissions => nil}}
        the_policy = self.permission_policy()
        result = false
        begin
          if self.alive?()
            if self.open?()
              actions = []
              the_policy.each do |rule|
                if event[:action] == rule[:event]
                  if rule[:credential] == event[:credential] || rule[:credential] == :any
                    actions << rule[:action]
                  end
                end
              end
              actions.each do |action|
                case action.keys[0]
                when :extend_permissions
                  if action[:use_permission].is_a?(::Hash)
                    use_permission = action[:use_permission]
                  else
                    use_permission = nil
                  end
                  credential = event[:credential]
                  unless ::GxG::valid_uuid?(credential)
                    raise ArgumentError, "You MUST provide a valid UUID as :credential."
                  end
                  new_credential = action[:extend_permissions]
                  source = event[:source]
                  unless source.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    raise ArgumentError, "You MUST provide a persisted object as :source."
                  end
                  unless source.db_address
                    raise Exception, "You provided a Deactivated object as :source."
                  end
                  destination = event[:destination]
                  unless destination.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                    raise ArgumentError, "You MUST provide a persisted object as :source."
                  end
                  unless destination.db_address
                    raise Exception, "You provided a Deactivated object as :destination."
                  end
                  #
                  permissions = self.element_permissions(source.db_address()[:table],source.db_address()[:dbid])
                  permission_db = []
                  if [:persisted_array, :persisted_hash].include?(destination.db_address()[:table])
                    search_db = [{:table => destination.db_address()[:table], :dbid => destination.db_address()[:dbid]}]
                    permission_db << {:table => destination.db_address()[:table], :dbid => destination.db_address()[:dbid]}
                    while search_db.size > 0 do
                      entry = search_db.shift
                      self.element_manifest(entry[:table],entry[:dbid],false).each do |item|
                        if [:persisted_array, :persisted_hash].include?(item[:table])
                          search_db << item
                          permission_db << item
                        end
                      end
                    end
                    permission_db.each do |the_reference|
                      permissions.each do |record|
                        self.assign_element_permission(the_reference[:table],the_reference[:dbid], credential, record[:permissions])
                        if use_permission
                          self.assign_element_permission(the_reference[:table],the_reference[:dbid], new_credential, use_permission)
                        else
                          self.assign_element_permission(the_reference[:table],the_reference[:dbid], new_credential, record[:permissions])
                        end
                      end
                    end
                    # destination.search do |the_value, the_selector, the_container|
                    #   if [:persisted_array, :persisted_hash].include?(the_value.db_address()[:table])
                    #     permission_db << {:table => the_value.db_address()[:table], :dbid => the_value.db_address()[:dbid]}
                    #   end
                    # end
                    #
                  end
                  # permission_db << {:table => destination.db_address()[:table], :dbid => destination.db_address()[:dbid]}
                  # if destination.is_any?(::GxG::Database::PersistedHash, ::GxG::Database::PersistedArray)
                  #   destination.search do |the_value, the_selector, the_container|
                  #     permission_db << {:table => the_value.db_address()[:table], :dbid => the_value.db_address()[:dbid]}
                  #   end
                  # end
                  # permission_db.each do |item|
                  #   self.element_manifest(item[:table],item[:dbid],false).each do |entry|
                  #     permissions.each do |record|
                  #       self.assign_element_permission(entry[:table],entry[:dbid], credential, record[:permissions])
                  #       if use_permission
                  #         self.assign_element_permission(entry[:table],entry[:dbid], new_credential, use_permission)
                  #       else
                  #         self.assign_element_permission(entry[:table],entry[:dbid], new_credential, record[:permissions])
                  #       end
                  #     end
                  #   end
                  # end
                  #
                end
              end
              result = true
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:event => event}})
        end
        result
      end
      # ### Import methods (deprecated in favor of sychronize_records)
      def import(credential=nil, the_record=nil)
        #
        result = nil
        if self.alive?
          if self.open?
            if self.db_permissions()[:write]
              cleanup_manifest = []
              begin
                unless ::GxG::valid_uuid?(credential)
                  raise ArgumentError, "You must supply a valid credential UUID (as a String or Symbol)"
                end
                if the_record.is_a?(::Hash)
                  case the_record[:type]
                  when :element_boolean, :element_integer, :element_float, :element_bigdecimal, :element_datetime
                    new_dbid = @connector[(the_record[:type])].insert({:version => (the_record[:version]), :content => (the_record[:content])})
                    self.assign_element_permission((the_record[:type]), (new_dbid), credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                    result = {:table => (the_record[:table]), :dbid => (new_dbid)}
                  when :element_text
                    the_uuid = ::GxG::uuid_generate()
                    while (@connector[:element_text].filter({:uuid => the_uuid}).count > 0)
                      the_uuid = ::GxG::uuid_generate()
                    end
                    new_dbid = @connector[:element_text].insert({:uuid => (the_uuid), :version => (the_record[:version]), :length => (the_record[:content].size)})
                    cleanup_manifest << {:table => :element_text, :dbid => (new_dbid)}
                    ::GxG::apportioned_ranges(the_record[:content].size, 4096).each_with_index do |the_range,the_ordinal|  
                      @connector[:text_page].insert({:parent_uuid => (the_uuid), :ordinal => (the_ordinal), :length => (the_record[:content][(the_range)].size), :content => (the_record[:content][(the_range)])})
                    end
                    self.assign_element_permission((the_record[:type]), (new_dbid), credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                    result = {:table => :element_text, :dbid => (new_dbid)}
                  when :element_binary
                    the_uuid = ::GxG::uuid_generate()
                    while (@connector[:element_binary].filter({:uuid => the_uuid}).count > 0)
                      the_uuid = ::GxG::uuid_generate()
                    end
                    new_dbid = @connector[:element_binary].insert({:uuid => (the_uuid), :version => (the_record[:version]), :length => (the_record[:content].size)})
                    cleanup_manifest << {:table => :element_binary, :dbid => (new_dbid)}
                    ::GxG::apportioned_ranges(the_record[:content].size, 65536).each_with_index do |the_range,the_ordinal|  
                      @connector[:binary_page].insert({:parent_uuid => (the_uuid), :ordinal => (the_ordinal), :length => (the_record[:content].data()[(the_range)].size), :content => (the_record[:content].data()[(the_range)])})
                    end
                    self.assign_element_permission((the_record[:type]), (new_dbid), credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                    result = {:table => :element_binary, :dbid => (new_dbid)}
                  when :element_array
                    # {:type => :element_array, :uuid => @uuid, :title => @title, :version => @version, :content => []}
                    existing = @connector[(the_record[:type])].select(:dbid, :version).where({:uuid => the_record[:uuid].to_s}).first
                    if existing
                      if the_record[:version] > existing[:version]
                        unless self.element_destroy(credential, :element_array, existing[:dbid])
                          raise Exception, "Error replacing array element - Aborting"
                        end
                        existing = nil
                      else
                        log_warn("Import record is older than existing one - Skipping")
                        new_dbid = existing[:dbid]
                      end
                    end
                    unless existing
                      new_dbid = @connector[(the_record[:type])].insert({:uuid => (the_record[:uuid].to_s), :title => (the_record[:title]), :version => (the_record[:version])})
                      cleanup_manifest << {:table => :element_array, :dbid => (new_dbid)}
                      self.assign_element_permission(:element_array, (new_dbid), credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                      the_record[:content].each_with_index do |element, indexer|
                        new_address = self.import(credential, (element))
                        if new_address
                          cleanup_manifest << new_address
                          @connector[:array_links].insert({:parent_uuid => (the_record[:uuid].to_s), :ordinal => (indexer), :element => (::GxG::Database::Database::element_table_index(new_address[:table])), :elementid => new_address[:dbid]})
                        else
                          raise Exception, "Error processing the import record - Aborting"
                        end
                      end
                    end
                    result = {:table => :element_array, :dbid => (new_dbid)}
                  when :element_hash
                    # {:type => :element_hash, :uuid => @uuid, :title => @title, :version => @version, :format => @format, :content => {}}
                    existing = @connector[(the_record[:type])].select(:dbid, :version).where({:uuid => the_record[:uuid].to_s}).first
                    if existing
                      if the_record[:version] > existing[:version]
                        unless self.element_destroy(credential, :element_hash, existing[:dbid])
                          raise Exception, "Error replacing hash element - Aborting"
                        end
                        existing = nil
                      else
                        log_warn("Import record is older than existing one - Skipping")
                        new_dbid = existing[:dbid]
                      end
                    end
                    unless existing
                      new_dbid = @connector[(the_record[:type])].insert({:uuid => (the_record[:uuid].to_s), :title => (the_record[:title]), :version => (the_record[:version]), :format => (the_record[:format].to_s)})
                      cleanup_manifest << {:table => :element_hash, :dbid => (new_dbid)}
                      self.assign_element_permission(:element_hash, (new_dbid), credential, {:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                      the_record[:content].keys.each_with_index do |the_key, indexer|
                        new_address = self.import(credential, (the_record[:content][(the_key)]))
                        if new_address
                          cleanup_manifest << new_address
                          @connector[:hash_links].insert({:parent_uuid => (the_record[:uuid].to_s), :property => (the_key.to_s), :ordinal => (indexer), :element => (::GxG::Database::Database::element_table_index(new_address[:table])), :elementid => new_address[:dbid]})
                        else
                          raise Exception, "Error processing the import record - Aborting"
                        end
                      end
                    end
                    result = {:table => :element_hash, :dbid => (new_dbid)}
                  else
                    raise ArgumentError, "Invalid table specified"
                  end
                else
                  raise ArgumentError, "You must supply an import record as a Hash"
                end
              rescue Exception => the_error
                # clean up
                cleanup_manifest.each do |entry|
                  self.element_destroy(credential, entry[:table], entry[:dbid])
                end
                log_error({:error => the_error, :parameters => {:the_record => (the_record)}})
              end
            else
              log_warn("Cannot import records into a read-only Database - Aborting")
            end
          end
        end
        result
      end
      # ### Search function method
      def uuid_list(credential=nil, criteria={})
        # will return an array of all structures the credential has (at least) read access to
        result = []
        begin
          if self.alive?
            if self.open?
              unless ::GxG::valid_uuid?(credential)
                raise ArgumentError, "You must supply a valid credential UUID (as a String or Symbol)"
              end
              unless criteria.is_a?(::Hash)
                raise ArgumentError, "You must supply a search criteria as a Hash"
              end
              hash_criteria = {}
              array_criteria = {}
              # Limit, Offset, and Page selection
              if criteria[:limit].is_a?(::Integer)
                limit = criteria[:limit]
              else
                limit = nil
              end
              if criteria[:offset].is_a?(::Integer)
                offset = criteria[:offset]
              else
                offset = 0
              end
              if criteria[:page].is_a?(::Integer)
                page = criteria[:page]
                unless limit
                  limit = 100
                end
                offset = ((page * limit) - 1)
              else
                page = nil
              end
              # UUID, Title, and Format searches
              if ::GxG::valid_uuid?(criteria[:uuid])
                hash_criteria[:uuid] = criteria[:uuid].to_s
                array_criteria[:uuid] = criteria[:uuid].to_s
              end
              if criteria[:title].is_a?(::String)
                hash_criteria[:title] = criteria[:title].to_s[0..256]
                array_criteria[:title] = criteria[:title].to_s[0..256]
              end
              if criteria[:format].is_any?([::String, ::Symbol])
                if ::GxG::valid_uuid?(criteria[:format])
                  format_list = self.format_list({:uuid => criteria[:format].to_sym})
                  unless format_list.size > 0
                    raise ArgumentError, "Format not found: #{criteria[:format].inspect}"
                  end
                  hash_criteria[:format] = criteria[:format].to_s
                end
              end
              if criteria[:ufs].is_any?(::String, ::Symbol)
                if criteria[:ufs_version].is_a?(::Numeric)
                  format_list = self.format_list({:ufs => criteria[:ufs].to_sym, :version => ::BigDecimal.new(criteria[:ufs_version].to_s)})
                else
                  format_list = self.format_list({:ufs => criteria[:ufs].to_sym})
                end
                unless format_list.size > 0
                  if criteria[:ufs_version].is_a?(::Float)
                    raise ArgumentError, "Format not found: #{criteria[:ufs].inspect}, Version: #{criteria[:ufs_version].inspect}"
                  else
                    raise ArgumentError, "Format not found: #{criteria[:ufs].inspect}"
                  end
                end
                hash_criteria[:format] = format_list[0][:uuid].to_s
              end
              # Output column selection: (very very basic at first)
              selectables = [:uuid, :title, :version]
              selected = []
              if criteria[:select].is_any?(::Symbol, ::Array)
                if criteria[:select].is_a?(::Array)
                  criteria[:select].each do |the_column_symbol|
                    if selectables.include?(the_column_symbol)
                      selected << the_column_symbol
                    end
                  end
                else
                  if selectables.include?(criteria[:select])
                    selected << criteria[:select]
                  end
                end
              end
              if selected.size == 0
                selected << :uuid
              end
              #
              reduce_to_datetime = Proc.new do |the_value|
                the_result = nil
                db_content = nil
                if the_value.is_a?(::String)
                  if the_value.include?("between")
                    the_times = the_value.split("between")[1].split("and")
                    the_times[0] = ::Chronic.parse(the_times[0])
                    the_times[1] = ::Chronic.parse(the_times[1])
                    if the_times[0].is_a?(::Time) && the_times[1].is_a?(::Time)
                      db_content = ((the_times[0].to_datetime)..(the_times[1].to_datetime))
                    else
                      raise Exception, "Unable to understand your time specification text: #{the_value.inspect}"
                    end
                  else
                    if the_value.valid_time? || the_value.valid_date? || the_value.valid_datetime_nolocale? || the_value.valid_datetime?
                      db_content = ::DateTime::parse(the_value)
                    else
                      the_times = ::Chronic.parse(the_value)
                      if the_times.is_a?(::Time)
                        db_content = the_times.to_datetime
                      else
                        raise Exception, "Unable to understand your time specification text: #{the_value.inspect}"
                      end
                    end
                  end
                end
                if the_value.is_a?(::Range)
                  the_times = [(the_value.first), (the_value.last)]
                  if the_times[0].is_a?(::Time)
                    the_times[0] = the_times[0].to_datetime
                  end
                  if the_times[0].is_a?(::Date)
                    the_times[0] = ::DateTime::parse(the_times[0].to_s)
                  end
                  if the_times[1].is_a?(::Time)
                    the_times[1] = the_times[1].to_datetime
                  end
                  if the_times[1].is_a?(::Date)
                    the_times[1] = ::DateTime::parse(the_times[1].to_s)
                  end
                  the_times = ((the_times[0])..(the_times[1]))
                  if the_times.first.is_a?(::DateTime) && the_value.last.is_a?(::DateTime)
                    db_content = the_times
                  else
                    raise Exception, "Invalid Range of dates, use DateTime objects in the Range: #{the_value.inspect}"
                  end
                end
                if the_value.is_any?(::Time, ::Date)
                  db_content = ::DateTime::parse(the_value.to_s)
                end
                if the_value.is_a?(::DateTime)
                  db_content = the_value
                end
                if db_content
                  result = db_content
                else
                  raise Exception, "Unable to reduce to a DateTime with this input: #{the_value.inspect}"
                end
                the_result
              end
              #
              db_content_value = Proc.new do |the_value|
                the_result = nil
                the_table = ::GxG::Database::Database::element_table_for_instance(the_value)
                if the_table == :unspecified
                  raise Exception, "Invalid value passed as persistable: #{the_value.inspect}"
                else
                  db_content = nil
                  case the_table
                  when :element_boolean
                    if the_value.is_a?(::TrueClass)
                      db_content = 1
                    else
                      if the_value.is_a?(::FalseClass)
                        db_content = 0
                      else
                        db_content = -1
                      end
                    end
                  when :element_binary
                    db_content = ""
                    the_value.each do |the_byte|
                      db_content << the_byte.to_s(base=16)
                    end
                  when :element_text
                    if the_value.valid_time? || the_value.valid_date? || the_value.valid_datetime_nolocale? || the_value.valid_datetime?
                      db_content = reduce_to_datetime.call(the_value)
                    else
                      db_content = the_value
                    end
                  else
                    db_content = the_value
                  end
                  if db_content
                    the_result = db_content
                  else
                    raise Exception, "Could not cast the value to something useful: #{the_value.inspect}"
                  end
                end
                the_result
              end
              #
              find_property_records = Proc.new do |a_selector, a_container|
                a_result = []
                a_container.each do |item|
                  if item[(a_selector)]
                    a_result << item
                  end
                end
                a_result
              end
              find_element_records = Proc.new do |a_selector, a_container|
                a_result = []
                a_container.each do |item|
                  if item[(a_selector)]
                    a_result << item
                  end
                end
                a_result
              end
              found_list = []
              # criteria[:property] :
              # For all
              # {:property_name => {:equals => value}}
              # For :element_integer, :element_float, :element_bigdecimal
              # {:property_name => {:greater_than => value, :greater_or_equal => value, :less_than => value, :less_or_equal => value}}
              # For :element_datetime, Note: if you pass text as a date ::Chronic will be used to parse it.
              # {:property_name => {:at => value, :before => value, :at_or_before => value, :after => value, :at_or_after => value, :between => <range-value>}
              # For Text, Binary
              # {:property_name => {:include => value}}
              # 
              # criteria[:element] :
              # similar to criteria[:property] except that the entire table for the type is searched and no property dereferencing needed.
              #
              if criteria[:property] || criteria[:element]
                # Expansion
                # Text Search: @connector[:text_page].where(::Sequel.like(:content,'%#{search_text}%'))
                # Binary Search: @connector[:binary_page].where(::Sequel.like(:content,'%#{byte_sequence}%'))
                # self.element_parent_address(the_table=:unspecified, the_dbid=0)
                if criteria[:property].is_a?(::Hash)
                  # Only ONE property key can be compared (TODO: expand to multiple keys)
                  property_matches = []
                  last_key = nil
                  #
                  criteria[:property].keys.each do |property_key|
                    # compare each key's value to qualify the parent object:
                    # {:html => {:include => "\n"}}
                    comparison_op = criteria[:property][(property_key)].keys[0].to_sym
                    if criteria[:property][(property_key)][(comparison_op)].is_any?(::String, ::Range) && [:at, :before, :after, :at_or_before, :at_or_after, :between].include?(comparison_op)
                      comparison_value = reduce_to_datetime.call(criteria[:property][(property_key)][(comparison_op)])
                      table_test = ::GxG::Database::Database::element_table_for_instance(comparison_value)
                    else
                      table_test = ::GxG::Database::Database::element_table_for_instance(criteria[:property][(property_key)][(comparison_op)])
                      comparison_value = db_content_value.call(criteria[:property][(property_key)][(comparison_op)])
                    end
                    #
                    if [:element_hash, :element_array].include?(table_test)
                      # Only properties with base elements can be compared - not structures (TODO: expand this)
                      log_warn("Attempted to compare a structure as a property value (not supported, ignoring).")
                      next
                    end
                    # Review : rewrite - adapt to new arch.
                    match_uuid_list = []
                    # comparison_value
                    @connector[:hash_properties].filter({:property => property_key.to_s}).each do |entry|
                      element_value = nil
                      case entry[:element]
                      when "element_boolean"
                        case entry[:element_boolean]
                        when -1
                          element_value = nil
                        when 0
                          element_value = false
                        when 1
                          element_value = nil
                        end
                      when "element_integer"
                        element_value = entry[:element_integer]
                      when "element_float"
                        element_value = entry[:element_float]
                      when "element_bigdecimal"
                        element_value = ::BigDecimal.new(entry[:element_bigdecimal].to_s)
                      when "element_datetime"
                        element_value = entry[:element_datetime]
                      when "element_text"
                        if entry[:element_text_uuid].to_s.size > 0
                          # Review: issue with Base64: decode64 mangles non-base64 text but does it w/o error now.
                          element_value = ""
                          @connector[:text_page].filter({:uuid => entry[:element_text_uuid].to_s}).order(:ordinal).each do |text_page|
                            element_value << text_page[:content]
                          end
                        else
                          element_value = entry[:element_text]
                        end
                      when "element_binary"
                        element_value = ::GxG::ByteArray.new
                        @connector[:binary_page].filter({:uuid => entry[:element_binary_uuid].to_s}).order(:ordinal).each do |binary_page|
                          element_value << binary_page[:content]
                        end
                      end
                      #
                      begin
                        case comparison_op
                        when :equals, :at
                          if element_value == comparison_value
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :greater_than, :after
                          if element_value > comparison_value
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :greater_or_equal, :at_or_after
                          if element_value >= comparison_value
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :less_than, :before
                          if element_value < comparison_value
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :less_or_equal, :at_or_before
                          if element_value <= comparison_value
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :between
                          if comparison_value.include?(element_value)
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :include
                          if element_value.to_s.include?(comparison_value.to_s)
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        when :match
                          if element_value.to_s.match(comparison_value)
                            match_uuid_list << entry[:parent_uuid].to_sym
                          end
                        end
                      rescue Exception => cast_error
                        # Probably a type casting error (comparison of dissimilar types)
                        next
                      end
                    end
                    #
                    match_uuid_list.each do |the_matched_uuid|
                      # Add to main found list
                      parent_record = @connector[:element_hash].select(:uuid, :version, :title).where({:uuid => the_matched_uuid.to_s}).first
                      if parent_record
                        new_record = {}
                        selected.each do |the_selected_key|
                          if parent_record.keys.include?(the_selected_key)
                            new_record[(the_selected_key)] = parent_record[(the_selected_key)]
                            if ::GxG::valid_uuid?(new_record[(the_selected_key)])
                              new_record[(the_selected_key)] = new_record[(the_selected_key)].to_sym
                            end
                          end
                        end
                        unless found_list.include?(new_record)
                          found_list << new_record
                        end
                      end
                    end
                    #
                    if last_key != property_key
                      last_key = property_key
                    end
                    #
                  end
                  #
                else
                  if criteria[:element].is_a?(::Array)
                    criteria[:element].each_with_index do |the_element, element_index|
                      comparison_op = criteria[:element][(element_index)].keys[0].to_sym
                      if criteria[:element][(element_index)][(comparison_op)].is_any?(::String, ::Range) && [:at, :before, :after, :at_or_before, :at_or_after, :between].include?(comparison_op)
                        comparison_value = reduce_to_datetime.call(criteria[:element][(element_index)][(comparison_op)])
                        element_table = ::GxG::Database::Database::element_table_for_instance(comparison_value)
                      else
                        element_table = ::GxG::Database::Database::element_table_for_instance(criteria[:element][(element_index)][(comparison_op)])
                        comparison_value = db_content_value.call(criteria[:element][(element_index)][(comparison_op)])
                      end
                      # Structural comparison not supported.
                      if [:element_hash, :element_array].include?(element_table)
                        log_warn("Attempted to compare a structure as an element (not supported, ignoring).")
                        next
                      end
                      match_uuid_list = []
                      # comparison_value
                      @connector[:array_elements].filter({:element => element_table.to_s}).each do |entry|
                        element_value = nil
                        case entry[:element]
                        when "element_boolean"
                          case entry[:element_boolean]
                          when -1
                            element_value = nil
                          when 0
                            element_value = false
                          when 1
                            element_value = nil
                          end
                        when "element_integer"
                          element_value = entry[:element_integer]
                        when "element_float"
                          element_value = entry[:element_float]
                        when "element_bigdecimal"
                          element_value = ::BigDecimal.new(entry[:element_bigdecimal].to_s)
                        when "element_datetime"
                          element_value = entry[:element_datetime]
                        when "element_text"
                          if entry[:element_text_uuid].to_s.size > 0
                            # Review: issue with Base64: decode64 mangles non-base64 text but does it w/o error now.
                            element_value = ""
                            @connector[:text_page].filter({:uuid => entry[:element_text_uuid].to_s}).order(:ordinal).each do |text_page|
                              element_value << text_page[:content]
                            end
                          else
                            element_value = entry[:element_text]
                          end
                        when "element_binary"
                          element_value = ::GxG::ByteArray.new
                          @connector[:binary_page].filter({:uuid => entry[:element_binary_uuid].to_s}).order(:ordinal).each do |binary_page|
                            element_value << binary_page[:content]
                          end
                        end
                        #
                        begin
                          case comparison_op
                          when :equals, :at
                            if element_value == comparison_value
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :greater_than, :after
                            if element_value > comparison_value
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :greater_or_equal, :at_or_after
                            if element_value >= comparison_value
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :less_than, :before
                            if element_value < comparison_value
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :less_or_equal, :at_or_before
                            if element_value <= comparison_value
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :between
                            if comparison_value.include?(element_value)
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :include
                            if element_value.to_s.include?(comparison_value.to_s)
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          when :match
                            if element_value.to_s.match(comparison_value)
                              match_uuid_list << entry[:parent_uuid].to_sym
                            end
                          end
                        rescue Exception => cast_error
                          # Probably a type casting error (comparison of dissimilar types)
                          next
                        end
                        # end - comparison loop
                      end
                      #
                      match_uuid_list.each do |the_matched_uuid|
                        # Add to main found list
                        parent_record = @connector[:element_array].select(:uuid, :version, :title).where({:uuid => the_matched_uuid.to_s}).first
                        if parent_record
                          new_record = {}
                          selected.each do |the_selected_key|
                            if parent_record.keys.include?(the_selected_key)
                              new_record[(the_selected_key)] = parent_record[(the_selected_key)]
                              if ::GxG::valid_uuid?(new_record[(the_selected_key)])
                                new_record[(the_selected_key)] = new_record[(the_selected_key)].to_sym
                              end
                            end
                          end
                          unless found_list.include?(new_record)
                            found_list << new_record
                          end
                        end
                      end
                      #
                      # unless last_index == element_index
                      #   last_index = element_index
                      # end
                    end
                    #
                  else
                    # Criteria Expansion Here
                  end
                end
              else
                @connector[:element_hash].filter(hash_criteria).each do |entry|
                  new_record = {}
                  selected.each do |the_key|
                    if ::GxG::valid_uuid?(entry[(the_key)])
                      new_record[(the_key)] = entry[(the_key)].to_sym
                    else
                      new_record[(the_key)] = entry[(the_key)]
                    end
                  end
                  found_list << new_record
                end
                #
                unless hash_criteria[:format]
                  @connector[:element_array].filter(array_criteria).each do |entry|
                    new_record = {}
                    selected.each do |the_key|
                      if ::GxG::valid_uuid?(entry[(the_key)])
                        new_record[(the_key)] = entry[(the_key)].to_sym
                      else
                        new_record[(the_key)] = entry[(the_key)]
                      end
                    end
                    found_list << new_record
                  end
                end
              end
              #
              # Sorting Options Here: (Expansion)
              if criteria[:order].is_any?(::Symbol, ::Hash)
                ascending = true
                sort_key = nil
                if criteria[:order].is_a?(::Hash)
                  if criteria[:order][:ascending].is_a?(::Symbol)
                    sort_key = criteria[:order][:ascending]
                  end
                  if criteria[:order][:descending].is_a?(::Symbol)
                    sort_key = criteria[:order][:descending]
                    ascending = false
                  end
                else
                  sort_key = criteria[:order]
                end
                if selected.include?(sort_key)
                  found_list = found_list.sort do |entry, another|
                    entry[(sort_key)] <=> another[(sort_key)]
                  end
                  unless ascending
                    found_list.reverse!
                  end
                end
              end
              # Impose result set limit and offset
              if limit.is_a?(::Integer)
                if found_list.size > 0
                  if (offset + (limit - 1)) <= (found_list.size - 1)
                    found_list = found_list[((offset)..(offset + (limit - 1)))]
                  else
                    if offset <= (found_list.size - 1)
                      found_list = found_list[((offset)..(-1))]
                    end
                  end
                end
              end
              #
              found_list.size.times do
                result << found_list.shift
              end
              #
            else
              raise Exception, "Database not available"
            end
          else
            raise Exception, "Attempted to access a defunct Database"
          end
        rescue Exception => the_error
          log_error({:error => the_error, :parameters => {:credential => (credential), :criteria => (criteria)}})
        end
        result
      end
      #
      def search_database(credential=nil, criteria={})
        # Usage: search_database(credential, {:ufs => "the.ufs.code", :properties => [{:the_property => {:equals => value}}]})
        #
        # criteria[:properties] :
        # For all
        # {:property_name => {:equals => value}}
        # For :element_integer, :element_float, :element_bigdecimal
        # {:property_name => {:greater_than => value, :greater_or_equal => value, :less_than => value, :less_or_equal => value}}
        # For :element_datetime, Note: if you pass text as a date ::Chronic will be used to parse it.
        # {:property_name => {:at => value, :before => value, :at_or_before => value, :after => value, :at_or_after => value, :between => <range-value>}
        # For Text, Binary
        # {:property_name => {:include => value}}
        # 
        # criteria[:element] :
        # similar to criteria[:property] except that the entire table for the type is searched and no property dereferencing needed.
        #
        result = []
        criterium = []
        criteria_error = false
        unless criteria.is_a?(::Hash)
          criteria_error = true
        end
        unless criteria_error
          common_criteria = criteria.clone
          properties = (common_criteria.delete(:properties) || [])
          unless properties.is_a?(::Array)
            criteria_error = true
          end
          elements = (common_criteria.delete(:elements) || [])
          unless elements.is_a?(::Array)
            criteria_error = true
          end
        end
        #
        unless criteria_error
          if properties.size > 0 && elements.size > 0
            criteria_error = true
            log_warn("You MUST select EITHER :properites OR :elements, not both.")
          end
        end
        #
        unless criteria_error
          # Prepare criterium
          if common_criteria[:select].is_a?(::Array)
            unless common_criteria[:select].include?(:uuid)
              common_criteria[:select] << :uuid
            end
          else
            common_criteria[:select] = [:uuid]
          end
          #
          if common_criteria[:ufs]
            criterium << {:ufs => common_criteria[:ufs]}
          end
          if common_criteria[:format]
            criterium << {:format => common_criteria[:format]}
          end
          #
          if properties.size > 0
            properties.each do |the_property_search|
              criterium << ((common_criteria.clone).merge({:property => the_property_search}))
            end
          end
          if elements.size > 0
            elements.each do |the_element_search|
              criterium << ((common_criteria.clone).merge({:element => the_element_search}))
            end
          end
        end
        #
        result_sets = []
        # if properties.size == 0 && elements.size == 0
        #   result_sets << self.uuid_list(credential, criteria)
        # else
          criterium.each do |the_criteria|
            result_sets << self.uuid_list(credential, the_criteria)
          end
        # end
        scores = {}
        result_sets.each do |the_result|
          the_result.each do |the_answer|
            if scores.keys.include?(the_answer[:uuid])
              scores[(the_answer[:uuid])] = (scores[(the_answer[:uuid])] + 1)
            else
              scores[(the_answer[:uuid])] = 1
            end
          end
        end
        scores.keys.each do |the_uuid|
          if scores[(the_uuid)] == result_sets.size
            result_sets[0].each do |the_record|
              if the_record[:uuid] == the_uuid
                result << the_record
                break
              end
            end
          end
        end
        #
        result
      end
      # Synchronize records: (and supports)
      #
      def synchronize_records(the_records=[], credential=nil, options={})
        # Review : rewrite for new architecture.
        result = {:status => :completed}
        #
        total_records_processed = 0
        total_formats_processed = 0
        # List of format uuids needed from the OTHER database to complete the sync.
        formats_needed = []
        # List of format records we are sharing.
        formats_provided = []
        # records on THIS database that are higher version than submitted version.
        updates_provided = []
        # In case something goes horribly wrong:
        clean_up_list = []
        #
        begin
          if self.alive?
            if self.open?
              unless ::GxG::valid_uuid?(credential)
                raise ArgumentError, "You MUST provide a valid UUID as credential."
              end
              #
              if the_records.is_a?(::String)
                if the_records.base64?
                  the_records = the_records.decode64
                end
                if the_records.json?
                  the_records = ::JSON.parse(the_records,{:symbolize_names => true})
                end
              end
              if the_records.is_a?(::Hash)
                the_records = [(the_records)]
              end
              unless the_records.is_a?(::Array)
                raise ArgumentError, "You MUST provide: Base64, JSON, Hash, or Array of operation Hashes."
              end
              # Process each operation in the_records, data is inline under :data key.
              the_records.each do |the_operation|
                if the_operation.is_a?(::Hash)
                  if [:merge, :delete, :fetch, :merge_format, :delete_format, :formats_provided, :formats_needed].include?(the_operation[:operation])
                    #
                    case the_operation[:operation]
                    when :merge
                      unless self.db_permissions()[:write]
                        raise Exception, "Attempted to alter a read-only database."
                      end
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if entry[:format]
                          unless self.format_list({:uuid => (entry[:format])}).size > 0
                            raise Exception, "Attempted to merge with unknown :format #{entry[:format].inspect}. Synchronize formats first, then records."
                          end
                        end
                        # fetch existing:
                        # if existing - compare versions - if greater provide, if lesser update, else add to db.
                        queue = [(entry)]
                        while queue.size > 0 do
                          record = queue.shift
                          if ::GxG::valid_uuid?(record[:uuid])
                            formatting = {:format => nil, :constraint => nil}
                            existing = self.retrieve_by_uuid(record[:uuid], credential)
                            unless existing
                              # Note: since there is no way to create a Persisted Object with a given UUID, this method is used to create the object: object will be updated later.
                              unless @connector[(record[:type].to_s.downcase.to_sym)].filter({:uuid => record[:uuid].to_s}).count > 0
                                # This prevents no-element-retrieved-due-to-permission issue causing an 'add duplicate uuid object' situation:
                                dbid = @connector[(record[:type].to_s.downcase.to_sym)].insert({:uuid => record[:uuid].to_s, :title => "Merged Persisted Object"})
                                self.assign_element_permission(record[:type].to_s.downcase.to_sym,dbid,credential,{:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                                #
                              end
                              existing = self.retrieve_by_uuid(record[:uuid], credential)
                            end
                            if existing
                              # ### Compare versions
                              if existing.version > record[:version]
                                action = :provide
                              else
                                if existing.version < record[:version]
                                  action = :update
                                else
                                  action = :ignore
                                end
                              end
                              # ### Take Action
                              case action
                              when :provide
                                updates_provided << {:operation => :merge, :data => [(existing.export())]}
                                existing.deactivate
                                total_records_processed += 1
                              when :update
                                # ### Prelude
                                if record[:format].to_s.size > 0
                                  formatting[:format] = record[:format].to_s
                                end
                                if record[:constraint].to_s.size > 0
                                  formatting[:constraint] = record[:constraint].to_s
                                end
                                clean_up_list << existing
                                existing.get_reservation()
                                unless existing.write_permission?() && existing.write_reserved?()
                                  raise Exception, "Failed to secure write permission and write reservation for this credential."
                                end
                                existing.title = (record[:title])
                                # ### Update Elements
                                if record[:content].is_a?(::Hash)
                                  # Review : What to do / how to handle formatted existing Hashes??
                                  unless existing.format
                                    # Eliminate keys that the imported record does not have. (tracking structural changes)
                                    existing.keys.each do |the_key|
                                      unless record[:content].keys.include?(the_key)
                                        temp_object = existing.delete(the_key)
                                        if temp_object.is_any?(::GxG::Database::PersistedArray, ::GxG::Database::PersistedHash)
                                          temp_object.destroy()
                                        end
                                      end
                                    end
                                  end
                                  record[:content].each_pair do |property, element_record|
                                    if element_record[:uuid]
                                      # ### Element is Hash or Array
                                      element = self.retrieve_by_uuid(element_record[:uuid], credential)
                                      unless element
                                        # ### Create blank element record and retrieve
                                        # Note: since there is no way to create a Persisted Object with a given UUID, this method is used to create the object: object will be updated later.
                                        unless @connector[(element_record[:type].to_s.downcase.to_sym)].filter({:uuid => element_record[:uuid].to_s}).count > 0
                                          # This prevents no-element-retrieved-due-to-permission issue causing an 'add duplicate uuid object' situation:
                                          dbid = @connector[(element_record[:type].to_s.downcase.to_sym)].insert({:uuid => element_record[:uuid].to_s, :title => "Merged Persisted Object"})
                                          self.assign_element_permission(element_record[:type].to_s.downcase.to_sym,dbid,credential,{:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                                          #
                                        end
                                        element = self.retrieve_by_uuid(element_record[:uuid], credential)
                                      end
                                      if element
                                        # ### Ensure Element Linking
                                        # Review : Warning - absence of a :write permission can bugger this up.
                                        clean_up_list << element
                                        element.get_reservation()
                                        unless element.write_permission?() && element.write_reserved?()
                                          raise Exception, "Failed to secure write permission and write reservation for this credential."
                                        end
                                        existing[(property)] = element
                                        # element.deactivate ??
                                      end
                                      # Note: return to processing queue to set its elements
                                      queue << element_record
                                    else
                                      # ### Base Element
                                      unless existing.version(property) > element_record[:version]
                                        the_content = nil
                                        case element_record[:type].to_s.downcase.to_sym
                                        when :element_boolean, :element_integer, :element_float
                                          the_content = element_record[:content]
                                        when :element_bigdecimal
                                          the_content = ::BigDecimal.new(element_record[:content].to_s)
                                        when :element_datetime
                                          the_content = ::DateTime::parse(element_record[:content].to_s)
                                        when :element_text
                                          the_content = element_record[:content].to_s
                                        when :element_binary
                                          the_content = ::GxG::ByteArray.new(element_record[:content].to_s.decode64)
                                        end
                                        existing[(property)] = the_content
                                      end
                                    end
                                  end
                                else
                                  if record[:content].is_a?(::Array)
                                    # Eliminate elements that the imported record does not have. (tracking structural changes)
                                    if existing.size > record[:content].size
                                      ((record[:content].size)..(existing.size - 1)).each do |the_indexer|
                                        temp_object = existing.delete_at(the_indexer)
                                        if temp_object.is_any?(::GxG::Database::PersistedArray, ::GxG::Database::PersistedHash)
                                          temp_object.destroy()
                                        end
                                      end
                                    end
                                    record[:content].each_with_index do |element_record, indexer|
                                      if element_record[:uuid]
                                        # ### Element is Hash or Array
                                        element = self.retrieve_by_uuid(element_record[:uuid], credential)
                                        unless element
                                          # ### Create blank element record and retrieve
                                          # Note: since there is no way to create a Persisted Object with a given UUID, this method is used to create the object: object will be updated later.
                                          unless @connector[(element_record[:type].to_s.downcase.to_sym)].filter({:uuid => element_record[:uuid].to_s}).count > 0
                                            # This prevents no-element-retrieved-due-to-permission issue causing an 'add duplicate uuid object' situation:
                                            dbid = @connector[(element_record[:type].to_s.downcase.to_sym)].insert({:uuid => element_record[:uuid].to_s, :title => "Merged Persisted Object"})
                                            self.assign_element_permission(element_record[:type].to_s.downcase.to_sym,dbid,credential,{:execute => false, :rename => true, :move => true, :destroy => true, :create => true, :write => true, :read => true})
                                            #
                                          end
                                          element = self.retrieve_by_uuid(element_record[:uuid], credential)
                                        end
                                        if element
                                          # ### Ensure Element Linking
                                          # Review : Warning - absence of a :write permission can bugger this up.
                                          clean_up_list << element
                                          element.get_reservation()
                                          unless element.write_permission?() && element.write_reserved?()
                                            raise Exception, "Failed to secure write permission and write reservation for this credential."
                                          end
                                          existing[(indexer)] = element
                                          # element.deactivate ??
                                        end
                                        # Note: return to processing queue to set its elements
                                        queue << element_record
                                      else
                                        # ### Base Element
                                        unless existing.version(indexer) > element_record[:version]
                                          the_content = nil
                                          case element_record[:type].to_s.downcase.to_sym
                                          when :element_boolean, :element_integer, :element_float
                                            the_content = element_record[:content]
                                          when :element_bigdecimal
                                            the_content = ::BigDecimal.new(element_record[:content].to_s)
                                          when :element_datetime
                                            the_content = ::DateTime::parse(element_record[:content].to_s)
                                          when :element_text
                                            the_content = element_record[:content].to_s
                                          when :element_binary
                                            the_content = ::GxG::ByteArray.new(element_record[:content].to_s.decode64)
                                          end
                                          existing[(indexer)] = the_content
                                        end
                                      end
                                      #
                                    end
                                  end
                                end
                                # ### Set Fromatting / Constraints
                                if existing.is_a?(::GxG::Database::PersistedHash)
                                  if formatting[:format].to_s.size > 0
                                    existing.format = (formatting[:format])
                                  end
                                end
                                if existing.is_a?(::GxG::Database::PersistedArray)
                                  if formatting[:constraint].to_s.size > 0
                                    existing.constraint = (formatting[:constraint])
                                  end
                                end
                                # ### Conclude Existing
                                existing.version = (record[:version])
                                existing.save
                                existing.deactivate
                                total_records_processed += 1
                              end
                            end
                          end
                        end
                        #
                      end
                    when :delete
                      unless self.db_permissions()[:write]
                        raise Exception, "Attempted to alter a read-only database."
                      end
                      #
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if ::GxG::valid_uuid?(entry[:uuid])
                          existing = self.retrieve_by_uuid(entry[:uuid].to_sym, credential)
                          if existing
                            the_address = existing.db_address()
                            existing.deactivate
                            if self.element_destroy(credential,the_address[:table],the_address[:dbid])
                              total_records_processed += 1
                            else
                              log_warn("Record #{entry[:uuid].inspect} was not deleted.")
                            end
                          else
                            log_warn("Record #{entry[:uuid].inspect} was not found.")
                          end
                        else
                          log_warn("Invalid UUID specifier (ignoring): #{entry[:uuid].inspect}")
                        end
                      end
                      #
                    when :fetch
                      # wrap export record in a :merge operation and add to updates_provided.
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if ::GxG::valid_uuid?(entry[:uuid])
                          existing = self.retrieve_by_uuid(entry[:uuid].to_sym, credential)
                          if existing
                            updates_provided << {:operation => :merge, :data => [(existing.export())]}
                            existing.deactivate
                            total_records_processed += 1
                          else
                            log_warn("Record #{entry[:uuid].inspect} was not found.")
                          end
                        else
                          log_warn("Invalid UUID specifier (ignoring): #{entry[:uuid].inspect}")
                        end
                      end
                      #
                    when :merge_format
                      unless self.db_permissions()[:write]
                        raise Exception, "Attempted to alter a read-only database."
                      end
                      # add format record if missing - check for existing, and provide if ours is newer.
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if ::GxG::valid_uuid?(entry[:uuid])
                          existing = self.format_load({:uuid => entry[:uuid].to_sym})
                          if existing.is_a?(::Hash)
                            if existing[:version] < entry[:version]
                              if self.format_update(entry)
                                total_formats_processed += 1
                              else
                                log_warn("Could not update Format #{entry[:uuid].inspect}")
                              end
                            end
                            if existing[:version] > entry[:version]
                              unless formats_provided.include?(existing)
                                formats_provided << existing
                                total_formats_processed += 1
                              end
                            end
                          else
                            if self.format_create(entry)
                              total_formats_processed += 1
                            else
                              log_warn("Could not create Format #{entry[:uuid].inspect}")
                            end
                          end
                        else
                          log_warn("Invalid Format specifier (ignoring): #{entry[:uuid].inspect}")
                        end
                      end
                    when :delete_format
                      unless self.db_permissions()[:write]
                        raise Exception, "Attempted to alter a read-only database."
                      end
                      # If the format is in use, log_warn that you're ignoring the directive.
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if ::GxG::valid_uuid?(entry[:uuid])
                          if @connector[:element_hash].filter({:format => entry[:uuid].to_s}).count == 0 && @connector[:element_array].filter({:constraint => entry[:uuid].to_s}).count == 0
                            # Not in use, safe to delete
                            if self.format_destroy({:uuid => entry[:uuid].to_sym})
                              total_formats_processed += 1
                            end
                          else
                            log_warn("Format #{entry[:uuid].inspect} in use (ignorning).")
                          end
                        else
                          log_warn("Invalid format specifier on :delete directive (ignorning): #{entry[:uuid].inspect}")
                        end
                      end
                    when :formats_provided
                      unless self.db_permissions()[:write]
                        raise Exception, "Attempted to alter a read-only database."
                      end
                      # compare uuids against db-installed formats and add to formats_needed if missing.
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if ::GxG::valid_uuid?(entry[:uuid])
                          if self.format_list({:uuid => (entry[:uuid])}).size == 0
                            record = {:uuid => (entry[:uuid].to_sym)}
                            unless formats_needed.include?(record)
                              formats_needed << record
                              total_formats_processed += 1
                            end
                          end
                        else
                          log_warn("Invalid Format specifier (ignoring): #{entry[:uuid].inspect}")
                        end
                      end
                    when :formats_needed
                      # Gather up existing format records to share.
                      manifest = []
                      if the_operation[:data].is_a?(::Array)
                        manifest = the_operation[:data]
                      else
                        if the_operation[:data].is_a?(::Hash)
                          manifest = [(the_operation[:data])]
                        else
                          log_warn("Invalid record sepecifier or manifiest (ignoring): #{the_operation[:data].inspect}")
                        end
                      end
                      manifest.each do |entry|
                        if ::GxG::valid_uuid?(entry[:uuid])
                          existing = self.format_load({:uuid => entry[:uuid].to_sym})
                          if existing.is_a?(::Hash)
                            unless formats_provided.include?(existing)
                              formats_provided << existing
                              total_formats_processed += 1
                            end
                          end
                        else
                          log_warn("Invalid Format specifier (ignoring): #{entry[:uuid].inspect}")
                        end
                      end
                      #
                    end
                  else
                    log_warn("Invalid operation (ignoring): #{the_operation[:operation].inspect}")
                  end
                else
                  raise Exception, "Invalid formatted operation passed (MUST be a Hash): #{the_operation.inspect}"
                end
              end
              #
            else
              raise Exception, "Database not available."
            end
          else
            raise Exception, "Attempted to access a defunct database."
          end
        rescue Exception => the_error
          clean_up_list.each do |the_object|
            if the_object.alive?
              the_object.release_reservation()
              the_object.deactivate()
            end
          end
          result[:status] = :failed
          #log_error({:error => the_error, :parameters => {:records => (the_records), :options => (options)}})
          log_error({:error => the_error, :parameters => {}})
        end
        result[:formats_needed] = formats_needed
        result[:formats_provided] = formats_provided
        result[:record_updates] = updates_provided
        result[:records_processed] = total_records_processed
        result[:formats_processed] = total_formats_processed
        result
      end
      #
      def sync_export(credential=nil, uuid_list=[], options={})
        result = {:formats => {}, :records => []}
        if uuid_list.is_any?(::Array, ::GxG::Database::PersistedArray)
          uuid_list.each do |the_reference|
            the_uuid = the_reference
            if ::GxG::valid_uuid?(the_uuid)
              the_object = self.retrieve_by_uuid(the_uuid, credential)
              if the_object
                object_record = the_object.export()
                object_record.search do |item,selector,container|
                  if selector == :format || selector == :constraint
                    if item.to_s.size > 0
                      format_uuid = item
                      unless result[:formats][(format_uuid.to_s.to_sym)].is_a?(::Hash)
                        format_sample = self.format_load({:uuid => format_uuid.to_s.to_sym})
                        format_sample[:content] = format_sample[:content].gxg_export()
                        result[:formats][(format_uuid.to_s.to_sym)] = format_sample
                      end
                    end
                  end
                end
                result[:records] << object_record
                #
              end
            end
          end
        end
        result
      end
      #
      def sync_import(credential=nil, the_records={:formats => {}, :records => []}, options={})
        result = false
        #
        if the_records.is_a?(::Hash)
          if the_records[:formats].is_a?(::Hash)
            op_frame = {:operation => :merge_format, :data => []}
            the_records[:formats].each_pair do |the_uuid, the_format_record|
              if the_format_record[:version].is_a?(::String)
                the_format_record[:version] = ::BigDecimal.new(the_format_record[:version])
              end
              # gxg_import format content prior to sync update op
              the_format_record[:content] = ::Hash.gxg_import(the_format_record[:content])
              op_frame[:data] << the_format_record
            end
            if op_frame[:data].size > 0
              self.synchronize_records([(op_frame)],credential)
            end
          end
          #
          if the_records[:records].is_a?(::Array)
            if the_records[:records].size > 0
              the_records[:records].each do |the_record|
                the_record.search do |value, selector, container|
                  if selector == :version && value.is_a?(::String)
                    container[(selector)] = ::BigDecimal.new(value)
                  end
                end
              end
              self.synchronize_records([{:operation => :merge, :data => the_records[:records]}],credential)
              result = true
            end
          end
        end
        #
        result
      end
      # Class method for importing an export record as a detached structure.
      def self.detached_import(import_record=nil)
        result = nil
        unless import_record.is_any?(::Hash, ::GxG::Database::PersistedHash)
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
      # Class method to import an export package as a detached object.
      def self.detached_package_import(the_records={:formats => {}, :records => []}, options={})
        result = []
        #
        if the_records.is_a?(::Hash)
          if the_records[:formats].is_a?(::Hash)
            op_frame = {:operation => :merge_format, :data => []}
            the_records[:formats].each_pair do |the_uuid, the_format_record|
              if the_format_record[:version].is_a?(::String)
                the_format_record[:version] = ::BigDecimal.new(the_format_record[:version])
              end
              # gxg_import format content prior to sync update op
              the_format_record[:content] = ::Hash.gxg_import(the_format_record[:content])
              # Add to ::GxG::DB[:formats] ??
              unless ::GxG::DB[:formats][(the_uuid.to_s.to_sym)]
                # ?? Review : thread safety ??
                ::GxG::DB[:formats][(the_uuid.to_s.to_sym)] = the_format_record
              end
              op_frame[:data] << the_format_record
            end
            if op_frame[:data].size > 0
              ::GxG::DB[:roles][:formats].synchronize_records([(op_frame)],::GxG::DB[:administrator])
            end
          end
          #
          if the_records[:records].is_a?(::Array)
            if the_records[:records].size > 0
              the_records[:records].each do |the_record|
                the_record.search do |value, selector, container|
                  if selector == :version && value.is_a?(::String)
                    container[(selector)] = ::BigDecimal.new(value)
                  end
                end
                #
                result << ::GxG::Database::detached_import(the_record)
                #
              end
            end
          end
        end
        #
        result
      end
      #
      # ### Utility methods
      def clear_all_element_locks()
        # for when boo-boos happen
        if self.open?()
          if self.db_permissions()[:write]
            @connector[:element_locks].filter({}).delete
          end
        end
      end
      #
      # ### Various methods
      # Comm objects cannot be serialized - return encoded nil
      def serialize()
        "marshal:BAgw"
      end
      #
      # Comm objects cannot be cloned - returns nil
      def initialize_clone
        nil
      end
      alias :initialize_dup :initialize_clone
      alias :dup :initialize_clone
      def clone()
        initialize_clone
      end
      #
      def initialize(connection = nil, options={})
        # TODO: require :credential (access privs)
        super()
        @credential = nil
        @url = options[:url]
        @base_permissions = {:execute => false, :rename => false, :move => false, :destroy => false, :create => false, :write => false, :read => false}
        #
        if connection.is_a?(::Sequel::Database)
          @connector = connection
          #
          @active = false
          unless open?()
            raise Exception, "Unable to connect with the database"
          end
          # 
          @scheme = @url.scheme.to_s.to_sym
          case @scheme
          when :sqlite, :sqlite3
            @connector.run("PRAGMA page_size=65536")
            @connector.run("PRAGMA max_page_count=281474976710656")
            @connector.run("PRAGMA encoding='UTF-8'")
          when :mysql, :mysql2
            @connector.run("SET GLOBAL max_allowed_packet=17825792;")
            @connector.run("SET NAMES 'utf8' COLLATE 'utf8_general_ci';")
            @connector.run("SET collation_connection = 'utf8_general_ci';")
          when :postgres
            # place holder
          end
        else
          raise Exception, "Invalid db connection"
        end
        # characterize basic effective permissions
        begin
          formatted = db_formatted?()
          @base_permissions[:read] = true
          @base_permissions[:execute] = true
        rescue Exception => the_error
          formatted = false
          raise Exception, "Lack read permissions to the database"
        end
        #
        unless options[:read_only]
          if formatted
            begin
              dbid = @connector[:text_page].insert()
            rescue Exception => the_error
              dbid = nil
            end
            if dbid.is_a?(::Integer)
              @connector[:text_page].filter({:dbid => (dbid)}).delete
              @base_permissions[:write] = true
              @base_permissions[:create] = true
              @base_permissions[:destroy] = true
              @base_permissions[:rename] = true
              @base_permissions[:move] = true
            end
          else
            begin
              test_table_name = ::GxG::uuid_generate().gsub("-","")
              while (@connector.table_exists?(test_table_name.to_sym)) do
                test_table_name = ::GxG::uuid_generate().gsub("-","")
              end
              @connector.create_table(test_table_name.to_sym) do
                primary_key :dbid
              end
              @connector.drop_table(test_table_name.to_sym)
              @base_permissions[:write] = true
              @base_permissions[:create] = true
              @base_permissions[:destroy] = true
              @base_permissions[:rename] = true
              @base_permissions[:move] = true
            rescue Exception => the_error
              # Read-only Database
            end
          end
        end
        #
        @base_permissions.freeze
        #
        unless formatted
          if @base_permissions[:write]
            db_format
            unless db_formatted?()
              @active = false
              raise Exception, "Unable to format the database for use"
            end
          else
            raise Exception, "Unable to format a read-only database"
          end
        end
        #
        @authority = nil
        @db_list = []
        if options[:authority].is_any?(::GxG::Database::Database, ::GxG::Database::LDAPAuthority)
          @authority = options[:authority]
          @authority.db_register(self)
        end
        #
        unless @authority
          unless self.role_exist?("Administrators")
            if @base_permissions[:write]
              if self.user_id_available?("root")
                self.user_create("root","password")
                temp_cred = self.user_credential("root","password")
                temp_group = self.role_create("Administrators")
                self.role_add_user(temp_group,temp_cred)
                #
                dev_group = self.role_create("Developers")
                dsn_group = self.role_create("Designers")
                usr_group = self.role_create("Users")
                #
                self[:system_credentials] = {:administrator => temp_cred, :administrators => temp_group, :developers => dev_group, :designers => dsn_group, :users => usr_group}
                self[:permission_policy] = [{:event => :extend, :credential => :any, :action => {:extend_permissions => temp_group}}]
                #
              end
              if self.user_id_available?("public")
                self.user_create("public","password", "00000000-0000-4000-0000-000000000000")
              end
            end
          end
        end
        #
        permission_policy_load
        self
      end
      #
    end
    #
  end
  #
end
#
require File.expand_path("./gxg_database_persistedarray.rb",File.dirname(__FILE__))
require File.expand_path("./gxg_database_persistedhash.rb",File.dirname(__FILE__))
#
