Gem::Specification.new do |s|
  s.name        = 'gxg-framework'
  s.version     = '0.0.64'
  s.licenses    = ['HIPPOCRATIC 2.1', 'https://firstdonoharm.dev/version/2/1/license.html']
  s.summary     = "GxG Framework"
  s.description = "GxG Framework"
  s.authors     = ["G. Gibson"]
  s.email       = 'c0decafe@gmx.com'
  s.files       = ['gxg-framework.gemspec'] + ['lib/gxg-framework.rb'] + Dir['lib/gxg/*']
  s.homepage    = 'https://github.com/mistergibson/gxg-framework'
  s.metadata    = { "source_code_uri" => "https://github.com/mistergibson/gxg-framework" }
  s.require_path = "lib"
  # ### Requirements:
  s.add_runtime_dependency 'sys-cpu'
  s.add_runtime_dependency 'sys-proctable'
  s.add_runtime_dependency 'tzinfo-data'
  s.add_runtime_dependency 'tzinfo', '~> 1.1'
  s.add_runtime_dependency 'bcrypt'
  s.add_runtime_dependency 'sequel'
  s.add_runtime_dependency 'ffi'
  s.add_runtime_dependency 'chronic'
  s.add_runtime_dependency 'rufus-scheduler', '~> 3.0'
  if ::RUBY_ENGINE == "jruby"
    s.add_runtime_dependency 'jrzmq'
  else
    # FIX : big hassle with windows - exclude for now
    # s.add_runtime_dependency 'ffi-rzmq'
    # s.add_runtime_dependency 'ezmq'
  end
  s.add_runtime_dependency 'nokogiri'
  s.add_runtime_dependency 'shared-mime-info'
  s.add_runtime_dependency 'mimemagic'
  s.add_runtime_dependency 'rubysl-securerandom'
  s.add_runtime_dependency 'net-ssh'
  s.add_runtime_dependency 'net-scp'
  s.add_runtime_dependency 'net-sftp'
  s.add_runtime_dependency 'rubysl-xmlrpc'
  s.add_runtime_dependency 'handsoap'
  s.add_runtime_dependency 'rest-client'
  s.add_runtime_dependency 'gmail_xoauth'
  s.add_runtime_dependency 'mail'
  s.add_runtime_dependency 'matrix_sdk'
  s.add_runtime_dependency 'state_machines'
  s.add_runtime_dependency 'net-ldap'
  s.add_runtime_dependency 'nextcloud'
  s.add_runtime_dependency 'stanford-core-nlp'
  # ### Database Adapters:
  if ::RUBY_ENGINE == "jruby"
    s.add_runtime_dependency 'jdbc-sqlite3'
    s.add_runtime_dependency 'jdbc-mysql'
    s.add_runtime_dependency 'jdbc-postgresql'
    s.add_runtime_dependency 'jdbc-as400'
    s.add_runtime_dependency 'jdbc-cassandra'
    s.add_runtime_dependency 'jdbc-crate'
    s.add_runtime_dependency 'jdbc-derby'
    s.add_runtime_dependency 'jdbc-filemaker'
    s.add_runtime_dependency 'jdbc-firebird'
    s.add_runtime_dependency 'jdbc-h2'
    s.add_runtime_dependency 'jdbc-hive2'
    s.add_runtime_dependency 'jdbc-hsqldb'
    s.add_runtime_dependency 'jdbc-jt400'
    s.add_runtime_dependency 'jdbc-jtds'
    s.add_runtime_dependency 'jdbc-luciddb'
    s.add_runtime_dependency 'jdbc-mssql'
    s.add_runtime_dependency 'jdbc-nuodb'
    ### FIX : openedge requires external .jars in classpath -- exclude for now.
    # s.add_runtime_dependency 'jdbc-openedge'
    s.add_runtime_dependency 'jdbc-orientdb'
    s.add_runtime_dependency 'jdbc-phoenix'
    ### FIX : redshift is missing the RedshiftJDBC4.jar file -- exclude for now.
    # s.add_runtime_dependency 'jdbc-redshift'
    s.add_runtime_dependency 'jdbc-splice'
    s.add_runtime_dependency 'jdbc-vertica'
  end
end
