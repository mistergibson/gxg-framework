# See: https://github.com/crystal-lang/crystal-mysql
if defined?(::External::Database::Mysql)
else
    unless  ::RUBY_ENGINE == "jruby"
        require "mysql2"
    end
end