# See: https://github.com/crystal-lang/crystal-sqlite3
# See: http://sequel.jeremyevans.net/documentation.html
# See: https://github.com/jeremyevans/sequel
if defined?(::External::Database::Sqlite)
else
    unless  ::RUBY_ENGINE == "jruby"
        require "sqlite3"
    end
end