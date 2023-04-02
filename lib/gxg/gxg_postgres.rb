# See: https://github.com/will/crystal-pg
if defined?(::External::Database::Postgres)
else
    unless  ::RUBY_ENGINE == "jruby"
        require "pg"
    end
end