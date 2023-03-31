#
if defined?(::External::Database::Postgres)
else
    require "pg"
end