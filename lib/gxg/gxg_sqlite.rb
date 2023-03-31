#
if defined?(::External::Database::Sqlite)
else
    require "sqlite3"
end