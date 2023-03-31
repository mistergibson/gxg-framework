#
if defined?(::External::Database::Mysql)
else
    require "mysql2"
end