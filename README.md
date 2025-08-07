GxG Framework for JRuby

Building:

jgem build ./gxg-framework.gemspec

Installation:

sudo jgem install GEMFILE

Database prep: UPDATE mysql.user SET Super_Priv="Y" WHERE user='www-data' AND host='%';