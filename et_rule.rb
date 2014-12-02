#!/usr/bin/env ruby
require 'optparse'
require 'net/http'
begin
  require 'htmlentities'
rescue LoadError
  puts "[+] htmlentities is not installed. Installing now..."
  system("gem install htmlentities --no-ri --no-rdoc")
  puts "[+] htmlentities has been installed. Run the script again"
  exit 0
end

# set the version of script
VERSION = "0.1"

class EtQuery
  def initialize(sid)
    uri = URI("http://doc.emergingthreats.net/bin/view/Main/#{sid}")
    Net::HTTP.start(uri.host, uri.port) do |http|
      request = Net::HTTP::Get.new uri
      @response = http.request request # Net::HTTPResponse object
    end
  end
  def is_response_ok?
    if @response.code == "200"
      true
    else
      false
    end
  end
  def rule_formatter(str, space)
    str = HTMLEntities.new.decode str
    # convert '(' to '(\n    '
    str = str.sub!(/\(/, "\(\n" + " "*space)
    # convert ';' to ';\n    '
    str = str.gsub!(/;\s+/, ";\n" + " "*space)
    # convert ')' to '\n)'
    str = str.sub!(/\)$/, "\n\)")
    str
  end
  def get_rule
    match = @response.body.match(/<p \/>\n(?<rule>alert.*)\n<p \/>/)
    rule_formatter match["rule"], 4
  end
end

# option parser
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage:"
  opt.separator "     #{File.basename($0)} <sid>"
  opt.separator ""
  opt.separator "Examples:"
  opt.separator "     #{File.basename($0)} 2010000"
  opt.separator ""
  opt.separator "Options"

  opt.on("-v", "--version", "Display script version") do
    puts VERSION
    exit
  end
  opt.on("-h", "--help", "Display help messages") do
    puts opt_parser
    exit
  end
end

begin
  opt_parser.parse!

  # validate argument
  if ARGV.empty?
    puts "Missing Signature ID"
    puts opt_parser #<------- print help messages
    exit 1 #<------- exit with exit code 1. check with 'echo $!' after running script
  elsif ARGV.count > 1
    puts "Too many arguments"
    puts opt_parser
    exit 2
  else
    sid = ARGV[0]
  end

rescue OptionParser::InvalidOption, OptionParser::MissingArgument
  puts $!.to_s
  puts opt_parser
  exit
end

obj = EtQuery.new(sid)
if obj.is_response_ok?
  puts obj.get_rule
end

__END__

$ ./et_rule.rb 2010000
alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (
    msg:"ET EXPLOIT xp_fileexist access";
    flow:to_server,established;
    content:"x|00|p|00|_|00|f|00|i|00|l|00|e|00|e|00|x|00|i|00|s|00|t|00|";
    nocase;
    classtype:attempted-user;
    reference:url,doc.emergingthreats.net/2010000;
    reference:url,www.emergingthreats.net/cgi-bin/cvsweb.cgi/sigs/EXPLOIT/EXPLOIT_MSSQL_Response;
    sid:2010000;
    rev:3;
)