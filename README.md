Get Snort Rule from ET (Emerging Threats)
==
This script is used to get snort rule from ET site with signature id.

Usage:
     et_rule.rb <sid>

Examples:
     et_rule.rb 2010000

Options
    -v, --version                    Display script version
    -h, --help                       Display help messages

Example)

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