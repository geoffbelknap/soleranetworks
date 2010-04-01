## Solera Networks API Gem
## gbelknap@soleranetworks.com

# Copyright (c) 2010 Solera Networks, Inc

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

class SoleraNetworks
  attr_accessor :options

  # Constants for Humanizing File Sizes
  IS_AWESOME = 1
  GIGA_SIZE = 1073741824.0
  MEGA_SIZE = 1048576.0
  KILO_SIZE = 1024.0
  
  def initialize(options={})
    @options = {
      #
      # GEM Specific Method Paramaters
      #
      # DS Appliance Hostname / IP
      :host                 =>  '', # ie: 192.168.20.20
      # Username for Accessing API
      :user                 =>  '',
      # Password
      :pass                 =>  '',
      # Filename for returned PCAP
      :output_filename      =>  "data.pcap",
      # Type of Request URI ['pcap', 'sonar', 'applications', 'conversations', 'packetsizes', 'ipdiscovery', 'bandwidth']
      :type                 =>  'pcap',
      #
      # DeepSee API Method Parameters
      #
      :ethernet_address     =>  '', # ff:ff:ff:ff:ff:ff
      :ethernet_source      =>  '', # ff:ff:ff:ff:ff:ff
      :ethernet_destination =>  '', # ff:ff:ff:ff:ff:ff
      :ethernet_protocol    =>  '', # ipv4
      :interface            =>  '', # eth2
      :ip_protocol          =>  '', # tcp
      :ipv4_address         =>  '', # 127.0.0.1
      :ipv4_destination     =>  '', # 127.0.0.1
      :ipv4_source          =>  '', # 127.0.0.1
      :ipv6_address         =>  '', # ::ffff:127.0.0.1
      :ipv6_destination     =>  '', # ::ffff:127.0.0.1
      :ipv6_source          =>  '', # ::ffff:127.0.0.1
      :packet_length        =>  '', # 0_to_1549
      :tcp_destination_port =>  '', # 80
      :tcp_port             =>  '', # 80
      :tcp_source_port      =>  '', # 80
      # A Timespan is specified as start_time.end_time in the format of strftime('%m.%d.%Y.%I.%M.%S')
      # Default here is last 5 mins
      :timespan             =>  (Time.now.getlocal-(60*5)).strftime('%m.%d.%Y.%H.%M.%S')+"."+Time.now.getlocal.strftime('%m.%d.%Y.%H.%M.%S'),
      # :start_time           =>  (Time.now.getlocal-(60*5)).strftime('%m.%d.%Y.%H.%M.%S'),
      # :end_time             =>  Time.now.getlocal.strftime('%m.%d.%Y.%H.%M.%S'),
      :udp_destination_port =>  '', # 53
      :udp_port             =>  '', # 53
      :udp_source_port      =>  '', # 53
      :vlan_id              =>  '', # 1
    }.merge(options)
  end
  
  def uri()
    # Build Call : Long and Drawn out for ease of reading/editing
    api_call =  "https://#{@options[:host]}/ws/pcap?method=deepsee&"
    api_call += "user=#{@options[:user]}&"
    api_call += "password=#{@options[:pass]}&"
    api_call += "path=%2F"
    # Time Params
    api_call += "timespan%2F#{@options[:timespan]}%2F" unless @options[:timespan].empty?
    # Ethetnet Params
    api_call += "ethernet_address%2F#{@options[:ethernet_address]}%2F" unless @options[:ethernet_address].empty?
    api_call += "ethernet_source%2F#{@options[:ethernet_source]}%2F" unless @options[:ethernet_source].empty?
    api_call += "ethernet_destination%2F#{@options[:ethernet_destination]}%2F" unless @options[:ethernet_destination].empty?
    api_call += "ethernet_protocol%2F#{@options[:ethernet_protocol]}%2F" unless @options[:ethernet_protocol].empty?
    # Interface Params
    api_call += "interface%2F#{@options[:interface]}%2F" unless @options[:interface].empty?
    # IP Params
    api_call += "ip_protocol%2F#{@options[:ip_protocol]}%2F" unless @options[:ip_protocol].empty?
    # IPv4 Params
    api_call += "ipv4_address%2F#{@options[:ipv4_address]}%2F" unless @options[:ipv4_address].empty?
    api_call += "ipv4_source%2F#{@options[:ipv4_source]}%2F" unless @options[:ipv4_source].empty?
    api_call += "ipv4_destination%2F#{@options[:ipv4_destination]}%2F" unless @options[:ipv4_destination].empty?
    # IPv6 Params
    api_call += "ipv6_address%2F#{@options[:ipv6_address]}%2F" unless @options[:ipv6_address].empty?
    api_call += "ipv6_source%2F#{@options[:ipv6_source]}%2F" unless @options[:ipv6_source].empty?
    api_call += "ipv6_destination%2F#{@options[:ipv6_destination]}%2F" unless @options[:ipv6_destination].empty?
    # Packet Params
    api_call += "packet_length%2F#{@options[:packet_length]}%2F" unless @options[:packet_length].empty?
    # TCP Params
    api_call += "tcp_port%2F#{@options[:tcp_port]}%2F" unless @options[:tcp_port].empty?
    api_call += "tcp_source_port%2F#{@options[:tcp_source_port]}%2F" unless @options[:tcp_source_port].empty?
    api_call += "tcp_destination_port%2F#{@options[:tcp_destination_port]}%2F" unless @options[:tcp_destination_port].empty?
    # UDP Params
    api_call += "udp_port%2F#{@options[:udp_port]}%2F" unless @options[:udp_port].empty?
    api_call += "udp_source_port%2F#{@options[:udp_source_port]}%2F" unless @options[:udp_source_port].empty?
    api_call += "udp_destination_port%2F#{@options[:udp_destination_port]}%2F" unless @options[:udp_destination_port].empty?
    # VLAN Params
    api_call += "vlan_id%2F#{@options[:vlan_id]}%2F" unless @options[:vlan_id].empty?
    # Type of URI [pcap, sonar, applications, conversations, packetsizes, ipdiscovery, bandwidth]
    api_call += case @options[:type]
      when "pcap" then "data.pcap"
      when "sonar" then ";reportIndex=0"
      when "applications" then ";reportIndex=1"
      when "conversations" then ";reportIndex=2"
      when "packetsizes" then ";reportIndex=3"
      when "ipdiscovery"then ";reportIndex=4"
      when "bandwidth" then ";reportIndex=5"
      else "data.pcap"
    end
    
    return api_call  
  end

  def make_readable(size, precision)
    case
    when size == 1 : "1 Byte"
    when size < KILO_SIZE : "%d Bytes" % size
    when size < MEGA_SIZE : "%.#{precision}f KB" % (size / KILO_SIZE)
    when size < GIGA_SIZE : "%.#{precision}f MB" % (size / MEGA_SIZE)
    else "%.#{precision}f GB" % (size / GIGA_SIZE)
    end
  end

  def get_pcap(call)
    open(call, 'User-Agent' => 'Wget') {|call| @pcap = call.read}
    File.open(@options[:output_filename], 'wb') {|file| 
      file.write(@pcap) 
      puts "#{@options[:output_filename]} : " + make_readable(file.stat.size, 2)
    }
  end
end