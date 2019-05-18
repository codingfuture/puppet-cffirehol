#
# Copyright 2016-2019 (c) Andrey Galkin
#

require 'json'
require 'ipaddr'
require 'digest/md5'

module CfFirehol
    FIREHOL_CONF_FILE = '/etc/firehol/firehol.conf'
    FIREHOL_META_FILE = '/etc/firehol/.firehol.json'
    FIREHOL_START_REQUIRED_FILE = '/etc/firehol/.restart_stamp'
    # Make sure to regen config, if this module changes
    GENERATOR_VERSION = Digest::MD5.hexdigest(File.read(__FILE__))

    UNROUTABLE_IPS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '224.0.0.0/4',
        '127.0.0.1/8',
        '::1/128',
        #'fe80::/10',
        'fc00::/7',
        '0100::/64',
    ]

    # TODO: avoid hardcoding?
    DOCKER_IPS = [
        # 172.16.0.0/16 - 172.19.0.0/16
        '172.16.0.0/14',
    ]

    @@unroutable_cache = nil
    @@ipset_cache = nil
    @@needs_reconf = false

    class << self
        attr_accessor :orig_metafile
        attr_accessor :orig_config
        attr_accessor :new_config

        include Puppet::Util::Logging
        Puppet::Util.logmethods(self, true)
    end

    debug("Initializing Puppet::CfFirehol")

    def self.reset_config
        debug("Reset config")
        self.orig_metafile = nil
        self.orig_config = nil
        # keep for possible re-flush()
        #self.new_config = nil
    end

    def self.read_config
        orig_config = self.orig_config
        return orig_config unless orig_config.nil?

        fhmeta = {
            'generator_version' => '',
            'custom_services' => {},
            'custom_headers' => [],
            'synproxy_public' => false,
            'ports' => {},
            'ifaces' => {},
            'ipsets' => {},
        }
        self.orig_config = fhmeta
        self.new_config = JSON.parse(JSON.generate(fhmeta.clone)) # deep clone

        return fhmeta if not File.exist?(FIREHOL_META_FILE)

        begin
            file = File.read(FIREHOL_META_FILE)
            self.orig_metafile = file
            fhread = JSON.parse(file)
            if fhread['generator_version'] != GENERATOR_VERSION
                warning('FireHOL meta config generator version mismatch: ' + fhread['generator_version'])
            end
            fhmeta.merge! fhread
            debug "Read: " + fhmeta.to_s
        rescue
        end

        self.orig_config = fhmeta
        debug('Orig config:' + fhmeta.to_s)

        fhmeta
    end
    
    def self.get_ipset(ip)
        t = ip.split(':', 2)
        
        return nil unless t[0] == 'ipset'
        
        name = t[1]
        ips = @@ipset_cache[name]
        
        fail("Unknown ipset '#{name}'") if ips.nil?
        
        return ips
    end

    def self.filter_ipv(arg, unroll_ipset=false)
        arg = [arg] unless arg.is_a? Array

        ipv4 = []
        ipv6 = []
        have_dyn = false
        arg.each do |item|
            ips = get_ipset(item)
            if ips
                type = ips[:type]

                if ips[:dynamic] and !unroll_ipset
                    ipv4 << "#{item}-#{type}4"
                    ipv6 << "#{item}-#{type}6"
                    have_dyn = true
                else
                    v4, v6 = filter_ipv(ips[:addr], unroll_ipset)
                    
                    if unroll_ipset
                        ipv4 += v4
                        ipv6 += v6
                    else
                        ipv4 << "#{item}-#{type}4" unless v4.empty?
                        ipv6 << "#{item}-#{type}6" unless v6.empty?
                    end
                end
            else
                begin
                    ip = IPAddr.new(item)
                rescue
                    begin
                        ip = IPAddr.new(Resolv.getaddress item)
                    rescue
                        begin
                            ip = IPAddr.new(Resolv.new.getaddress item)
                        rescue
                            err("Failed host: #{item}")
                            @@needs_reconf = true
                            next
                        end
                    end
                end
                ipv4 << item if ip.ipv4?
                ipv6 << item if ip.ipv6?
            end
        end
        
        ipv4.uniq!
        ipv6.uniq!

        [ipv4, ipv6, have_dyn]
    end
    
    def self.filter_ipv_arg(arg)
        ipv4, ipv6, have_dyn = filter_ipv(arg)
        [ipv4.join(' '), ipv6.join(' '), have_dyn]
    end

    def self.is_routable(addr, to_check)
        # special processing for IPsets
        ips = get_ipset(addr)
        
        if ips
            ips[:addr].each do |v|
                return true if is_routable(v, to_check)
            end
            return false
        end
        
        # plain IPs
        begin
            ip = IPAddr.new(addr)
        rescue
            begin
                ip = IPAddr.new(Resolv.getaddress addr)
            rescue
                begin
                    ip = IPAddr.new(Resolv.new.getaddress addr)
                rescue
                    err("Failed host: #{addr}")
                    @@needs_reconf = true
                    return false
                end
            end
        end

        to_check.each do |cand|
            cand = IPAddr.new(cand)

            if ip.include? cand or cand.include? ip
                return true
            end
        end

        false
    end

    def self.filter_routable(addresses, iface)
        addresses = [addresses] unless addresses.is_a? Array

        # assume routable for dynamic iface
        return [addresses, []] if iface[:address].nil?

        match = []
        reject = []
        addresses.each do |addr|
            to_check = [ iface[:address] ]
            to_check += iface[:extra_addresses] unless iface[:extra_addresses].nil?

            unless iface[:extra_routes].nil?
                iface[:extra_routes].each do |route|
                    to_check << route['network']
                end
            end

            if is_routable(addr, to_check)
                match << addr
            else
                reject << addr
            end
        end

        [match, reject]
    end

    def self.strip_mask(ip)
        addr, mask = ip.split('/', 2)
        
        if IPAddr.new(ip).to_string == IPAddr.new(addr).to_string
            # This is a wildcard address, CIDR is required
            return ip
        else
            # This is a single address
            return addr
        end
    end

    def self.is_private_iface(ifacedef)
        return false if ifacedef[:force_public]
        
        if @@unroutable_cache.nil?
            @@unroutable_cache = UNROUTABLE_IPS.map do |net|
                IPAddr.new(net)
            end
        end

        if not ifacedef[:address].nil?
            addr = IPAddr.new(ifacedef[:address])
            @@unroutable_cache.each do |net|
                return true if net.include? addr
            end
        end
        
        if not ifacedef[:extra_addresses].nil?
            ifacedef[:extra_addresses].each do |addr|
                addr = IPAddr.new(addr)
                @@unroutable_cache.each do |net|
                    return true if net.include? addr
                end
            end
        end

        false
    end
    
    def self.map_iface(iface, ifacemap, type)
        unless ifacemap.has_key? iface
            raise Puppet::DevError, "Unknown #{type} interface: #{iface}"
        end
        
        ifacemap[iface]
    end

    def self.group_ports(ports)
        groups = {}

        ungrouped = ports.uniq

        ungrouped.each { |p|
            user = (p[:user] or []).sort
            group = (p[:group] or []).sort

            gkey = "#{user.join(' ')}:#{group.join(' ')}"
            next if gkey == ':'
            grp = groups[gkey]

            if grp.nil?
                grp = groups[gkey] = {
                    user: user,
                    group: group,
                    ports: [],
                }
            end

            grp[:ports] << p
        }

        ungrouped = ungrouped.map { |p|
            user = (p[:user] or []).sort
            group = (p[:group] or []).sort

            gkey = "#{user.join(' ')}:#{group.join(' ')}"
            grp = groups[gkey]

            if !grp or grp[:ports].length < 2
                groups.delete gkey
                p
            else
                nil
            end
        }

        ungrouped.compact!

        return ungrouped, groups
    end

    def self.gen_config()
        fhmeta = self.new_config
        fhmeta['generator_version'] = GENERATOR_VERSION

        metafile = JSON.pretty_generate(fhmeta)
        if self.orig_metafile == metafile and File.exists? FIREHOL_CONF_FILE
            debug('Meta files match, no need to reconfigure')
            return false
        end
        
        @@needs_reconf = false

        notice('Regenerating: %s' % FIREHOL_CONF_FILE)
        debug('Gen config: ' + fhmeta.to_s)

        fhconf = []
        fhconf << '# This file is autogenerated by cffirehol Puppet Module'
        fhconf << '# Any changes made here may be overwritten at any time'
        fhconf << 'version 6'
        fhconf << ''
        fhconf << '# Defaults'
        fhconf << '#----------------'
        fhconf << 'DEFAULT_INTERFACE_POLICY="DROP"'
        fhconf << 'DEFAULT_ROUTER_POLICY="DROP"'
        fhconf << 'FIREHOL_LOG_MODE="NFLOG"'
        fhconf << 'FIREHOL_TRUST_LOOPBACK="0"'
        fhconf << 'FIREHOL_DROP_ORPHAN_TCP_ACK_FIN="1"'
        fhconf << 'FIREHOL_DROP_ORPHAN_TCP_ACK_RST="1"'
        fhconf << 'FIREHOL_DROP_ORPHAN_TCP_ACK="1"'
        fhconf << 'FIREHOL_DROP_ORPHAN_TCP_RST="1"'
        fhconf << 'FIREHOL_DROP_ORPHAN_IPV4_ICMP_TYPE3="1"'
        fhconf << 'FIREHOL_INPUT_ACTIVATION_POLICY="DROP"'
        fhconf << 'FIREHOL_OUTPUT_ACTIVATION_POLICY="DROP"'
        fhconf << 'FIREHOL_FORWARD_ACTIVATION_POLICY="DROP"'
        fhconf << 'FIREHOL_CONNTRACK_HELPERS_ASSIGNMENT="manual"'
        fhconf << ''

        dnat_ports = []
        iface_ports = {}
        ifaces = fhmeta['ifaces'].clone
        custom_services = fhmeta['custom_services'].clone
        router_ports = {}

        #---
        debug('>> Merging partially defined ipsets')
        @@ipset_cache = {}
        fhmeta['ipsets'].each do |n, v|
            name = n.split(':')[0]
            
            if @@ipset_cache.has_key? name
                ips = @@ipset_cache[name]
                ips[:addr] += v[:addr]
                
                if ips[:type] != v[:type]
                    warning("Ipset type mismatch for #{n}")
                end
                
                if !ips[:dynamic] and v[:dynamic]
                    warning("Ipset dynamic mismatch for #{n}")
                end
            else
                @@ipset_cache[name] = v.clone
            end
        end
        
        #---
        debug('>> Creating iface map for merging')
        have_docker = ifaces.has_key? 'docker'
        #dev2main = {}
        iface_map = {}
        iface_dst = {}
        ifaces.keys.each do | iface |
            ifacedef = ifaces[iface]
            dev = ifacedef[:device]
            
            iface_addr = []
            
            if ifacedef[:method].to_s != 'dhcp'
                if not ifacedef[:address].nil?
                    iface_addr << ifacedef[:address]
                end
                
                if not ifacedef[:extra_addresses].nil?
                    iface_addr += ifacedef[:extra_addresses]
                end
                
                iface_addr.map! { |v| strip_mask v }
                iface_addr.uniq!
            end
            
            iface_dst[iface] = iface_addr
            
            <<-COMMENT
            # merge of ifaces would need to force dst on every rule
            # let's define several interfaces for one device with
            # common overall dst rule
            if dev2main.has_key? dev
                mainface = dev2main[dev]
                iface_map[iface] = mainface
                
                maindef = ifaces[mainface]

                maindef[:gateway] ||= ifacedef[:gateway]
                
                if not iface_addr.empty?
                    if maindef[:extra_addresses].nil?
                        maindef[:extra_addresses] = iface_addr
                    else
                        maindef[:extra_addresses] += iface_addr
                    end
                end

                ifaces.delete iface
            else
                dev2main[dev] = iface
                iface_map[iface] = iface
            end
            COMMENT
            iface_map[iface] = iface
        end

        #---
        ifaces['local'] = {
            :device => 'lo',
            :address => '127.0.0.1/8',
            :extra_addresses => ['::1/128']
        }
        iface_lo = ifaces['local']
        iface_map['local'] = 'local'
        iface_dst['local'] = [ iface_lo[:address] ] + iface_lo[:extra_addresses]

        debug('>> Populating local iface')
        ifaces.each do | iface, ifacedef |
            next if iface == 'local'
            
            # make sure gateway ifaces a always first in router pairs
            unless ifacedef[:gateway].nil?
                router_ports[iface] = {}
            end

            # make sure we found routes to self through lo
            unless ifacedef[:address].nil?
                iface_lo[:extra_addresses] << strip_mask(ifacedef[:address])
            end
            unless ifacedef[:extra_addresses].nil?
                ifacedef[:extra_addresses].each do |addr|
                    iface_lo[:extra_addresses] << strip_mask(addr)
                end
            end
        end
        
        debug(">>> Ifaces: #{ifaces}")

        debug('>> Processing port configuration')
        fhmeta['ports'].each do |portname, portdef|
            port_type, iface, service, comment = portname.split(':')

            weight = '100'
            weight, port_type = port_type.split('#') if port_type.include? ('#')
            weight = weight.to_i

            port_type = 'server' if port_type == 'service'

            if comment.nil?
                comment = portdef[:comment]
            else
                comment = comment + ': ' + (portdef[:comment] || '')
            end

            if port_type == 'dnat'
                if not custom_services.has_key?(service)
                    raise Puppet::DevError, "DNAT service must be defined as custom_service: #{service}"
                end

                if portdef[:to_dst].nil?
                    raise Puppet::DevError, "DNAT port must set to_dst property: #{service}"
                end

                inface, outface = iface.split('/')
                
                inface = map_iface(inface, iface_map, 'DNAT inface')
                outface = map_iface(outface, iface_map, 'DNAT outface')
                
                dnat_ports << portdef.merge({
                    :iface => inface,
                    :port_type => 'server',
                    :service => service,
                    :comment => comment,
                    :dnat_port => true,
                })
                

                # see cfnetwork::dnat_port type definition
                if not portdef[:to_port].nil?
                    to_port = portdef[:to_port].to_s
                    newservice = custom_services[service].clone
                    server_ports = newservice[:server_ports]
                    server_ports = [server_ports] unless server_ports.is_a? Array

                    newservice[:server_ports] = []
                    server_ports.each do |port|
                        newservice[:server_ports] << port.split('/')[0] + '/' + to_port
                    end

                    custom_services[service + '_' + to_port] = newservice
                end
                next
            end

            if port_type == 'router'
                inface, outface = iface.split('/')
                infaces = []
                outfaces = []
                msrc = portdef[:src]
                mdst = portdef[:dst]
                allifaces = ifaces.keys - ['local']
                gwifaces = ifaces.select do |k, v| not v[:gateway].nil? end

                if inface == 'any'
                    if msrc.nil? or msrc.empty?
                        infaces += allifaces
                    else
                        found = false

                        ifaces.each do |ifk, ifv|
                            next if ifk == 'local'
                            routable, unroutable = filter_routable(msrc, ifv)
                            if not routable.empty?
                                infaces << ifk
                                found = true
                            end
                        end

                        if not found
                            infaces += gwifaces.keys
                        end
                    end
                else
                    inface = map_iface(inface, iface_map, 'router inface')
                    infaces << inface
                end

                if outface == 'any'
                    if mdst.nil? or mdst.empty?
                        outfaces += allifaces
                    else
                        found = false

                        ifaces.each do |ifk, ifv|
                            next if ifk == 'local'
                            routable, unroutable = filter_routable(mdst, ifv)
                            if not routable.empty?
                                outfaces << ifk
                                found = true
                            end
                        end

                        if not found
                            outfaces += gwifaces.keys
                        end
                    end
                else
                    outface = map_iface(outface, iface_map, 'router outface')
                    outfaces << outface
                end
                
                # just in case
                infaces.uniq!
                outfaces.uniq!

                infaces.each do |inface|
                    outfaces.each do |outface|
                        # avoid creating reverse routers which never get reached
                        # NOTE: ordering is very important for FW rule reachability
                        if router_ports.has_key?(inface) and router_ports[inface].has_key?(outface)
                            port_type = 'server'
                        elsif router_ports.has_key?(outface) and router_ports[outface].has_key?(inface)
                            port_type = 'client'
                        elsif not ifaces[outface][:gateway].nil?
                            # prefer gateway to be the first
                            port_type = 'client'
                        else
                            port_type = 'server'
                        end

                        if port_type == 'client'
                            minface, moutface = outface, inface
                        else
                            minface, moutface = inface, outface
                        end

                        router_ports[minface] ||= {}
                        router_ports[minface][moutface] ||= []

                        router_ports[minface][moutface] << portdef.merge({
                            :port_type => port_type,
                            :service => service,
                            :comment => comment,
                        })
                    end
                end
                next
            end

            # filter by routable dst for client and src for server, if set
            if iface == 'any'
                gdst_match = []
                gsrc_match = []
                gportfdef = []
                ifaces.each do |iface, ifacedef|
                    iface_ports[iface] ||= []
                    msrc = portdef[:src]
                    mdst = portdef[:dst]
                    leafface = ifacedef[:gateway].nil? || ifacedef[:gateway].empty?
                    dynface = ifacedef[:address].nil? || ifacedef[:address].empty?

                    if dynface
                        # noop in routable filter
                    elsif not leafface
                        # postpone constraint reduction for gateway facing
                    elsif port_type == 'client' and !mdst.nil? and !mdst.empty?
                        mdst, rdst = filter_routable(mdst, ifacedef)
                        next if mdst.empty?
                        gdst_match += mdst
                    elsif port_type == 'server' and !msrc.nil? and !msrc.empty?
                        msrc, rsrc = filter_routable(msrc, ifacedef)
                        next if msrc.empty?
                        gsrc_match += msrc
                    end

                    port_override = portdef.merge({
                        :port_type => port_type,
                        :service => service,
                        :src => msrc,
                        :dst => mdst,
                        :comment => comment
                    })

                    if leafface
                        iface_ports[iface] << port_override
                    else
                        gportfdef << {
                            :iface => iface,
                            :ifacedef => ifacedef,
                            :portdef => port_override
                        }
                    end
                end

                gportfdef.each do |gdef|
                    iface = gdef[:iface]
                    ifacedef = gdef[:ifacedef]
                    port_override = gdef[:portdef]

                    unless gdst_match.empty?
                        mdst = port_override[:dst].clone
                        _, gdst_unroutable_match = filter_routable(gdst_match, ifacedef)
                        mdst -= gdst_unroutable_match
                        next if mdst.empty?
                        port_override[:dst] = mdst
                    end

                    unless gsrc_match.empty?
                        msrc = port_override[:src].clone
                        _, gsrc_unroutable_match = filter_routable(gsrc_match, ifacedef)
                        msrc -= gsrc_unroutable_match
                        next if msrc.empty?
                        port_override[:src] = msrc
                    end

                    iface_ports[iface] << port_override
                end
                next
            end

            # default
            iface = map_iface(iface, iface_map, port_type)
            iface_ports[iface] ||= []
            iface_ports[iface] << portdef.merge({
                :port_type => port_type,
                :service => service,
                :comment => comment
            })
        end
        debug(">>> Iface Ports: #{iface_ports}")
        debug(">>> Router Ports: #{router_ports}")
        
        #==============================
        debug('>> Creating custom services')
        fhconf << '# Custom Services'
        fhconf << '#----------------'

        custom_services.each do |k, v|
            server_ports = v[:server_ports]
            server_ports = server_ports.join(' ') if server_ports.is_a? Array
            client_ports = v[:client_ports]
            client_ports = client_ports.join(' ') if client_ports.is_a? Array
            comment = v[:comment]
            if comment
                fhconf << '# ' + comment.sub("\n", ' ')
            end
            fhconf << %Q{server_#{k}_ports="#{server_ports}"}
            fhconf << %Q{client_#{k}_ports="#{client_ports}"}
            fhconf << ''
        end

        debug('>> Creating ipsets')
        fhconf << '# Setup of ipsets'
        fhconf << '#----------------'
        ['dynblacklist', 'blacklist', 'whitelist'].each do |n|
            fail("Missing ipset #{n}") unless @@ipset_cache.has_key? n
        end
        
        @@ipset_cache.each do |name, ips|
            comment = ips[:comment]
            if comment
                fhconf << '# ' + comment.sub("\n", ' ')
            end
                
            ips4, ips6 = filter_ipv(ips[:addr], true)
            type = ips[:type]
            
            fhconf << %Q{ipset4 create #{name}-#{type}4 hash:#{type}}
            
            ips4.each do |ip|
                fhconf << %Q{  ipset add #{name}-#{type}4 "#{ip}"}
            end

            fhconf << %Q{ipset6 create #{name}-#{type}6 hash:#{type}}
            
            ips6.each do |ip|
                fhconf << %Q{  ipv6 ipset add #{name}-#{type}6 "#{ip}"}
            end
            fhconf << ''
        end
        
        # Large dynamic blacklist
        fhconf << %Q{ipset4 addfile dynblacklist-net4 dynblacklist4.netset}
        fhconf << %Q{ipset6 addfile dynblacklist-net6 dynblacklist6.netset}

        fhconf << ''

        debug('>> Protecting public interfaces')
        fhconf << '# Protection on public-facing interfaces'
        fhconf << '#----------------'
        snat_processed = Set.new
        ifaces.each do |iface, ifacedef|
            dev = ifacedef[:device]

            if is_private_iface(ifacedef)
                # NOTE: this is more like a dirty hack, but default DOCKER chain
                #       management is quite loose.
                next if not have_docker
                next if iface.start_with? 'docker'
                next if iface == 'local'
                # SNAT is based on physical devices
                next unless snat_processed.add? dev

                DOCKER_IPS.each { |net|
                    cmd = %Q{iptables -t nat -A POSTROUTING -o "#{dev}"}
                    cmd += %Q{ -s '#{net}'}
                    cmd += %Q{ -j MASQUERADE}
                    fhconf << cmd
                }
                next
            end

            fhconf << %Q{# Iface: #{iface}}
            fhconf << '#---'

            # unroutable
            routable, unroutable = filter_routable(UNROUTABLE_IPS, ifacedef)
            routable4, routable6 = filter_ipv(routable)
            unroutable4, unroutable6 = filter_ipv(unroutable)
            
            unless unroutable4.empty?
                fhconf << %Q{iptables -t raw -N cfunroute_#{iface}}
                unroutable4.each do |net|
                    fhconf << %Q{iptables -t raw -A cfunroute_#{iface} -s "#{net}" -j DROP}
                    fhconf << %Q{iptables -t raw -A cfunroute_#{iface} -d "#{net}" -j DROP}
                end
                fhconf << %Q{iptables -t raw -A PREROUTING -i "#{dev}" -j cfunroute_#{iface}}
            end
            
            unless unroutable6.empty?
                fhconf << %Q{ip6tables -t raw -N cfunroute_#{iface}}
                unroutable6.each do |net|
                    fhconf << %Q{ip6tables -t raw -A cfunroute_#{iface} -s "#{net}" -j DROP}
                    fhconf << %Q{ip6tables -t raw -A cfunroute_#{iface} -d "#{net}" -j DROP}
                end
                fhconf << %Q{ip6tables -t raw -A PREROUTING -i "#{dev}" -j cfunroute_#{iface}}
            end

            # Blacklist
            fhconf << %Q{blacklist4 statefull inface "#{dev}" "ipset:blacklist-net4 ipset:dynblacklist-net4" except src "#{routable4.join(' ')} ipset:whitelist-net4"}
            fhconf << %Q{blacklist6 statefull inface "#{dev}" "ipset:blacklist-net6 ipset:dynblacklist-net6" except src "#{routable6.join(' ')} ipset:whitelist-net6"}

            # synproxy
            if fhmeta['synproxy_public']
                synproxy_candidates = iface_ports[iface] or []
                synproxy_candidates += dnat_ports.select do |v| v[:iface] == iface end
                # TODO: router_ports that not DNAT-related
                synproxy_candidates.each do |portdef|
                    next if portdef[:port_type] != 'server'

                    service_name = portdef[:service]
                    service = custom_services[service_name]

                    if service.nil?
                        warning("Synproxy requires a described service: " + service_name)
                        next
                    end

                    server_ports = service[:server_ports]
                    server_ports = [server_ports] unless server_ports.is_a? Array

                    src = portdef[:src] || []
                    src4, src6 = filter_ipv_arg(src)

                    to_port = portdef[:to_port] || nil
                    to_port = ':' + to_port.to_s if not to_port.nil?

                    comment = portdef[:comment]
                    if comment
                        fhconf << '# ' + comment.sub("\n", ' ')
                    end

                    if portdef[:dst].nil? or portdef[:dst].empty?
                        dst = []
                        dst << ifacedef[:address] unless ifacedef[:address].nil?
                        dst += ifacedef[:extra_addresses] unless ifacedef[:extra_addresses].nil?

                        if dst.empty?
                            warning("SYNPROXY requires that dst is set either explicitly " +
                                    "or through iface static address: " + portdef.to_s)
                            next
                        end

                        dst.map! { |v| strip_mask v }

                        dst4, dst6 = filter_ipv_arg(dst)
                    else
                        dst4, dst6 = filter_ipv_arg(portdef[:dst])
                    end

                    if portdef.has_key? :dnat_port
                        to4, to6 = filter_ipv_arg(portdef[:to_dst])
                        # NAT still uses input
                        synproxy_type = 'input'
                        #synproxy_type = 'forward'
                        synproxy_action4 = nil
                        synproxy_action6 = nil
                        synproxy_action4 = %Q{dnat to "#{to4}#{to_port}"} unless to4.empty?
                        synproxy_action6 = %Q{dnat to "#{to6}#{to_port}"} unless to6.empty?
                        portdef[:synproxy] = true
                    else
                        synproxy_type = 'input'
                        synproxy_action4 = 'accept'
                        synproxy_action6 = 'accept'
                    end

                    server_ports.each do |p|
                        proto, dport = p.split('/')
                        next unless proto == 'tcp'

                        if !dst4.empty? and (src4.empty? == src.empty?) and !synproxy_action4.nil?
                            cmd = %Q{synproxy4 #{synproxy_type} inface #{dev} dst "#{dst4}" dport "#{dport}"}
                            cmd += %Q{ src "#{src4}"} unless src4.empty?
                            cmd += %Q{ #{synproxy_action4}}
                            fhconf << cmd
                        end
                        if !dst6.empty? and (src6.empty? == src.empty?) and !synproxy_action6.nil?
                            cmd = %Q{synproxy6 #{synproxy_type} inface #{dev} dst "#{dst6}" dport "#{dport}"}
                            cmd += %Q{ src "#{src6}"} unless src6.empty?
                            cmd += %Q{ #{synproxy_action6}}
                            fhconf << cmd
                        end
                    end
                end
            end

            # SNAT is based on physical devices
            next unless snat_processed.add? dev

            snat_addresses = []

            ifaces.each { |_, v|
                next if dev != v[:device]
                snat_addresses << v[:address] unless v[:address].nil?
                snat_addresses += v[:extra_addresses] unless v[:extra_addresses].nil?
            }

            snat_addr4_list, _ = filter_ipv(snat_addresses)

            # SNAT / MASQUERADE
            if snat_addr4_list.empty? or snat_addr4_list[0] == strip_mask(snat_addr4_list[0])
                fhconf << %Q{iptables -t nat -A POSTROUTING -o "#{dev}" -j MASQUERADE}
            else
                snat_addr4_list.map! do |item| strip_mask item end # strip mask
                address = snat_addr4_list[0]

                snat_addr4_list = snat_addr4_list.join(',')
                fhconf << %Q{iptables -t nat -N cfpost_snat_#{dev}}
                fhconf << %Q{iptables -t nat -A cfpost_snat_#{dev} -s #{snat_addr4_list} -j RETURN}
                fhconf << %Q{iptables -t nat -A cfpost_snat_#{dev} -j SNAT --to-source=#{address}}
                fhconf << %Q{iptables -t nat -A POSTROUTING -o "#{dev}" -j cfpost_snat_#{dev}}

                fhconf << %Q{ip6tables -t nat -A POSTROUTING -o "#{dev}" -j MASQUERADE}
            end
            fhconf << ''
        end
        fhconf << ''

        debug('>> Adding NAT')
        fhconf << '# NAT'
        fhconf << '#----------------'
        dnat_ports.each do |v|
            next if v[:synproxy]
            
            iface = v[:iface]
            service = v[:service]

            if iface != 'any'
                dev = ifaces[iface][:device]
                inface = %Q{inface "#{dev}"}
            else
                inface = ''
            end
            src = v[:src] || []
            dst = v[:dst] || []
            src4, src6 = filter_ipv_arg(src)
            dst4, dst6 = filter_ipv_arg(dst)
            to4, to6 = filter_ipv_arg(v[:to_dst])

            to_port = v[:to_port] || nil
            to_port = ':' + to_port.to_s if not to_port.nil?

            comment = v[:comment]
            if comment
                fhconf << '# ' + comment.sub("\n", ' ')
            end

            server_ports = custom_services[service][:server_ports]
            server_ports = [server_ports] unless server_ports.is_a? Array
            curr_iface_dst = iface_dst[iface]

            if !to4.empty? and (src4.empty? == src.empty?) and  (dst4.empty? == dst.empty?)
                server_ports.each do |p|
                    proto, dport = p.split('/')
                    dst4, ignore = filter_ipv_arg(curr_iface_dst) if dst4.empty? and curr_iface_dst
                    
                    warning("Missing dst (IPv4) for #{iface} DNAT") if dst4.empty?

                    cmd = %Q{dnat4 to "#{to4}#{to_port}" #{inface} proto "#{proto}" dport "#{dport}"}
                    cmd += %Q{ dst "#{dst4}"} unless dst4.empty?
                    cmd += %Q{ src "#{src4}"} unless src4.empty?
                    fhconf << cmd
                end
            end

            if !to6.empty? and (src6.empty? == src.empty?) and  (dst6.empty? == dst.empty?)
                server_ports.each do |p|
                    proto, dport = p.split('/')
                    ignore, dst6 = filter_ipv_arg(curr_iface_dst) if dst6.empty? and curr_iface_dst
                    
                    warning("Missing dst (IPv6) for #{iface} DNAT") if dst6.empty?
                    
                    cmd = %Q{dnat6 to "#{to6}#{to_port}" #{inface} proto "#{proto}" dport "#{dport}"}
                    cmd += %Q{ dst "#{dst6}"} unless dst6.empty?
                    cmd += %Q{ src "#{src6}"} unless src6.empty?
                    fhconf << cmd
                end
            end
        end
        fhconf << ''

        debug('>> Adding custom headers')
        fhconf << '# Custom Headers'
        fhconf << '#----------------'
        fhconf << fhmeta['custom_headers'].join("\n")
        fhconf << ''

        debug('>> Adding IPv6 essentials')
        fhconf << ''
        fhconf << '# IPv6 interop essentials'
        fhconf << '#----------------'
        fhconf << 'ipv6 interface any ipv6interop proto icmpv6'
        fhconf << '    client6 ipv6neigh accept'
        fhconf << '    server6 ipv6neigh accept'
        fhconf << '    policy return'
        fhconf << ''
        
        debug('>> Adding interfaces')
        fhconf << '# Interfaces'
        fhconf << '#----------------'
        iface_ports.each do |iface, ports|
            if !is_private_iface(ifaces[iface]) and !iface_dst[iface].empty?
                warning("'#{iface}' iface is public => packets can arrive on any interface")
                dev = 'any'
            elsif ifaces.has_key?(iface)
                dev = ifaces[iface][:device]
            else
                # 'any' should be distributed across ifaces
                warning("Unknown iface: " + iface.to_s)
                warning("Ports: " + ports.to_s)
                next
            end
            
            dst = ''
            interface = 'interface'
            iface_ipv4 = true
            iface_ipv6 = true
            accept_unknown_rst = false
            accept_root_ack = false
            
            if dev != 'lo'
                dst4, dst6 = filter_ipv_arg(iface_dst[iface])
                
                if !dst4.empty? and !dst6.empty?
                    interface = 'interface46'
                    dst = %Q{ dst4 "#{dst4}" dst6 "#{dst6}"}
                elsif dst4.empty? and !dst6.empty?
                    interface = 'interface6'
                    dst = %Q{ dst "#{dst6}"}
                    iface_ipv4 = false
                elsif !dst4.empty? and dst6.empty?
                    interface = 'interface4'
                    dst = %Q{ dst "#{dst4}"}
                    iface_ipv6 = false
                end
            end

            fhconf << %Q{#{interface} "#{dev}" "#{iface}"#{dst}}

            if dev == 'lo'
                fhconf << %Q{    policy reject with port-unreach}
                fhconf << %Q{    client4 icmp accept} if iface_ipv4
                fhconf << %Q{    server4 icmp accept} if iface_ipv4
                fhconf << %Q{    client6 icmpv6 accept} if iface_ipv6
                fhconf << %Q{    server6 icmpv6 accept} if iface_ipv6
                accept_unknown_rst = true
            elsif is_private_iface ifaces[iface]
                fhconf << %Q{    policy reject with port-unreach}
                fhconf << %Q{    client4 icmp accept} if iface_ipv4
                fhconf << %Q{    server4 icmp accept} if iface_ipv4
                fhconf << %Q{    client6 icmpv6 accept} if iface_ipv6
                fhconf << %Q{    server6 icmpv6 accept} if iface_ipv6
                accept_unknown_rst = true
            else
                fhconf << %Q{    policy deny}
                fhconf << %Q{    protection bad-packets}
                fhconf << %Q{    client4 icmp accept} if iface_ipv4
                fhconf << %Q{    client6 icmpv6 accept} if iface_ipv6

                fhconf << %Q{    server4 ping accept with hashlimit P4 upto 1/s burst 2} if iface_ipv4
                fhconf << %Q{    server6 ping accept with hashlimit P6 upto 1/s burst 2} if iface_ipv6
            end

            ungrouped, groups = group_ports(ports)

            ungrouped.each do |p|
                config_port(fhconf, p, {
                    do_uidgid: true,
                    iface_ipv4: iface_ipv4,
                    iface_ipv6: iface_ipv6,
                })
            end

            groups.each do |k, g|
                cmd_cond = ''
                user = (g[:user] or []).join(' ')
                group = (g[:group] or []).join(' ')

                cmd_cond += %Q{ uid "#{user}"} unless user.empty?
                cmd_cond += %Q{ gid "#{group}"} unless group.empty?
                accept_root_ack = true unless user.empty? and group.empty?

                fhconf << ''
                fhconf << %Q{    group with#{cmd_cond}}

                g[:ports].each do |p|
                    config_port(fhconf, p, {
                        iface_ipv4: iface_ipv4,
                        iface_ipv6: iface_ipv6,
                        indent: ( ' ' * 8 ),
                    })
                end

                fhconf << %Q{    group end}
            end

            fhconf << ''

            if accept_unknown_rst
                fhconf << '    # prevent noise & local connection timeouts'
                fhconf << %Q{    iptables -A in_#{iface} -p tcp --tcp-flags RST RST -j ACCEPT} if iface_ipv4
                fhconf << %Q{    iptables -A out_#{iface} -p tcp --tcp-flags RST RST -j ACCEPT} if iface_ipv4
                fhconf << %Q{    ip6tables -A in_#{iface} -p tcp --tcp-flags RST RST -j ACCEPT} if iface_ipv6
                fhconf << %Q{    ip6tables -A out_#{iface} -p tcp --tcp-flags RST RST -j ACCEPT} if iface_ipv6
                fhconf << ''
            end

            if accept_root_ack
                fhconf << '    # owner/group matches ACKs may be sent from system in some cases'
                fhconf << %Q{    iptables -A out_#{iface} -p tcp --tcp-flags ACK ACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT} if iface_ipv4
                fhconf << %Q{    ip6tables -A out_#{iface} -p tcp --tcp-flags ACK ACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT} if iface_ipv6
                fhconf << ''
            end
        end
        fhconf << ''

        debug('>> Adding routers')
        fhconf << '# Routers'
        fhconf << '#----------------'
        router_ports.each do |inface, infacedef|
            if ifaces.has_key?(inface)
                dev = ifaces[inface][:device]
                indev = 'inface "%s"' % dev
                inprivate = is_private_iface ifaces[inface]
            else
                warning("Unknown inface: " + inface.to_s)
                next
            end

            infacedef.each do |outface, outfacedef|
                if outface == 'any'
                    outdev = ''
                    outprivate = false
                elsif ifaces.has_key?(outface)
                    dev = ifaces[outface][:device]
                    outdev = 'outface "%s"' % dev
                    outprivate = is_private_iface ifaces[outface]
                else
                    warning("Unknown outface: " + outface.to_s)
                    next
                end

                fhconf << %Q{router "#{inface}_#{outface}" #{indev} #{outdev}}
                if inprivate and outprivate
                    fhconf << %Q{    policy reject}
                else
                    fhconf << %Q{    policy drop}
                end
                if inprivate
                    fhconf << %Q{    server4 icmp accept}
                    fhconf << %Q{    server6 icmpv6 accept}
                end
                if outprivate
                    fhconf << %Q{    client4 icmp accept}
                    fhconf << %Q{    client6 icmpv6 accept}
                end

                outfacedef.each do |p|
                    config_port(fhconf, p, {})
                end
                fhconf << ''
            end
        end
        fhconf << ''

        #
        if @@needs_reconf
            fhmeta['needs_reconf'] = true
            metafile = JSON.pretty_generate(fhmeta)
        end

        # Write New FireHOL conf
        #---
        debug('>> Writing files')
        conftmp = FIREHOL_CONF_FILE + ".#{$$}"
        fhconf = fhconf.join("\n")
        File.open(conftmp, 'w+', 0600 ) do |f|
            f.write(fhconf)
        end

        # Write registry file
        #---
        metatmp = FIREHOL_META_FILE + ".#{$$}"

        File.open(metatmp, 'w+', 0600 ) do |f|
            f.write(metafile)
        end

        # Move tmp files to their location
        #---
        File.rename(conftmp, FIREHOL_CONF_FILE)
        File.rename(metatmp, FIREHOL_META_FILE)
        true
    end


    def self.config_port(fhconf, p, opt)
        service = p[:service]
        port_type = p[:port_type]
        indent = opt.fetch(:indent, (' ' * 4) )
        src = p[:src] || []
        dst = p[:dst] || []
        cmd_cond = ''

        if opt.fetch(:do_uidgid, false)
            user = (p[:user] or []).join(' ')
            group = (p[:group] or []).join(' ')

            cmd_cond += %Q{ uid "#{user}"} unless user.empty?
            cmd_cond += %Q{ gid "#{group}"} unless group.empty?
        end

        comment = p[:comment]
        if comment
            fhconf << %Q{#{indent}\##{comment.sub("\n", ' ')}}
        end

        if src.empty? and dst.empty?
            cmd = %Q{#{indent}#{port_type} "#{service}" accept}
            cmd += cmd_cond
            fhconf << cmd
        else
            src4, src6, dyn_src = filter_ipv_arg(src)
            dst4, dst6 = filter_ipv_arg(dst)
            
            if opt.fetch(:iface_ipv4, true) and \
                !(src4.empty? and dst4.empty?) and \
                (src4.empty? == src.empty?) and \
                (dst4.empty? == dst.empty?)
            then
                cmd = %Q{#{indent}#{port_type}4 "#{service}" accept}
                cmd += %Q{ dst "#{dst4}"} unless dst4.empty?
                cmd += %Q{ src "#{src4}"} unless src4.empty?
                cmd += cmd_cond
                fhconf << cmd
                
                if dyn_src
                    cmd = %Q{#{indent}#{port_type}4 "#{service}" accept}
                    cmd += %Q{ dst "#{dst4}"} unless dst4.empty?
                    cmd += %Q{ custom "-m conntrack --ctstate ESTABLISHED"}
                    cmd += cmd_cond
                    fhconf << cmd
                end
            end
            
            if opt.fetch(:iface_ipv6, true) and \
                !(src6.empty? and dst6.empty?) and \
                (src6.empty? == src.empty?) and \
                (dst6.empty? == dst.empty?)
            then
                cmd = %Q{#{indent}#{port_type}6 "#{service}" accept}
                cmd += %Q{ dst "#{dst6}"} unless dst6.empty?
                cmd += %Q{ src "#{src6}"} unless src6.empty?
                cmd += cmd_cond
                fhconf << cmd
                
                if dyn_src
                    cmd = %Q{#{indent}#{port_type}6 "#{service}" accept}
                    cmd += %Q{ dst "#{dst6}"} unless dst6.empty?
                    cmd += %Q{ custom "-m conntrack --ctstate ESTABLISHED"}
                    cmd += cmd_cond
                    fhconf << cmd
                end
            end
        end
    end
end
