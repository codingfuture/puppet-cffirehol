require 'json'
require 'ipaddr'
require 'digest/md5'

module CfFirehol
    FIREHOL_CONF_FILE = '/etc/firehol/firehol.conf'
    FIREHOL_META_FILE = '/etc/firehol/.firehol.json'
    # gen version based on actual generator hash
    GENERATOR_VERSION = Digest::MD5.hexdigest(File.read(__FILE__))

    UNROUTABLE_IPS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '224.0.0.0/4',
        '127.0.0.1/8',
    ]

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
            'ip_whitelist' => [],
            'ip_blacklist' => [],
            'synproxy_public' => false,
            'ports' => {},
            'ifaces' => {},
        }
        self.orig_config = fhmeta
        self.new_config = fhmeta.clone

        return fhmeta if not File.exist?(FIREHOL_META_FILE)

        begin
            file = File.read(FIREHOL_META_FILE)
            self.orig_metafile = file
            fhread = JSON.parse(file)
            if fhread['generator_version'] != GENERATOR_VERSION
                warning('FireHOL meta config generator version mismatch: ' + fhread['generator_version'])
            else
                fhmeta.merge! fhread
            end
            debug "Read: " + fhmeta.to_s
        rescue
        end

        self.orig_config = fhmeta
        debug('Orig config:' + fhmeta.to_s)

        fhmeta
    end

    def self.filter_ipv(arg)
        arg = [arg] unless arg.is_a? Array
        return ['', ''] if arg.empty?

        ipv4 = []
        ipv6 = []
        arg.each do |v|
            ip = IPAddr.new(v)
            ipv4 << v if ip.ipv4?
            ipv6 << v if ip.ipv6?
        end
        [ ipv4.join(' '), ipv6.join(' ') ]
    end

    def self.is_routable(ip, to_check)
        to_check.each do |cand|
            cand = IPAddr.new(cand)

            if ip.include? cand or cand.include? ip
                return true
            end
        end

        false
    end

    def self.filter_routable(addresses, iface)
        # assume routable for dynamic iface
        return addresses if iface[:address].nil?

        match = []
        reject = []
        addresses = [addresses] unless addresses.is_a? Array
        addresses.each do |addr|
            ip = IPAddr.new(addr)
            to_check = [ iface[:address] ]
            to_check += iface[:extra_addresses] unless iface[:extra_addresses].nil?

            unless iface[:extra_routes].nil?
                iface[:extra_routes].each do |route|
                    to_check << route['network']
                end
            end

            if is_routable(ip, to_check)
                match << addr
            else
                reject << addr
            end
        end

        [match, reject]
    end

    def self.strip_mask(ip)
        return ip.gsub(/\/[0-9]+$/, '')
    end

    def self.is_private_iface(ifacedef)
        return false if ifacedef[:force_public]

        addr = IPAddr.new(ifacedef[:address])
        UNROUTABLE_IPS.each do |net|
            return true if IPAddr.new(net).include? addr
        end

        false
    end

    def self.gen_config()
        fhmeta = self.new_config
        fhmeta['generator_version'] = GENERATOR_VERSION

        metafile = JSON.pretty_generate(fhmeta)
        if self.orig_metafile == metafile
            debug('Meta files match, no need to reconfigure')
            return false
        end

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
        fhconf << 'FIREHOL_INPUT_ACTIVATION_POLICY="DROP"'
        fhconf << 'FIREHOL_OUTPUT_ACTIVATION_POLICY="DROP"'
        fhconf << 'FIREHOL_FORWARD_ACTIVATION_POLICY="DROP"'
        fhconf << ''


        dnat_ports = []
        iface_ports = {}
        ifaces = fhmeta['ifaces'].clone
        custom_services = fhmeta['custom_services'].clone
        router_ports = {}

        ifaces['local'] = {
            :device => 'lo',
            :address => '127.0.0.1/8',
            :extra_addresses => []
        }
        iface_lo = ifaces['local']

        ifaces.each do | iface, ifacedef |
            # make sure gateway ifaces a always first in router pairs
            unless ifacedef[:gateway].nil?
                router_ports[iface] = {}
            end

            # make sure we found routes to self through lo
            unless ifacedef[:address].nil?
                iface_lo[:extra_addresses] << ifacedef[:address]
            end
            unless ifacedef[:extra_addresses].nil?
                iface_lo[:extra_addresses] += ifacedef[:extra_addresses]
            end
        end
        iface_lo[:extra_addresses].map! do |item| strip_mask item end

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
                    raise Puppet::DevError, "DNAT port must set to_dst property: #{k}"
                end

                inface, outface = iface.split('/')
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
                gwifaces = ifaces.select do |k, v| not v[:gateway].nil? end

                if inface == 'any'
                    if msrc.nil? or msrc.empty?
                        infaces += ifaces.keys
                    else
                        found = false

                        ifaces.each do |ifk, ifv|
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
                    infaces << inface
                end

                if outface == 'any'
                    if mdst.nil? or mdst.empty?
                        outfaces += ifaces.keys
                    else
                        found = false

                        ifaces.each do |ifk, ifv|
                            routable, unroutable = filter_routable(mdst, ifv)
                            if not routable.empty?
                                outfaces << ifk
                                found = true
                            end
                        end

                        if not found
                            infaces += gwifaces.keys
                        end
                    end
                else
                    outfaces << outface
                end

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
                            inface, outface = outface, inface
                        end

                        router_ports[inface] ||= {}
                        router_ports[inface][outface] ||= []

                        router_ports[inface][outface] << portdef.merge({
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
                gdst_reject = []
                gsrc_match = []
                gsrc_reject = []
                gportfdef = []
                ifaces.each do |iface, ifacedef|
                    iface_ports[iface] ||= []
                    msrc = portdef[:src]
                    mdst = portdef[:dst]
                    leafface = ifacedef[:gateway].nil?

                    if port_type == 'client' and !mdst.nil? and !mdst.empty?
                        mdst, rdst = filter_routable(mdst, ifacedef)
                        gdst_match += mdst
                        gdst_reject += rdst
                        next if mdst.empty? and leafface
                    elsif port_type == 'server' and !msrc.nil? and !msrc.empty?
                        msrc, rsrc = filter_routable(msrc, ifacedef)
                        gsrc_match += msrc
                        gsrc_reject += rsrc
                        next if msrc.empty? and leafface
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
                            :portdef => port_override
                        }
                    end
                end

                gsrc_reject.uniq!
                gsrc_reject -= gsrc_match

                gdst_reject.uniq!
                gdst_reject -= gdst_match

                # Add all unmatched to interfaces with default gateway
                gportfdef.each do |gdef|
                    port_override = gdef[:portdef]
                    unless gdst_reject.empty?
                        mdst = port_override[:dst] || []
                        mdst += gdst_reject
                        mdst.uniq!
                        port_override[:dst] = mdst
                    end
                    unless gsrc_reject.empty?
                        msrc = port_override[:src] || []
                        msrc += gsrc_reject
                        msrc.uniq!
                        port_override[:src] = msrc
                    end

                    iface_ports[gdef[:iface]] << port_override
                end
                next
            end

            # default
            iface_ports[iface] ||= []
            iface_ports[iface] << portdef.merge({
                :port_type => port_type,
                :service => service,
                :comment => comment
            })
        end
        #==============================
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

        fhconf << '# Setup of ipsets'
        fhconf << '#----------------'
        ip_whitelist = fhmeta['ip_whitelist']
        ip_blacklist = fhmeta['ip_blacklist']

        fhconf << %Q{ipset4 create whitelist4 hash:net}
        fhconf << %Q{ipset6 create whitelist6 hash:net}
        fhconf << %Q{ipset4 create blacklist4 hash:ip}
        fhconf << %Q{ipset4 create blacklist4net hash:net}
        fhconf << %Q{ipset6 create blacklist6net hash:net}

        fhconf << '# note: hardcoded list is not expected to be large'
        ip_whitelist.each do |ip|
            cand = IPAddr.new(ip)

            if cand.ipv4?
                fhconf << %Q{ipset4 add whitelist4 "#{ip}"}
            elsif cand.ipv6?
                fhconf << %Q{ipset6 add whitelist6 "#{ip}"}
            else
                warning('Unknown whitelist address type: ' + ip)
            end
        end
        fhconf << ''
        ip_blacklist.each do |ip|
            cand = IPAddr.new(ip)

            if cand.ipv4?
                fhconf << %Q{ipset4 add blacklist4 "#{ip}"}
            elsif cand.ipv6?
                fhconf << %Q{ipset6 add blacklist6 "#{ip}"}
            else
                warning('Unknown blacklist address type: ' + ip)
            end
        end
        fhconf << ''

        fhconf << '# Protection on public-facing interfaces'
        fhconf << '#----------------'
        ifaces.each do |iface, ifacedef|
            next if is_private_iface ifacedef
            fhconf << %Q{# #{iface}}
            dev = ifacedef[:device]
            address = ifacedef[:address]

            # Blacklist
            fhconf << %Q{blacklist4 input inface "#{dev}" ipset:blacklist4net ipset:blacklist4 except src ipset:whitelist4}
            fhconf << %Q{blacklist6 input inface "#{dev}" ipset:blacklist6net ipset:blacklist6 except src ipset:whitelist6}

            # unroutable
            routable, unroutable = filter_routable(UNROUTABLE_IPS, ifacedef)

            unless unroutable.empty?
                unroutable = unroutable.join(',')
                fhconf << %Q{iptables -t raw -N cfunroute_#{iface}}
                fhconf << %Q{iptables -t raw -A cfunroute_#{iface} -s "#{unroutable}" -j DROP}
                fhconf << %Q{iptables -t raw -A cfunroute_#{iface} -d "#{unroutable}" -j DROP}
                fhconf << %Q{iptables -t raw -A PREROUTING -i "#{dev}" -j cfunroute_#{iface}}
            end

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

                    src4, src6 = filter_ipv(portdef[:src] || [])

                    to_port = portdef[:to_port] || nil
                    to_port = ':' + to_port.to_s if not to_port.nil?

                    comment = portdef[:comment]
                    if comment
                        fhconf << '# ' + comment.sub("\n", ' ')
                    end

                    if portdef[:dst].nil? or portdef[:dst].empty?
                        dst = []
                        dst << ifaces[iface][:address] unless ifaces[iface][:address].nil?
                        dst += ifaces[iface][:extra_address] unless ifaces[iface][:extra_address].nil?

                        if dst.empty?
                            warning("SYNPROXY requires that dst is set either explicitly " +
                                    "or through iface static address: " + portdef.to_s)
                            next
                        end

                        dst4, dst6 = filter_ipv(dst)
                    else
                        dst4, dst6 = filter_ipv(portdef[:dst])
                    end

                    if portdef.has_key? :dnat_port
                        to4, to6 = filter_ipv(portdef[:to_dst])
                        synproxy_type = 'forward'
                        synproxy_action4 = %Q{dnat to "#{to4}#{to_port}"}
                        synproxy_action6 = %Q{dnat to "#{to6}#{to_port}"}
                    else
                        synproxy_type = 'input'
                        synproxy_action4 = 'accept'
                        synproxy_action6 = 'accept'
                    end

                    server_ports.each do |p|
                        proto, dport = p.split('/')
                        next unless proto == 'tcp'

                        if not dst4.empty?
                            cmd = %Q{synproxy4 #{synproxy_type} inface #{iface} dst "#{dst4}" dport "#{dport}"}
                            cmd += %Q{ src "#{src4}"} unless src4.empty?
                            cmd += %Q{ #{synproxy_action4}}
                            fhconf << cmd
                        end
                        if not dst6.empty?
                            cmd = %Q{synproxy6 #{synproxy_type} inface #{iface} dst "#{dst6}" dport "#{dport}"}
                            cmd += %Q{ src "#{src6}"} unless src6.empty?
                            cmd += %Q{ #{synproxy_action6}}
                            fhconf << cmd
                        end
                    end
                end
            end

            # SNAT / MASQUERADE
            if address.nil?
                fhconf << %Q{iptables -t nat -A POSTROUTING -o "#{dev}" -j MASQUERADE}
            else
                addr_list = [address]
                addr_list += ifacedef[:extra_addresses] unless ifacedef[:extra_addresses].nil?
                addr_list.map! do |item| strip_mask item end # strip mask
                address = addr_list[0]

                addr_list = addr_list.join(',')
                fhconf << %Q{iptables -t nat -N cfpost_snat_#{iface}}
                fhconf << %Q{iptables -t nat -A cfpost_snat_#{iface} -s #{addr_list} -j RETURN}
                fhconf << %Q{iptables -t nat -A cfpost_snat_#{iface} -j SNAT --to-source=#{address}}
                fhconf << %Q{iptables -t nat -A POSTROUTING -o "#{dev}" -j cfpost_snat_#{iface}}
            end
            fhconf << ''
        end
        fhconf << ''

        fhconf << '# Custom Headers'
        fhconf << '#----------------'
        fhconf << fhmeta['custom_headers'].join("\n")
        fhconf << ''


        fhconf << '# NAT'
        fhconf << '#----------------'
        dnat_ports.each do |v|
            iface = v[:iface]
            service = v[:service]

            if iface != 'any'
                dev = ifaces[iface][:device]
                inface = %Q{inface "#{dev}"}
            else
                inface = ''
            end
            src4, src6 = filter_ipv(v[:src] || [])
            dst4, dst6 = filter_ipv(v[:dst] || [])
            to4, to6 = filter_ipv(v[:to_dst])

            to_port = v[:to_port] || nil
            to_port = ':' + to_port.to_s if not to_port.nil?

            comment = v[:comment]
            if comment
                fhconf << '# ' + comment.sub("\n", ' ')
            end

            server_ports = custom_services[service][:server_ports]
            server_ports = [server_ports] unless server_ports.is_a? Array

            if not (src4.empty? and dst4.empty? and to4.empty?)
                server_ports.each do |p|
                    proto, dport = p.split('/')
                    cmd = %Q{dnat4 to "#{to4}#{to_port}" #{inface} proto "#{proto}" dport "#{dport}"}
                    cmd += %Q{ dst "#{dst4}"} unless dst4.empty?
                    cmd += %Q{ src "#{src4}"} unless src4.empty?
                    fhconf << cmd
                end
            end
            if not (src6.empty? and dst6.empty? and to6.empty?)
                server_ports.each do |p|
                    proto, dport = p.split('/')
                    cmd = %Q{dnat6 to "#{to6}#{to_port}" #{inface} proto "#{proto}" dport "#{dport}"}
                    cmd += %Q{ dst "#{dst6}"} unless dst6.empty?
                    cmd += %Q{ src "#{src6}"} unless src6.empty?
                    fhconf << cmd
                end
            end
        end
        fhconf << ''

        fhconf << '# Interfaces'
        fhconf << '#----------------'
        iface_ports.each do |iface, ports|
            if ifaces.has_key?(iface)
                dev = ifaces[iface][:device]
            else
                # 'any' should be distributed across ifaces
                warning("Unknown iface: " + iface.to_s)
                warning("Ports: " + ports.to_s)
                next
            end

            fhconf << %Q{interface "#{dev}" "#{iface}"}

            if dev == 'lo'
                fhconf << %Q{    policy reject}
                fhconf << %Q{    client icmp accept}
                fhconf << %Q{    server icmp accept}
            elsif is_private_iface ifaces[iface]
                fhconf << %Q{    policy reject}
                fhconf << %Q{    client icmp accept}
                fhconf << %Q{    server icmp accept}
            else
                fhconf << %Q{    policy deny}
                fhconf << %Q{    protection bad-packets}
                fhconf << %Q{    client icmp accept}
                # TODO: there is a bug with table length 'ACC_LIM_5_sec_accurate_REJECT' (max 28)
                #fhconf << %Q{    server ping accept with limit 5/sec}
            end
            
            ports.each do |p|
                service = p[:service]
                port_type = p[:port_type]
                src4, src6 = filter_ipv(p[:src] || [])
                dst4, dst6 = filter_ipv(p[:dst] || [])
                user = (p[:user] or []).join(' ')
                group = ( p[:group] or []).join(' ')

                cmd_cond = ''
                cmd_cond += %Q{ uid "#{user}"} unless user.empty?
                cmd_cond += %Q{ gid "#{group}"} unless group.empty?

                comment = p[:comment]
                if comment
                    fhconf << '    # ' + comment.sub("\n", ' ')
                end

                do_generic = true

                if not (src4.empty? and dst4.empty?)
                    do_generic = false
                    cmd = %Q{    #{port_type}4 "#{service}" accept}
                    cmd += %Q{ dst "#{dst4}"} unless dst4.empty?
                    cmd += %Q{ src "#{src4}"} unless src4.empty?
                    cmd += cmd_cond
                    fhconf << cmd
                end
                if not (src6.empty? and dst6.empty?)
                    do_generic = false
                    cmd = %Q{    #{port_type}6 "#{service}" accept}
                    cmd += %Q{ dst "#{dst6}"} unless dst6.empty?
                    cmd += %Q{ src "#{src6}"} unless src6.empty?
                    cmd += cmd_cond
                    fhconf << cmd
                end
                if do_generic
                    cmd = %Q{    #{port_type} "#{service}" accept}
                    cmd += cmd_cond
                    fhconf << cmd
                end
            end
            fhconf << ''
        end
        fhconf << ''

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
                    fhconf << %Q{    server icmp accept}
                end
                if outprivate
                    fhconf << %Q{    client icmp accept}
                else
                    fhconf << %Q{    client ping accept}
                end
                
                outfacedef.each do |p|
                    service = p[:service]
                    port_type = p[:port_type]
                    src4, src6 = filter_ipv(p[:src] || [])
                    dst4, dst6 = filter_ipv(p[:dst] || [])
                
                    comment = p[:comment]
                    if comment
                        fhconf << '    # ' + comment.sub("\n", ' ')
                    end
                    
                    do_generic = true
                    
                    if not (src4.empty? and dst4.empty?)
                        do_generic = false
                        cmd = %Q{    #{port_type}4 "#{service}" accept}
                        cmd += %Q{ dst "#{dst4}"} unless dst4.empty?
                        cmd += %Q{ src "#{src4}"} unless src4.empty?
                        fhconf << cmd
                    end
                    if not (src6.empty? and dst6.empty?)
                        do_generic = false
                        cmd = %Q{    #{port_type}6 "#{service}" accept}
                        cmd += %Q{ dst "#{dst6}"} unless dst6.empty?
                        cmd += %Q{ src "#{src6}"} unless src6.empty?
                        fhconf << cmd
                    end
                    if do_generic
                        fhconf << %Q{    #{port_type} "#{service}" accept}
                    end
                end
                fhconf << ''
            end
        end
        fhconf << ''


        # Write New FireHOL conf
        #---
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
end
