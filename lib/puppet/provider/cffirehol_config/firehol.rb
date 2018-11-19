#
# Copyright 2016-2018 (c) Andrey Galkin
#


require 'fileutils'

# Done this way due to some weird behavior in tests also ignoring $LOAD_PATH
require File.expand_path( '../../../../cffirehol/providerbase', __FILE__ )

Puppet::Type.type(:cffirehol_config).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for cffirehol_config"
    
    commands :firehol => "/sbin/firehol"
    commands :iptables => "/sbin/iptables"
    commands :sysctl => "/sbin/sysctl"
    
    def self.instances
        instances = []
        fhmeta = cf_firehol().read_config()
        type = getMetaIndex()
            
        instances << self.new(
            :name => 'firehol',
            :ensure => fhmeta['generator_version'].empty? ? :absent : :present,
            :custom_headers => fhmeta['custom_headers'],
            :synproxy_public => fhmeta['synproxy_public'],
            :enable => fhmeta['enable'],
        )
        
        #debug('Instances:' + instances.to_s)
        instances
    end
    
    def flush
        debug('flush')
        ensure_val = @property_hash[:ensure] || @resource[:ensure]
            
        case ensure_val 
        when :absent
            write_config('custom_headers', [])
            write_config('synproxy_public', false)
            write_config('enable', false)
        when :present
            write_config('custom_headers', (@resource[:custom_headers] or []))
            write_config('synproxy_public', (@resource[:synproxy_public] or false))
            write_config('enable', (@resource[:enable] or false))
        else
            warning(@resource)
            warning(@property_hash)
            raise Puppet::DevError, "Unknown 'ensure' = " + ensure_val.to_s
        end

        cf_firehol = self.class.cf_firehol()
        reconf = cf_firehol.gen_config()
        cf_firehol.reset_config()
        
        restart_file = CfFirehol::FIREHOL_START_REQUIRED_FILE
        reconf ||= File.exists? restart_file
        
        if reconf
            FileUtils.touch(restart_file)
            
            if @resource[:enable]
                iptables_res = iptables('-L', 'INPUT').split("\n")

                if (iptables_res[0] == 'Chain INPUT (policy ACCEPT)')
                    tcp_loose = sysctl('-nb', 'net.netfilter.nf_conntrack_tcp_loose')
                    
                    if tcp_loose == "0"
                        warning('Enabling firewall learning for the first activation!')
                        sysctl('-w', 'net.netfilter.nf_conntrack_tcp_loose=1')
                    end
                end

                warning('Running: /sbin/firehol start')
                firehol('start')
                FileUtils.rm_f(restart_file)
            end
        end
        
        if !@resource[:enable]
            warning('SECURITY WARNING!!! cffirehol is added, but not enabled')
        end
    end
    
    def self.getMetaIndex
        nil
    end
end
