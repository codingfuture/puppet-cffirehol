require 'cffirehol/providerbase'

Puppet::Type.type(:cffirehol_config).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for cffirehol_config"
    
    commands :firehol => "/sbin/firehol"
    
    def self.instances
        instances = []
        fhmeta = cf_firehol().read_config()
        type = getMetaIndex()
            
        instances << self.new(
            :name => 'firehol',
            :ensure => fhmeta['generator_version'].empty? ? :absent : :exists,
            :custom_headers => fhmeta['custom_headers'],
            :ip_whitelist => fhmeta['ip_whitelist'],
            :ip_blacklist => fhmeta['ip_blacklist'],
            :synproxy_public => fhmeta['synproxy_public'],
        )
        
        debug('Instances:' + instances.to_s)
        instances
    end
    
    def flush
        debug('flush')
        ensure_val = @property_hash[:ensure]
            
        case ensure_val 
        when :absent
            write_config('custom_headers', [])
            write_config('ip_whitelist', [])
            write_config('ip_blacklist', [])
            write_config('synproxy_public', false)
        when :present, :exists
            write_config('custom_headers', (@resource[:custom_headers] or []))
            write_config('ip_whitelist', (@resource[:ip_whitelist] or []))
            write_config('ip_blacklist', (@resource[:ip_blacklist] or []))
            write_config('synproxy_public', (@resource[:synproxy_public] or false))
        else
            warning(@resource)
            warning(@property_hash)
            raise Puppet::DevError, "Unknown 'ensure' = " + ensure_val.to_s
        end

        cf_firehol = self.class.cf_firehol()
        reconf = cf_firehol.gen_config()
        cf_firehol.reset_config()
        
        if reconf and @resource[:enable]
            debug('Running firehol')
            firehol('start')
        end
    end
    
    def self.getMetaIndex
        nil
    end
end
