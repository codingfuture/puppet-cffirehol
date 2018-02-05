#
# Copyright 2016-2018 (c) Andrey Galkin
#


require 'puppet/provider'

# Done this way due to some weird behavior in tests also ignoring $LOAD_PATH
require File.expand_path( '../../cffirehol', __FILE__ )

class CfFirehol::ProviderBase < Puppet::Provider
    desc "FireHOL provider for cfnetwork_firewall_port"
    
    # Unified functionality across providers
    #------------------------
    
    def self.cf_firehol
        CfFirehol
    end
    
    def self.resource_type=(resource)
        super
        debug('resource_type=: ' + resource.to_s)
        mk_resource_methods
    end
    
    def self.instances
        debug('self.instances')
        instances = []
        fhmeta = cf_firehol().read_config()
        type = getMetaIndex()
        
        fhmeta[type].each do |k, v|
            params = {}
            v.each do |vk, vv|
                params[vk.to_sym] = vv
            end
            
            params[:name] = k
            params[:ensure] = :present
            
            instances << self.new(params)
        end
        
        #debug('Instances:' + instances.to_s)
        instances
    end
    
    def self.prefetch(resources)
        debug('self.prefetch')
        instances().each do |prov|
            if resource = resources[prov.name]
                resource.provider = prov
            end
        end
    end
    
    def write_config(name, opts)
        type = self.class.getMetaIndex()
        debug("#{type} #{name} #{opts}")
        
        cf_firehol = self.class.cf_firehol()
        fhmeta = cf_firehol.new_config
        if type
            fhmeta_type = fhmeta[type]
        else
            fhmeta_type = fhmeta
        end

        if not opts.nil?
            fhmeta_type[name] = opts
        elsif type and fhmeta_type.has_key?(name)
            fhmeta_type.delete(name)
        end

        #debug(fhmeta)
    end
    
    def flush
        debug('flush')
        ensure_val = @property_hash[:ensure] || @resource[:ensure]
            
        case ensure_val 
        when :absent
            write_config(@resource[:name], nil)
        when :present
            properties = {}
            self.class.resource_type.validproperties.each do |property|
                next if property == :ensure
                properties[property] = @resource[property]
            end
            write_config(@resource[:name], properties)
        else
            warning(@resource)
            warning(@property_hash)
            raise Puppet::DevError, "Unknown 'ensure' = " + ensure_val.to_s
        end
    end
    
    def create
        debug('create')
        @property_hash[:ensure] = :present
        flush
    end

    def destroy
        debug('destroy')
        @property_hash[:ensure] = :absent
        flush
    end

    def exists?
        debug('exists?')
        
        ensure_val = @property_hash[:ensure] || @resource[:ensure]
        flush if ensure_val == :present
        ensure_val != :absent
    end
end
