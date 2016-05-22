require 'puppet/parameter/boolean'
require 'puppet/property/boolean'

Puppet::Type.newtype(:cffirehol_config) do
    desc "Generate FireHOL config"
    
    ensurable do
        defaultvalues
        defaultto :absent
    end
    
    newparam(:name) do
        desc "Most always be 'firehol'"
        isnamevar
    end
    
    newproperty(:enable, :boolean => true, :parent=>Puppet::Property::Boolean) do
        desc "Enable firewall immediate activation"
        defaultto false
    end
    
    newproperty(:custom_headers, :array_matching => :all) do
        desc "Custom raw headers to be included in firehol.conf"
    end
    
    newproperty(:ip_whitelist, :array_matching => :all) do
        desc "Whitelist IPs not to block even if they get into blacklist"
        
        validate do |value|
            value = munge value
            ip = IPAddr.new(value) # may raise ArgumentError

            unless ip.ipv4? or ip.ipv6?
                raise ArgumentError, "%s is not a valid IPv4 or IPv6 address" % value
            end
        end
        
        munge do |value|
            begin
                ip = IPAddr.new(value)
                return value
            rescue
                return Resolv.getaddress value
            end
        end
    end
    
    newproperty(:ip_blacklist, :array_matching => :all) do
        desc "Blacklist IPs to filter before connection tracking"
        
        validate do |value|
            value = munge value
            ip = IPAddr.new(value) # may raise ArgumentError

            unless ip.ipv4? or ip.ipv6?
                raise ArgumentError, "%s is not a valid IPv4 or IPv6 address" % value
            end
        end
        
        munge do |value|
            begin
                ip = IPAddr.new(value)
                return value
            rescue
                return Resolv.getaddress value
            end
        end
    end

    newproperty(:synproxy_public, :boolean => true, :parent=>Puppet::Property::Boolean) do
        desc "Enable TCP SynProxy on all services on the public interface"
        defaultto false
    end
    
    newproperty(:persistent_dhcp, :boolean => true, :parent=>Puppet::Property::Boolean) do
        desc "Assume persistent DHCP configuration"
        defaultto false
    end

end
