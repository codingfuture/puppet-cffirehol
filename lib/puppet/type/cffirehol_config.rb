#
# Copyright 2016-2017 (c) Andrey Galkin
#

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
    
    newproperty(:synproxy_public, :boolean => true, :parent=>Puppet::Property::Boolean) do
        desc "Enable TCP SynProxy on all services on the public interface"
        defaultto false
    end
end
