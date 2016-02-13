require 'cffirehol/providerbase'

Puppet::Type.type(:cfnetwork_firewall_iface).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for cfnetwork_firewall_iface"
    
    def self.getMetaIndex
        'ifaces'
    end
end
