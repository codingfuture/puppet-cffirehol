require 'cffirehol/providerbase'

Puppet::Type.type(:cfnetwork_firewall_port).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for cfnetwork_firewall_port"
    
    def self.getMetaIndex
        'ports'
    end
end
