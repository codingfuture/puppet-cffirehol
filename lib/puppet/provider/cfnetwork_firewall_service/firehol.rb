require 'cffirehol/providerbase'

Puppet::Type.type(:cfnetwork_firewall_service).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for custom service defined by cfnetwork_firewall_service"
    
    def self.getMetaIndex
        'custom_services'
    end
end
