#
# Copyright 2016-2019 (c) Andrey Galkin
#


# Done this way due to some weird behavior in tests also ignoring $LOAD_PATH
require File.expand_path( '../../../../cffirehol/providerbase', __FILE__ )

Puppet::Type.type(:cfnetwork_firewall_service).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for custom service defined by cfnetwork_firewall_service"
    
    def self.getMetaIndex
        'custom_services'
    end
end
