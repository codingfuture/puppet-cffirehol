#
# Copyright 2016 (c) Andrey Galkin
#


# Done this way due to some weird behavior in tests also ignoring $LOAD_PATH
require File.expand_path( '../../../../cffirehol/providerbase', __FILE__ )

Puppet::Type.type(:cfnetwork_firewall_port).provide(
    :firehol,
    :parent => CfFirehol::ProviderBase
) do
    desc "FireHOL provider for cfnetwork_firewall_port"
    
    def self.getMetaIndex
        'ports'
    end
end
