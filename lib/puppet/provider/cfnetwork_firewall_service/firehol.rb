
Puppet::Type.type(:cfnetwork_firewall_service).provide(
    :firehol,
    :parent => Puppet::Type.type(:cfnetwork_firewall_port).provider(:firehol)
) do
    desc "FireHOL provider for custom service defined by cfnetwork_firewall_service"
end
