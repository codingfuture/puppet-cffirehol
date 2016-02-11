
Puppet::Type.type(:cfnetwork_firewall_iface).provide(
    :firehol,
    :parent => Puppet::Type.type(:cfnetwork_firewall_port).provider(:firehol)
) do
    desc "FireHOL provider for cfnetwork_firewall_iface"
end
