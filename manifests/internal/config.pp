#
# Copyright 2016-2017 (c) Andrey Galkin
#


# Please see README
class cffirehol::internal::config {
    #---
    #Cfnetwork::Internal::Exported_port <<| |>>

    if $::cffirehol::ip_whitelist {
        cfnetwork::ipset { 'whitelist:cffirehol':
            type => 'net',
            addr => $::cfauth::admin_hosts,
        }
    }

    if $::cffirehol::ip_blacklist {
        cfnetwork::ipset { 'blacklist:cffirehol':
            type => 'net',
            addr => $::cfauth::admin_hosts,
        }
    }

    file { ['/etc/firehol/blacklist4.txt',
            '/etc/firehol/blacklist6.txt']:
        ensure  => present,
        replace => 'no',
        content => '',
        mode    => '0600',
        notify  => Cffirehol_config['firehol'],
    }

    #---
    cffirehol_config{ 'firehol':
        ensure          => present,
        enable          => $::cffirehol::enable,
        custom_headers  => any2array($::cffirehol::custom_headers),
        synproxy_public => $::cffirehol::synproxy_public,
    }

    #---
    Cfnetwork_firewall_iface <| |> ->
        Cfnetwork_firewall_ipset <| |> ->
        Cfnetwork_firewall_service <| |> ->
        Cfnetwork_firewall_port <| |> ->
        Cffirehol_config['firehol']

}
