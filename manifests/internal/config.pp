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
            addr => $::cffirehol::ip_whitelist,
        }
    }

    if $::cffirehol::ip_blacklist {
        cfnetwork::ipset { 'blacklist:cffirehol':
            type => 'net',
            addr => $::cffirehol::ip_blacklist,
        }
    }

    cfnetwork::ipset { 'dynblacklist':
        type    => 'net',
        addr    => [],
        dynamic => true,
    }

    file { [$cffirehol::blacklist4_file,
            $cffirehol::blacklist6_file]:
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

    #--
    file { "/etc/init.d/${cffirehol::service}":
        ensure => absent,
    }
    -> file { "/etc/systemd/system/${cffirehol::service}.service":
        mode    => '0644',
        content => epp('cffirehol/firehol.service', {
            before => ''
        }),
        notify  => Exec['cfnetwork-systemd-reload'],
    }
    service { $cffirehol::service:
        ensure   => $::cffirehol::enable,
        enable   => $::cffirehol::enable,
        provider => 'systemd',
        require  => [
            Cffirehol_config['firehol'],
            File["/etc/systemd/system/${cffirehol::service}.service"],
        ],
    }

    #---
    Anchor['cfnetwork:pre-firewall']
        -> Cfnetwork_firewall_iface <| |>
        -> anchor { 'cffirehol:sep:iface': }
        -> Cfnetwork_firewall_ipset <| |>
        -> anchor { 'cffirehol:sep:ipset': }
        -> Cfnetwork_firewall_service <| |>
        -> anchor { 'cffirehol:sep:service': }
        -> Cfnetwork_firewall_port <| |>
        -> Cffirehol_config['firehol']
        -> Anchor['cfnetwork:firewall']
    
    # Pre-5.x fix
    Anchor['cfnetwork:pre-firewall']
        -> Anchor['cffirehol:sep:iface']
        -> Anchor['cffirehol:sep:ipset']
        -> Anchor['cffirehol:sep:service']
        -> Cffirehol_config['firehol']

    if defined(Service[$cfnetwork::dns_service_name]) {
        Service[$cfnetwork::dns_service_name]
            -> Cffirehol_config['firehol']
    }
}
