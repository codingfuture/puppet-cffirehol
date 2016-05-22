
class cffirehol::internal::config {
    #---
    #Cfnetwork::Internal::Exported_port <<| |>>
    
    if $::cfauth::admin_hosts {
        $ip_whitelist = any2array($::cffirehol::ip_whitelist) +
                        any2array($::cfauth::admin_hosts)
    } else {
        $ip_whitelist = any2array($::cffirehol::ip_whitelist)
    }
    
    #---
    cffirehol_config{ 'firehol':
        ensure          => present,
        enable          => $::cffirehol::enable,
        custom_headers  => any2array($::cffirehol::custom_headers),
        ip_whitelist    => $ip_whitelist,
        ip_blacklist    => any2array($::cffirehol::ip_blacklist),
        synproxy_public => $::cffirehol::synproxy_public,
        persistent_dhcp => $::cffirehol::persistent_dhcp,
    }

    #---
    Cfnetwork_firewall_iface <| |> ->
        Cfnetwork_firewall_service <| |> ->
        Cfnetwork_firewall_port <| |> ->
        Cffirehol_config['firehol']

}