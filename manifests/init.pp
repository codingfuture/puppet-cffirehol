
class cffirehol (
    $enable = false,
    $custom_headers = [],
    $ip_whitelist = [],
    $ip_blacklist = [],
    $synproxy_public = true,
    $persistent_dhcp = true,
) {
    include stdlib
    require cfnetwork
    # required for adminhost whitelist
    include cfauth

    case $::operatingsystem {
        'Debian', 'Ubuntu': { require cffirehol::debian }
        default: { err("Not supported OS ${::operatingsystem}") }
    }

    require cffirehol::internal::config

}

