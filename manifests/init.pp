
# Please see README
class cffirehol (
    Boolean
        $enable = false,
    Array[String[1]]
        $custom_headers = [],
    Optional[Array[String[1]]]
        $ip_whitelist = undef,
    Optional[Array[String[1]]]
        $ip_blacklist = undef,
    Boolean
        $synproxy_public = true,
    Boolean
        $persistent_dhcp = true,
) {
    include stdlib
    require cfnetwork

    case $::operatingsystem {
        'Debian', 'Ubuntu': { require cffirehol::debian }
        default: { err("Not supported OS ${::operatingsystem}") }
    }

    require cffirehol::internal::config

}

