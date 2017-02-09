#
# Copyright 2016-2017 (c) Andrey Galkin
#


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
    Hash[String[1], Hash]
        $knockers = {},
) {
    include stdlib
    require cfnetwork

    $service = 'firehol'
    $blacklist4_file = '/etc/firehol/dynblacklist4.netset'
    $blacklist6_file = '/etc/firehol/dynblacklist6.netset'

    case $::operatingsystem {
        'Debian', 'Ubuntu': { require cffirehol::debian }
        default: { err("Not supported OS ${::operatingsystem}") }
    }

    create_resources('cffirehol::knocker', $knockers)

    require cffirehol::internal::config
    require cffirehol::dynblacklist
}

