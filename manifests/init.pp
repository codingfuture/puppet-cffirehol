#
# Copyright 2016-2019 (c) Andrey Galkin
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
    Hash[String[1], Struct[{
        'timeout'      => Optional[Integer[600]],
        'ipset'        => Optional[Variant[Cfnetwork::Ipsetname,Array[Cfnetwork::Ipsetname]]],
        'key_b64'      => Cffirehol::Base64,
        'hmac_key_b64' => Cffirehol::Base64,
    }]]
        $knockers = {},
    Optional[Hash[String[1],Struct[{
        'user'         => Pattern[/^[a-z][a-z0-9]+$/],
        'host'         => Pattern[/^[a-z][a-z0-9.-]+$/],
        'port'         => Cfnetwork::Port,
        'test_port'    => Cfnetwork::Port,
        'key_b64'      => Cffirehol::Base64,
        'hmac_key_b64' => Cffirehol::Base64,
    }]]]
        $knock_remote = undef,
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

    if $knock_remote {
        include cffirehol::fwknop
    }
}

