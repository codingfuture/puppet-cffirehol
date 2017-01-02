#
# Copyright 2016-2017 (c) Andrey Galkin
#


# Please see README
define cffirehol::knocker(
    String[22]
        $key_b64,
    String[22]
        $hmac_key_b64,
    String[1]
        $user = $title,
    String[1]
        $ipset = 'cfauth_admin',
) {
    include cffirehol::fwknop

    if !defined(Cfnetwork::Ipset[$ipset]) {
        fail("Cfnetwork::Ipset[${ipset}] must be defined first!")
    }

    if $cffirehol::fwknop::enable {
        file { "${cffirehol::fwknop::access_dir}/${user}.conf":
            owner   => $cffirehol::fwknop::user,
            group   => $cffirehol::fwknop::group,
            mode    => '0600',
            content => epp('cffirehol/fwknopd_access.conf.epp', {
                user         => $user,
                ipset        => $ipset,
                key_b64      => $key_b64,
                hmac_key_b64 => $hmac_key_b64,
                helper_bin   => $cffirehol::fwknop::helper_bin,
            }),
            notify  => Service[$cffirehol::fwknop::service],
        }
    }
}
