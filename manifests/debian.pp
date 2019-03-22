#
# Copyright 2016-2019 (c) Andrey Galkin
#


# Please see README
class cffirehol::debian (
    $firehol_apt_url = 'http://ppa.launchpad.net/andvgal/firehol-bpo/ubuntu',
    $firehol_apt_release = $cffirehol::debian::params::launchpad_release,
) inherits cffirehol::debian::params {
    include stdlib
    assert_private();

    class {'cffirehol::debian::apt':
        stage => 'setup',
    }

    package { 'iprange': ensure => latest }
    package { 'firehol': ensure => latest }
    package { 'ulogd2': }

    package { 'iptables-persistent': ensure => absent }
    package { 'netfilter-persistent': ensure => absent }
    package { 'ufw': ensure => absent }
}
