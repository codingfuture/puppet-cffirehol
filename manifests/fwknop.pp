#
# Copyright 2016-2017 (c) Andrey Galkin
#


# Please see README
class cffirehol::fwknop(
    Boolean
        $enable = false,
    Integer[1, 65535]
        $port = 62201, # the default of fwknopd
) {
    if $enable {
        $service = 'cffwknopd'
        $user = 'cffwknop'
        $group = $user
        $conf_dir = '/etc/fwknop'
        $access_dir = "${conf_dir}/access"
        $helper_bin = "${conf_dir}/cf_fwknop_ipset_helper"

        if !defined(Package['sudo']) {
            package { 'sudo': }
        }

        group { $group:
            ensure => present,
        } ->
        user { $user:
            ensure  => present,
            gid     => $group,
            require => Group[$group]
        } ->
        package { 'fwknop-server': } ->
        service { 'fwknop-server':
            ensure   => false,
            enable   => false,
            provider => 'systemd',
        } ->
        file { $conf_dir:
            ensure  => directory,
            owner   => $user,
            group   => $group,
            mode    => '0700',
            purge   => true,
            recurse => true,
        } ->
        file { $access_dir:
            ensure  => directory,
            owner   => $user,
            group   => $group,
            mode    => '0700',
            purge   => true,
            recurse => true,
        } ->
        file { $helper_bin:
            owner   => $user,
            group   => $group,
            mode    => '0700',
            content => file('cffirehol/cf_fwknop_ipset_helper.sh'),
        } ->
        file { "${conf_dir}/fwknopd.conf":
            owner   => $user,
            group   => $group,
            mode    => '0600',
            content => epp('cffirehol/fwknopd.conf.epp'),
        } ->
        file { "/etc/systemd/system/${service}.service":
            mode    => '0644',
            content => epp('cffirehol/cffwknopd.service.epp'),
            notify  => Exec['cffirehol-systemd-reload'],
        } ->
        file {"/etc/sudoers.d/${user}":
            group   => root,
            owner   => root,
            mode    => '0400',
            replace => true,
            content => "
${user}   ALL=(ALL:ALL) NOPASSWD: /sbin/ipset
",
            require => Package['sudo'],
        } ->
        service { $service:
            ensure   => running,
            enable   => true,
            provider => 'systemd',
        }

        cfnetwork::describe_service { 'cffwknop':
            server => "udp/${port}"
        }
        cfnetwork::service_port { 'any:cffwknop': }
    } else {
        package { 'fwknop-server':
            ensure => false
        }
    }
}
