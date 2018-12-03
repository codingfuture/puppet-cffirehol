#
# Copyright 2016-2018 (c) Andrey Galkin
#


# Please see README
class cffirehol::fwknop(
    Boolean
        $enable = false,
    Cfnetwork::Port
        $port = 62201, # the default of fwknopd
) {
    $knock_remote = $cffirehol::knock_remote
    $enable_client = ($knock_remote != undef)

    if $enable or $enable_client {
        $service = 'cffwknopd'
        $user = 'cffwknop'
        $group = $user
        $conf_dir = '/etc/fwknop'
        $access_dir = "${conf_dir}/access"
        $helper_bin = "${conf_dir}/cf_fwknop_ipset_helper"
        $ensure_package = $enable ? {
            true => present,
            default => absent
        }

        ensure_packages(['sudo'])

        Package['sudo']
        -> group { $group:
            ensure => present,
        }
        -> user { $user:
            ensure  => present,
            gid     => $group,
            home    => $conf_dir,
            require => Group[$group]
        }
        -> package { 'fwknop-server':
            ensure => $ensure_package,
        }
        -> service { 'fwknop-server':
            ensure   => false,
            enable   => false,
            provider => 'systemd',
        }
        -> file { $conf_dir:
            ensure  => directory,
            owner   => $user,
            group   => $group,
            mode    => '0700',
            purge   => true,
            recurse => true,
        }
        -> file { $access_dir:
            ensure  => directory,
            owner   => $user,
            group   => $group,
            mode    => '0700',
            purge   => true,
            recurse => true,
        }
        -> file { $helper_bin:
            owner   => $user,
            group   => $group,
            mode    => '0700',
            content => file('cffirehol/cf_fwknop_ipset_helper.sh'),
        }
        -> file { "${conf_dir}/fwknopd.conf":
            owner   => $user,
            group   => $group,
            mode    => '0600',
            content => epp('cffirehol/fwknopd.conf.epp'),
        }
        -> file { "/etc/systemd/system/${service}.service":
            mode    => '0644',
            content => epp('cffirehol/cffwknopd.service.epp'),
            notify  => Exec['cfnetwork-systemd-reload'],
        }
        -> file {"/etc/sudoers.d/${user}":
            group   => root,
            owner   => root,
            mode    => '0440',
            replace => true,
            content => "
${user}   ALL=(ALL:ALL) NOPASSWD: /sbin/ipset
",
            require => Package['sudo'],
        }
        -> service { $service:
            ensure   => $enable,
            enable   => $enable,
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

    # Client
    #--------------
    $client_service = 'cffwknop-client'
    $client_helper_bin = "${conf_dir}/cf_fwknop_client"

    file { "/etc/systemd/system/${client_service}.service":
        mode    => '0644',
        content => epp('cffirehol/cffwknop-client.service.epp'),
        notify  => Exec['cfnetwork-systemd-reload'],
    }
    -> service { $client_service:
        ensure   => $enable_client,
        enable   => $enable_client,
        provider => 'systemd',
    }

    if $enable_client {
        $knock_remote.each |$n, $cfg| {
            cfnetwork::describe_service { "cffwknop_${n}":
                server => [
                    "udp/${cfg['port']}",
                    "tcp/${cfg['test_port']}",
                ],
            }
            cfnetwork::client_port { "any:cffwknop_${n}:auto":
                user => $user,
                dst  => $cfg['host'],
            }
        }

        cfnetwork::client_port { ['any:http:cffwknop', 'any:https:cffwknop']:
            user => $user,
        }

        package { 'fwknop-client': }
        -> file { $client_helper_bin:
            owner   => $user,
            group   => $group,
            mode    => '0700',
            content => epp('cffirehol/cf_fwknop_client.epp', { client => $knock_remote }),
        }
        ~>file { "${conf_dir}/.fwknoprc":
            owner   => $user,
            group   => $group,
            mode    => '0600',
            content => epp('cffirehol/fwknoprc.epp', { client => $knock_remote }),
        }
        ~> Service[$client_service]
    }
}
