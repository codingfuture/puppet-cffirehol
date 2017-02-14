#
# Copyright 2017 (c) Andrey Galkin
#


class cffirehol::dynblacklist(
    Boolean
        $enable = false,
    Array[String[1]]
        $blacklists4 = [
            # firehol-level1
            'bambenek_c2',
            'dshield',
            'feodo',
            'fullbogons',
            'palevo',
            'spamhaus_drop',
            'spamhaus_edrop',
            'sslbl',
            'zeus_badips',
            'ransomware_rw',
        ],
    Array[String[1]]
        $blacklists6 = [],
    Hash
        $blacklist_cron = {
            minute => '*/10',
        },
    Hash[String[1], String[1]]
        $addon_ipsets = {},
    Optional[String[1]]
        $custom_update = undef,
    Optional[String[1]]
        $custom_netset4_file = undef,
    Optional[String[1]]
        $custom_netset6_file = undef,
) {
    assert_private()

    $cron_update = 'cffirehol-update-blacklist'
    $update_blacklist = '/etc/firehol/update_blacklist.sh'

    if $enable {
        $user = 'cfblacklist'
        $root_dir = "/home/${user}"
        $state_dir = "${root_dir}/.update-ipsets"
        $addon_ipset_dir = "${state_dir}/ipsets.d"
        $ipsets_dir = "${root_dir}/ipsets"
        $blacklists = $blacklists4 + $blacklists6

        ensure_packages(['unzip'])
        group { $user: ensure => present } ->
        user { $user:
            ensure         => present,
            gid            => $user,
            managehome     => true,
            home           => $root_dir,
            purge_ssh_keys => true,
            shell          => '/bin/bash',
        } ->
        file { [$root_dir, $state_dir, $addon_ipset_dir]:
            ensure => directory,
            owner  => $user,
            group  => $user,
            mode   => '0700',
        }

        cfnetwork::client_port { ['any:http:cffirehol',
                                'any:https:cffirehol']:
            user => $user,
        }

        # Addon ipset configuration
        #---
        $addon_ipsets.each |$n, $v| {
            file { "${addon_ipset_dir}/${n}.conf":
                owner   => $user,
                group   => $user,
                mode    => '0600',
                content => $v,
            }
        }

        # enable ipsets
        #---
        $blacklists6.each |$bl| {
            fail('IPv6 blacklists are not supported by update-ipsets yet :(')
        }

        $blacklists.each |$bl| {
            exec { "cffirehol-init-bl-${bl}":
                command => [
                    "/usr/bin/sudo -H -u ${user} ",
                        "/usr/sbin/update-ipsets -s enable ${bl}",
                ].join(''),
                creates => "${ipsets_dir}/${bl}.source",
                require => [
                    File[$root_dir],
                    User[$user],
                    Cffirehol_config['firehol'],
                    Package['unzip'],
                ],
                notify  => Cron[$cron_update],
            }
        }

        # Updates
        #---
        file { $update_blacklist:
            mode    => '0700',
            content => epp('cffirehol/update_blacklist.sh.epp'),
        }
        create_resources('cron', {
            $cron_update => {
                command => "${update_blacklist} >/dev/null",
                user => 'root',
            },
        }, $blacklist_cron)
    } else {
        cron { [$cron_update, $update_blacklist]:
            ensure => absent,
            user   => 'root',
        }
        file { $update_blacklist: ensure => absent }
    }
}
