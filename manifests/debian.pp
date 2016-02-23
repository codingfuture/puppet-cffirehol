
class cffirehol::debian(
    $firehol_apt_url = 'http://ppa.launchpad.net/andvgal/firehol-bpo/ubuntu',
    $firehol_apt_release = 'trusty',
) {
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
    
    
    if $::cffirehol::enable {
        file_line { 'firehol_enable':
            ensure  => present,
            path    => '/etc/default/firehol',
            line    => 'START_FIREHOL=YES',
            match   => 'START_FIREHOL=NO',
            replace => true,
        }
    }
}
