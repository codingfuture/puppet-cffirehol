#
# Copyright 2016-2018 (c) Andrey Galkin
#


# Please see README
class cffirehol::debian::params {
    if ($::facts['operatingsystem'] == 'Debian' and
            versioncmp($::facts['operatingsystemrelease'], '9') >= 0)
    {
        $launchpad_release = 'xenial'
    } elsif ($::facts['operatingsystem'] == 'Ubuntu' and
            versioncmp($::facts['operatingsystemrelease'], '18.04') >= 0)
    {
        $launchpad_release = 'bionic'
    } else {
        $launchpad_release = 'trusty'
    }
}
