#
# Copyright 2016-2017 (c) Andrey Galkin
#


# Please see README
class cffirehol::debian::params {
    if ($::facts['operatingsystem'] == 'Debian' and
            versioncmp($::facts['operatingsystemrelease'], '9') >= 0) or
        ($::facts['operatingsystem'] == 'Ubuntu' and
            versioncmp($::facts['operatingsystemrelease'], '16.04') >= 0)
    {
        $launchpad_release = 'xenial'
    } else {
        $launchpad_release = 'trusty'
    }
}
