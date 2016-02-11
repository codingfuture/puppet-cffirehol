# cffirehol

## Description

This is not a standalone module. Please use with [codingfuture/cfnetwork](https://github.com/codingfuture/puppet-cfnetwork).

Allmost all configuration is done through abstract `cfnetwork::*` resources, except FireHOL-specific stuff.

**By default, firewall is disabled!**
The proper deployment procedure would be:
* Add `codingfuture/cfnetwork` and `codingfuture/cffirehol` to R10K Puppetfile (or install manually)
* Add related configuration to Hiera (strongly encouraged)
* Deploy configuration
* Verify network interfaces are properly configured
* Verify that `/etc/firehol/firehol.conf` is properly configured
* TRY firehol with: `/sbin/firehol try`
* Ensure that at least new SSH connections work
* Update Hiera to enable cffirehol
* Deploy and pray ;)

## Implementation details:

`cffirehol` has providers for `cfnetwork` resource types. On every puppet catalog apply,
`cffirehol` read all defined resources from `/etc/firehol/.firehol.json`. Upon catalog
apply is complete, a new JSON is generated. ONLY IF, new JSON does not byte-to-byte
match the original one, a new `/etc/firehol/firehol.conf` is generated with both
files getting rewritten.

If files got rewritten and `cffirehol` is enabled, `/sbin/firehol start` is executed.
Custom Debian/Ubuntu packages for the latest FireHOL and dependencies are available at
[FireHOL Backports in Launchpad](https://launchpad.net/~andvgal/+archive/ubuntu/firehol-bpo)


## Classes and resources types

### cffirehol

The main class. Normally, it includes by bi-directional dependency from cfnetwork based on
$firewall_provider parameter.

Options:

* `enable` = false - if true, FireHOL will be enabled upon deployment.
    Note: /etc/firehol/firehol.conf is always generated
* `custom_headers` = [] - optional, add custom FireHOL configuration headers
* `ip_whitelist` = [] - optional, add essential IPs to firewall whitelist as exception for blacklist
    This list is not expected to be large.
    Note: you still need to open services.
* `ip_blacklist` = [] - optional, add blacklisted IPs.
    Please avoid specifying this parameter. Please update blacklist* ipsets directly.
* `synproxy_public` = true - protect TCP services with SYNPROXY on all public interfaces.
    Please see [cfnetwork][] for definition of public interface.

### cfnetwork::debian

Debian and Ubuntu specific FireHOL package configuration

* `firehol_apt_url` = 'http://ppa.launchpad.net/andvgal/firehol-bpo/ubuntu' - repo with required packages
* `firehol_apt_release` = 'trusty' - OS release
    Note: it is safe to use these Ubuntu packages on Debian of corresponding version (e.g. trusty & jessie have the same roots)



[cfnetwork](https://github.com/codingfuture/puppet-cfnetwork)