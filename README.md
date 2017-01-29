# cffirehol

## Description

This is not a standalone module. Please use with [codingfuture/cfnetwork][cfnetwork]

Allmost all configuration is done through abstract `cfnetwork::*` resources, except for FireHOL-specific stuff.

**By default, firewall is disabled!**

Features:

* Generic iptables
* SYNPROXY support
* Static & dynamic blacklists with whitelist exceptions
* Single Packet Authorization (SPA) secure port knocking with fwknopd
* Dynamic blacklists

The proper deployment procedure should be:

* Add `codingfuture/cfnetwork` and `codingfuture/cffirehol` to R10K Puppetfile (or install manually)
* Add related configuration to Hiera (strongly encouraged)
* Deploy configuration
* Verify network interfaces are properly configured
* Verify that `/etc/firehol/firehol.conf` is properly configured
* TRY firehol with: `/sbin/firehol try`
* Ensure that at least new SSH connections work
* Update Hiera to enable cffirehol
* Deploy and pray ;)

## Technical Support

* [Example configuration](https://github.com/codingfuture/puppet-test)
* Free & Commercial support: [support@codingfuture.net](mailto:support@codingfuture.net)

## Setup

Please use [librarian-puppet](https://rubygems.org/gems/librarian-puppet/) or
[cfpuppetserver module](https://forge.puppetlabs.com/codingfuture/cfpuppetserver) to deal with dependencies.

There is a known r10k issue [RK-3](https://tickets.puppetlabs.com/browse/RK-3) which prevents
automatic dependencies of dependencies installation.

## Examples

Please check [codingufuture/puppet-test](https://github.com/codingfuture/puppet-test) for
example of a complete infrastructure configuration and Vagrant provisioning.

## Implementation details

`cffirehol` has providers for `cfnetwork` resource types. On every puppet catalog apply,
`cffirehol` read all defined resources from `/etc/firehol/.firehol.json`. Upon catalog
apply is complete, a new JSON is generated. ONLY IF, new JSON does not byte-to-byte
match the original one, a new `/etc/firehol/firehol.conf` is generated with both
files getting rewritten.

If files get rewritten and `cffirehol` is enabled, `/sbin/firehol start` is executed.
Custom Debian/Ubuntu packages for the latest FireHOL and dependencies are available at
[FireHOL Backports in Launchpad](https://launchpad.net/~andvgal/+archive/ubuntu/firehol-bpo)

*Note: At the moment, firehol.conf generation is relatively messy and needs to be rewritten
accompanied by unit tests*

## Notes of Firewall port knocking

There are various port knocking techniques, but interest is only most secure approaches like
Single Packet Authorization. `fwknop` project was chosen as one of the most mature, used and
maintained. However, only a very limited subset of the functionality is used for security reasons.

The daemon runs under unprivileged user and is only allowed to manipulate `ipsets` based
on SPA packet received in UDP server mode.

Current configuration:
* AES-256
* HMAC-SHA-256
* UDP with port from `cffirehol::fwknop::port`
* User name and keys come from cffirehol::knocker configuration
* IP is automatically added to `whitelist` ipset

Suggested `.fwknoprc` configuration:

```
[default]
WGET_CMD /usr/bin/wget
SPA_SERVER_PROTO udp
USE_HMAC Y
HMAC_DIGEST_TYPE sha256
RESOLVE_IP_HTTPS Y
# just a placeholder for SPA format
ACCESS tcp/1

[<server_name>]
SPA_SERVER <server_address>
SPA_SERVER_PORT <ffirehol::fwknop::port>
SPOOF_USER <cffirehol::knocker::user>
KEY_BASE64 <cffirehol::knocker::key_b64>
HMAC_KEY_BASE64 <cffirehol::knocker::hmac_key_b64>

```

Suggested command line:

```
fwknop -R -n myserver -A tcp/22
```

## Classes and resources types

### class `cffirehol`

The main class. Normally, it is included by bi-directional dependency from cfnetwork based on
$firewall_provider parameter.

Options:

* `enable` = `false` - if true, FireHOL will be enabled upon deployment.
    *Note: `/etc/firehol/firehol.conf` is always generated*
* `custom_headers` = `[]` - optional, add custom FireHOL configuration headers
* `synproxy_public` = `true` - protect TCP services with SYNPROXY on all public interfaces.
    Please see [cfnetwork][] for definition of public interface.
* `knockers = {}` - create resources of `cffirehol::knocker`

### class `ffirehol::debian`

Debian and Ubuntu specific FireHOL package configuration

* `firehol_apt_url` = 'http://ppa.launchpad.net/andvgal/firehol-bpo/ubuntu' - repo with required packages
* `firehol_apt_release` = 'trusty' - OS release
    Note: it is safe to use these Ubuntu packages on Debian of corresponding version (e.g. trusty & jessie have the same roots)

### class `cffirehol::fwknop

Configuration of `fwknopd` FireWall knocking service.

* `enable = false` - enable `fwknopd` daemon
* `port = 62201` - UDP port to use for `fwknopd`

### type `cffirehol::knocker`

Configuration of firewall knocking user.

* `key_b64` - Base64 encoded key for message digest
* `hmac_key_b64` - Base64 encoded key for HMAC
* `user = $title` - arbitrary user name for access check
* `ipset = 'cfauth_admin'` - ipset to use for dynamic IP add, can be array of IP sets
* 'timeout = 3*60*60' - timeout to remove IP after (3 hours by default, 0 - disable)

### type `cffirehol::dynblacklist`

Configuration of dynamic blacklist.

* `enable = false` - enables `cffirehol::dynblacklist`
* `blacklists4 = ['dependencies of firehol-level1']` - list of blacklists to enable for IPv4
    - NOTE: there is problem of enabling list with dependency on other lists
* `blacklists6 = []` - list of blacklists to enable for IPv6
    - Not supported until: https://github.com/firehol/firehol/issues/182
* `blacklist_cron = { minute => '*/10' }` - cron resource default configuration for automatic updates
* `addon_ipsets = {}` - list of "name" => "conf file content" to extend built-in blacklist config
* `custom_update = undef` - arbitrary command to generate $custom_*_file files
* `custom_netset4_file = undef` - path to external IPv4 blacklist, if any
* `custom_netset6_file = undef` - path to external IPv6 blacklist, if any


[cfnetwork]: https://github.com/codingfuture/puppet-cfnetwork