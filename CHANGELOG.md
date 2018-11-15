# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

## (next)
- CHANGED: updated for Ubuntu Bionic 18.04

## 1.1.0 (2018-04-30)
- CHANGED: to use firehol_level1 directly for dynblacklist by default
- CHANGED: to always ICMP-reject connection according to RFC3360
- FIXED: to accept unmatched TCP-RST on interfaces with REJECT policy

## 1.0.0 (2018-03-26)
- FIXED: minor Ruby warnings

## 0.12.2 (2018-03-20)
- FIXED: further improved src/dst processing for main interface

## 0.12.1 (2018-03-19)
- FIXED: failure on missing DNAT to_dst parameter
- FIXED: lost filter dst/src on primary interfaces for unroutable addresses
- NEW: added uid/gid-based grouping for filter rules
    - better readability of generated rules
    - minor performance improvement

## [0.12.0](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.12.0)
- NEW: version bump of cf* series

## [0.11.5](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.11.5)
- FIXED: removed bogus "palevo" blacklist
- CHANGED: safer failure handling of dynblacklist download

## [0.11.4](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.11.4)
- FIXED: updated firehol.service with upstream changed for dependencies

## [0.11.3](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.11.3)
- FIXED: minor resource dependency ordering for pre-5.x Puppet
- CHANGED: updated t APT module >= 4.1
- NEW: Puppet 5.x support
- NEW: Ubuntu Zesty support

## [0.11.2]
- Changed to allow ESTABLISHED connection to ports protected by 
    dynamic SRC ipset. Solves dropped connections after fwknop
    address expiration.

## [0.11.1]
- Changed dynblacklist cron not to send emails with regular updates

## [0.11.0]
- Added cfnetwork:firewall & cfnetwork:pre-firewall anchors support
- Fixed a long standing issues with "exists" in ensure processing
- Optimized implicit multi-to-multi dependency list with resource capture
- Fixed old problem of not processed firewall on first run

## [0.10.2]
- Fixed to strip interface address mask on synproxy protected port without
    explicit destination

## [0.10.1]
- Implemneted proper firehol systemd unit
- Updated to cfnetwork 0.10.1

## [0.10.0]
- SECURITY FIXES
    - Additional fixes to properly handle v4/v6 separation
- Improved IPv6 support
- Changed to silently drop orphan TCP RST, TCP ACK and ICMPv4 destination
    unreachable packets
- Change blacklist to "stateful" mode instead of "input" only
- Added routable private nets to exception of iface blacklist (VPS friendly)
- Implemented `fwknop` port knocking in SPA UDP mode
- Removed 'persistent_dhcp' flag and reworked DHCP interface support
- Fixed IPv6 SNAT/MASQ
- Added support of "network" interface addresses (e.g. for link-local)
- Added /etc/firehol/blacklist[46].txt - placeholders for startup loading
- Now, *public* interface with static configuration is allowed
    to received packets from any interface (solves router cases)
- Implemented dynamic blacklist support
- Added security warning on added, but not enabled cffirehol

## [0.9.12]
- SECURITY FIXES:
    - Fixed synproxy to properly protect selected interfaces
    - Fixed DNAT & Forward rules to properly keep src/dst during IP v4/v6 separation
- Added `cfnetwork` 0.9.11+ ipset support
- Deprecated `ip_whitelist` and `ip_blacklist` in favor of `cfnetwork` approach
- Updated to use SHA-2 repos for stretch+ and xenial+
- Added strict parameter type checking
- Fixed processing of DNAT ports without specified `dst`
- Changed to always require to_dst parameter for DNAT ports
- Automatic newer puppet-lint fixes
- Fixed puppet-lint and metadata-json-lint warnings
- Removed no needed `ipv6error`

## [0.9.11]
- Security: Fixed to properly handle case of multiple `cfnetwork` interfaces per device
    > Note: now dst IP check is enforced on interface & DNAT level

## [0.9.10]
- Fixed minor Puppet Lanaguage issue appeared with 4.6.0: PUP-6606

## [0.9.9]
- Updated supported OS list

## [0.9.8]
- Added new parameter persistent_dhcp=true - auto-detect routing
- Fixed to auto-route own addresses with proper mask /32 or /128 through local interface
- Added silent drop of RST
- Fixed not to show false recreate of resources on module update
- Added IPv6 unroutable
- Fixed to remember if firehol must be restarted (after failure or getting enabled)

## [0.9.7]

- Fixed to properly support apt pinning with related cfsystem changes
- Added missing IPv6 essentials. For more advanced configuration use custom headers.

## [0.9.6]

- Added force removal of ufw package

## [0.9.5]

- Fixed to issue with removed hash:ip blacklist for IPv6 - only hash:net is enough
- Fixed enable to be a property instead of param to force FireHOL run on only this propery update

## [0.9.4]

- Added check verify that port ifaces are defined instead of not understandable error
- Changed to require ruby modules by absolute path due to strange issues with $LOAD_PATH in some deployments
- Added hiera.yaml version 4 support

## [0.9.3]

- No changes, accident release.

## [0.9.2]

- Fixed src/dst property processing with DHCP interfaces

## [0.9.1]

- Properly organized Puppet modules and classes
- Improved to always regenerate firehol.conf, if generator module code changes
- Got rid of legacy code with regex-based private IP matching
- Fixed not to poison meta config with dynamically created DNAT services
- Implemented missing mapping of 'any' interface in router ports with dst/src properties
- Added missing comment support for services
- Re-enabled ping on public IPv4 interfaces with hashlimit of 1/second burst 2.
    There is a small internal FireHOL issue with IPv6 limits. So, IPv6 ping is disabled.
- Fixed not to allow routing ping requests from public interfaces
- Fixed not to include 'local' for interface 'any' of routing ports
- Misc. improvements

## [0.9.0]

Initial release

[0.11.2](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.11.2)
[0.11.1](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.11.1)
[0.11.0](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.11.0)
[0.10.2](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.10.2)
[0.10.1](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.10.1)
[0.10.0](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.10.0)
[0.9.13](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.13)
[0.9.12](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.12)
[0.9.11](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.11)
[0.9.10](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.10)
[0.9.9](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.9)
[0.9.8](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.8)
[0.9.7](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.7)
[0.9.6](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.6)
[0.9.5](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.5)
[0.9.4](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.4)
[0.9.3](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.3)
[0.9.2](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.2)
[0.9.1](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.1)
[0.9.0](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.0)
