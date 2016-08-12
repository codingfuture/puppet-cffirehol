# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

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