# Change Log

All notable changes to this project will be documented in this file. This
project adheres to [Semantic Versioning](http://semver.org/).

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

[0.9.2](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.2)
[0.9.1](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.1)
[0.9.0](https://github.com/codingfuture/puppet-cffirehol/releases/tag/v0.9.0)