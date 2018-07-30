# vRA7 Security Hardening Profile


This profile implements the [CIS VMware ESXi Benchmark](https://docs.vmware.com/en/vRealize-Automation/7.2/vrealize-automation-72-hardening.pdf).

## Prerequities

- [InSpec](https://inspec.io)

You will need to run this on the vRA Appliance. You can install `inspec` via the Chef DK.

```shell
~$ curl -L https://chef.io/chef/install.sh | sudo bash -s -- -P chefdk
```

## Usage

Currently can be run against servers via inspec exec.

```shell
~$ inspec exec .
```

## License and Author

- Author::  Brett Johnson <brett@sdbrett.com>

Licensed under the MIT License.  https://opensource.org/licenses/MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
