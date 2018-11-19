# vRA7 Security Hardening Profile


This profile validates the configuration of a vRA appliance against settings specified in the vRA hardening guide, available [here](https://docs.vmware.com/en/vRealize-Automation/7.2/vrealize-automation-72-hardening.pdf).

It is recommended to used certificate authentication when running the checks instead of password authentication.

## Prereqs

The system running the checks connect to the vRA Appliance using SSH. 

Local Inspec with ChefDK
- [CheckDK](https://downloads.chef.io/chefdk)

Inspec Docker image:
- [Docker](https://www.docker.com)
- [Chef Inspec Docker image](https://hub.docker.com/r/chef/inspec/)


## Usage - Local Inspec install

These steps for performing the checks running an 

Currently can be run against servers via inspec exec.

```shell
~$ inspec exec .
```

## License and Author

- Author::  Brett Johnson <brett@sdbrett.com>

Licensed under the MIT License.  https://opensource.org/licenses/MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
