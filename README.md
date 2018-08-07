# vRA7 Security Hardening Profile


This tests the configuration of a vRA appliance against the settings in specified within the [vRA Hardening Guide](https://docs.vmware.com/en/vRealize-Automation/7.2/vrealize-automation-72-hardening.pdf).

You can either install Chef Inspec from Chef DK or use the Chef Inspec Docker image. If you're not familiar with 
managing Ruby
 environments, the Docker image is the easiest option
 
 - [Chef DK](https://downloads.chef.io/chefdk)
 - [Inspec GitHub](https://github.com/inspec/inspec)
 - [Docker Image](https://hub.docker.com/r/chef/inspec/)

#### Connecting to vRA appliances

Inspec uses SSH to connect to the vRA appliance, therefore this security check is not part of the validation checks.

Checks are run on the file level and will require validation against each vRA appliance individually.

#### Running with Inspec installation

Clone the project from GitHub

`git clone https://github.com/SDBrett/vra-7-hardening.git`

Enter the project directory

`cd vra-7-hardening`

Run Inspec against a vRA appliance using key pair
`inspec exec -t ssh@<user>@<IP/FQDN> -i <path to key> control/<control file>`

Run Inspec against a vRA appliance using password
`inspec exec -t ssh@<user>@<IP/FQDN> --password <password> control/<control file>`

#### Running with Inspec from Docker

When running Inspec from a container, you are replacing `inspec exec` with the relevant docker commands, but still 
using the same arguments.


Clone the project from GitHub

`git clone https://github.com/SDBrett/vra-7-hardening.git`

Obtain the Docker Image
'docker pull chef/inspec'

Enter the project directory

`cd vra-7-hardening`

Run Inspec against a vRA appliance using key pair
`docker run -it --rm -v $(pwd):/share chef/inspec -t ssh@<user>@<IP/FQDN> -i <path to key> control/<control file>`

Run Inspec against a vRA appliance using password
`docker run -it --rm -v $(pwd):/share chef/inspecc -t ssh@<user>@<IP/FQDN> --password <password> control/<control file>`


## License and Author

- Author::  Brett Johnson <brett@sdbrett.com>

Licensed under the MIT License.  https://opensource.org/licenses/MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
