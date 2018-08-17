# vRA7 Security Hardening Profile


This profile checks settings on a vRA appliance against those specified within the [vRA Hardening Guide](https://docs.vmware.com/en/vRealize-Automation/7.2/vrealize-automation-72-hardening.pdf).

SSH access is required to the appliance and it's recommended to use key pair authentication instead of password.

For environments with multiple vRA Appliances, this will need to be run against each one individually.

The instructions focus on using the Chef Inspec Docker image as this has proven to be more reliable than installing Inspec either through ChefDK or standalone. Primarily due to managing Ruby and dealing with networks which don't have internet access.

If you are using an installed version of Inspec instead of the Docker image, replace docker command strings with 'inspec'.

Currently this project cover most, but not all appliance configuration settings in the guide. 

## Prerequisites

- Docker host which can reach vRA Appliances 
- [Inspec Docker Image](https://hub.docker.com/r/chef/inspec/)


## Usage

Obtain the Docker image

` docker pull chef/inspec`

The profile needs to be accessible from the Docker container at run time, this can be done by mounting the directory into the container, or using a Git repo URL in the command

Mount into container:

```
git clone https://github.com/sdbrett/vra-7-hardening
cd vra-7-hardening
# With password
docker run --rm -it -v $(pwd):/profile chef/inspec exec /profile -t ssh://<user>@<appliance FQDN> --password <PASSWORD>

# With Key pair
docker run --rm -it -v $(pwd):/profile chef/inspec exec -v <Path to private key directory>:/ssl/ /profile -t ssh://<user>@<appliance FQDN> -i /ssl/private.key

```

If you run these commands against an appliance without any hardening steps from the guide completed, you will get a lot of failures and the output is quite verbose.

Initially you may wish to limit your checks to a specific control file. To do this modify the command to point to a specific file.
```
# Use
docker run --rm -it -v $(pwd):/profile chef/inspec exec /profile/controls/1_Appliance.rb 

# Instead of 
docker run --rm -it -v $(pwd):/profile chef/inspec exec /profile

```

## TODO

- Work to resolve rabbitmq_config 
- Make a fancy table to highlight setting coverage
- Look into controlling verbosity of output, particularly when checking file contents
- Smile more


## License and Author

- Author::  Brett Johnson <brett@sdbrett.com>

Licensed under the MIT License.  https://opensource.org/licenses/MIT

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
