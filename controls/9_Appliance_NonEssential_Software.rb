# frozen_string_literal: true

control '9_Appliance_NonEssential_Software_9.1' do
  title 'Verify Non-Essential software is not loaded and reduce attack surface'
  desc 'Verify software loaded with modprob'

  describe file('/etc/modprobe.conf.local') do
    its('content') { should include 'install usb-storage /bin/true' }
    its('content') { should include 'install bluetooth /bin/true' }
    its('content') { should include 'install sctp /bin/true' }
    its('content') { should include 'install dccp/bin/true' }
    its('content') { should include 'install dccp_ipv4/bin/true' }
    its('content') { should include 'install dccp_ipv6/bin/true' }
    its('content') { should include 'install bridge /bin/false' }
    its('content') { should include 'install rds /bin/true' }
    its('content') { should include 'install tipc /bin/true' }
    its('content') { should include 'install ipx /bin/true' }
    its('content') { should include 'install appletalk /bin/true' }
    its('content') { should include 'install decnet /bin/true' }
    its('content') { should include 'install ieee1394 /bin/true' }
    its('content') { should include 'install bridge /bin/false' }
  end
end
