# frozen_string_literal: true

control '2_Appliance_SSHD_2.1' do
  title 'Verify that the SSH service is not set to auto start'
  desc  'SSH access should only be used for troubleshooting. As such, it should not be configured to auto start on boot. Check for running is not configured as SSH is required for access to run compliance.'
  describe service('sshd') do
    it { should_not be_enabled }
  end
end

control '2_Appliance_SSHD_2.2' do
  title 'Verify permissions of the ssh private keys'
  desc 'Verify permissions of the ssh private keys'
  keys = command('ls -1 /etc/ssh/*_key').stdout.lines
  keys.each do |key|
    key.strip!
    describe file(key) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0600' }
    end
  end
end

control '2_Appliance_SSHD_2.3' do
  title 'Verify permissions of the ssh public keys'
  desc 'Verify permissions of the ssh public keys'
  keys = command('ls -1 /etc/ssh/*_key.pub').stdout.lines
  keys.each do |key|
    key.strip!
    describe file(key) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end

control '2_Appliance_SSHD_2.4' do
  impact 1
  title 'Verify permissions of ssh_config'
  desc 'Verifies that only root can modify sshd_config'
  describe file('/etc/ssh/ssh_config') do
    it { should exist }
    it { should_not be_readable.by 'group' }
    it { should_not be_writable.by 'group' }
    it { should_not be_executable.by 'group' }
    it { should_not be_readable.by 'other' }
    it { should_not be_writable.by 'other' }
    it { should_not be_executable.by 'other' }
    its(:uid) { should cmp 0 }
    its(:gid) { should cmp 0 }
  end
end

control '2_Appliance_SSHD_2.5' do
  title 'Client all should not be allowed'
  desc 'By default, the /etc/hosts.allow file contains a generic entry, sshd: ALL : ALLOW , that allows all access to the secure shell. Restrict this access as appropriate for your organization.'
  describe etc_hosts_allow.where { daemon == 'sshd' } do
    its('client_list') { should_not include ['ALL'] }
  end
end

control '2_Appliance_SSHD_2.6' do
  title 'Verify SSH server configuration'
  desc ''
  describe sshd_config do
    its(:Protocol) { should cmp 2 }
    its(:MaxSessions) { should cmp 1 }
    its(:X11Forwarding) { should eq 'no' }
    its(:PermitRootLogin) { should eq 'no' }
    its(:PermitEmptyPasswords) { should eq 'no' }
    its(:PermitUserEnvironment) { should eq 'no' }
    its(:Ciphers) { should_not be_nil }
    its(:PermitUserEnvironment) { should eq 'no' }
    its(:RhostsRSAAuthentication) { should eq 'no' }
    its(:UsePrivilegeSeparation) { should eq 'yes' }
    its(:AllowTcpForwarding) { should eq 'no' }
    its(:GatewayPorts) { should eq 'no' }
    its(:Compression) { should(eq 'delayed') || should(eq 'no') }
    its(:PermitTunnel) { should eq 'no' }
    its(:StrictModes) { should eq 'yes' }
    its(:Ciphers) { should eq 'aes256-ctr,aes128-ctr' }
    its(:MACs) { should eq 'hmac-sha1' }
    its(:GSSAPIAuthentication) { should eq 'no' }
    its(:KeberosAuthentication) { should eq 'no' }
  end
end
