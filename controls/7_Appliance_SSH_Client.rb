# frozen_string_literal: true

control '2_Appliance_SSH_Client_7.1' do
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

control '2_Appliance_SSH_Client_7.2' do
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

control '2_Appliance_SSH_Client_7.3' do
  impact 1
  title 'Verify permissions of ssh_config'
  desc 'Verifies that only root can modify ssh_config'
  describe file('/etc/ssh/ssh_config') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    its('mode') { should cmp '0644' }
  end
end

control '2_Appliance_SSH_Client_7.4' do
  title 'Verify SSH client configuration'
  desc ''
  describe ssh_config do
    its(:Protocol) { should cmp 2 }
    its(:GatewayPorts) { should eq 'no' }
    its(:Ciphers) { should eq 'aes256-ctr,aes128-ctr' }
    its(:MACs) { should eq 'hmac-sha1' }
    its(:GSSAPIAuthentication) { should eq 'no' }
    its(:KeberosAuthentication) { should eq 'no' }
  end
end
