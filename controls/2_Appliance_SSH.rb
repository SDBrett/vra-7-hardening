# TODO: /etc/ssh/*keys
 
control 'check-ssh-private-key-permissiosn' do
  impact 1
  title 'Verify permissions of the ssh private keys'
  desc 'Verify permissiosn of the ssh private keys'

  keys = command('ls -1 /etc/ssh/*_keys').stdout.lines
  keys.each do |key|
    key.strip!
    describe file(key) do
      it { should be_owned_by 'root'  }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0600' }
    end
  end
end

# TODO: /etc/ssh/*key.pub

control 'check-ssh-config-permissiosn' do
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

control 'check-allowed-hosts' do
  impact 1
  title 'Client all should not be allowed'
  desc 'By default, the /etc/hosts.allow file
contains a generic entry, Sshd: ALL : ALLOW , that allows all access to the secure shell. Restrict this access as
appropriate for your organization.'
  describe etc_hosts_allow do
    its('options') {should_not cmp 'ALLOW'}
  end
end
