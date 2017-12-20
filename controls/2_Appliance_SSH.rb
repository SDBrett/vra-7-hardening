control 'check-ssh-private-key-permissions' do
  impact 1
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

control 'check-ssh-public-key-permissions' do
  impact 1
  title 'Verify permissions of the ssh public keys'
  desc 'Verify permissions of the ssh public keys'
  keys = command('ls -1 /etc/ssh/_key.pub').stdout.lines
  keys.each do |key|
    key.strip!
    describe file(key) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end


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
contains a generic entry, sshd: ALL : ALLOW , that allows all access to the secure shell. Restrict this access as
appropriate for your organization.'
  describe etc_hosts_allow do
    its('options') { should_not cmp 'ALLOW' }
  end
end

control 'cis-dil-benchmark-5.2.2' do
  title 'Ensure SSH Protocol is set to 2'
  desc  "SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure.\n\nRationale: SSH v1 suffers from insecurities that do not affect SSH v2."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.2.2'
  tag level: 1

  describe sshd_config do
    its(:Protocol) { should cmp 2 }
  end
end

control 'cis-dil-benchmark-5.2.4' do
  title 'Ensure SSH X11 forwarding is disabled'
  desc  "The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.\n\nRationale: Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.2.4'
  tag level: 1

  describe sshd_config do
    its(:X11Forwarding) { should eq 'no' }
  end
end

control 'cis-dil-benchmark-5.2.7' do
  title 'Ensure SSH HostbasedAuthentication is disabled'
  desc  "The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with successful public key client host authentication. This option only applies to SSH Protocol Version 2.\n\nRationale: Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an additional layer of protection ."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.2.7'
  tag level: 1

  describe sshd_config do
    its(:HostbasedAuthentication) { should eq 'no' }
  end
end

control 'cis-dil-benchmark-5.2.8' do
  title 'Ensure SSH root login is disabled'
  desc  "The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no.\n\nRationale: Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su. This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident"
  impact 1.0

  tag cis: 'distribution-independent-linux:5.2.8'
  tag level: 1

  describe sshd_config do
    its(:PermitRootLogin) { should eq 'no' }
  end
end

control 'cis-dil-benchmark-5.2.10' do
  title 'Ensure SSH PermitUserEnvironment is disabled'
  desc  "The PermitUserEnvironment option allows users to present environment options to the ssh daemon.\n\nRationale: Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)"
  impact 1.0

  tag cis: 'distribution-independent-linux:5.2.10'
  tag level: 1

  describe sshd_config do
    its(:PermitUserEnvironment) { should eq 'no' }
  end
end

control 'cis-dil-benchmark-5.2.11' do
  title 'Ensure only approved ciphers are used'
  desc "This variable limits the types of ciphers that SSH can use during communication.\n\nRationale: 
  Based on research conducted at various institutions, it was determined that the symmetric portion of the SSH Transport Protocol 
  (as described in RFC 4253) has security weaknesses that allowed recovery of up to 32 bits of plaintext 
  from a block of ciphertext that was encrypted with the Cipher Block Chaining (CBD) method. 
  From that research, new Counter mode algorithms (as described in RFC4344) were designed that are n
  ot vulnerable to these types of attacks and these algorithms are now recommended for standard use."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.2.11'
  tag level: 1

  describe sshd_config do
    its(:Ciphers) { should_not be_nil }
  end

  if sshd_config.Ciphers
    describe sshd_config.Ciphers.split(',').each do
      # TODO: Add excluded ciphers
      it { should match(/-aes256-ctr$/) or should match (/-aes128-ctr$/)}
      it { should_not match(/-cbc$/) }
    end
  end
end
