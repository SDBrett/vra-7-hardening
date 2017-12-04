=begin
control 'additional-administrative-account' do
    title 'Verify administrative account has been created'
    desc  "As a security best practice, create and configure local administrative accounts for Secure Shell (SSH) on your
virtual appliance host machines. Also, remove root SSH access after you create the appropriate accounts."
    impact 1.0
  
    tag vra: 'Create-Local-Administrator-Account-for-Secure-Shell'
    tag level: 1
  
    describe file('/etc/ssh/sshd_config') do
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
=end
