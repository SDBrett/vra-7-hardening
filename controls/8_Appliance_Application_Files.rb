
control '8_Appliance_Application_Files_8.1' do
  title 'Validate application resources'
  desc 'Review vRealize Automation application resources and restrict file permissions.'
  describe file '/usr/lib/PolicyKit/polkit-set-default-helper' do
    it { should be_owned_by 'polkituser' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/lib/PolicyKit/polkit-read-auth-helper' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'polkituser' }
    it { should be_setgid }
    its('mode') { should cmp '02755' }
  end

  describe file '/usr/lib/PolicyKit/polkit-grant-helper-pam' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'polkituser' }
    it { should be_setuid }
    its('mode') { should cmp '04750' }
  end
  describe file '/usr/lib/PolicyKit/polkit-grant-helper' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'polkituser' }
    it { should be_setgid }
    its('mode') { should cmp '02755' }
  end

  describe file '/usr/lib/PolicyKit/polkit-explicit-grant-helper' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'polkituser' }
    it { should be_setgid }
    its('mode') { should cmp '02755' }
  end

  describe file '/usr/lib/PolicyKit/polkit-revoke-helper' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'polkituser' }
    it { should be_setgid }
    its('mode') { should cmp '02755' }
  end

  describe file '/usr/lib64/ssh/ssh-keysign' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04711' }
  end

  #describe file '/usr/sbin/utempter' do
  #  it { should be_owned_by 'root' }
  #  it { should be_grouped_into 'tty' }
  #  it { should be_setgid }
  #  its('mode') { should cmp '0715' }
  #end

  describe file '/usr/bin/passwd' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/chage' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/chfn' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/sudo' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/newgrp' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/crontab' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'trusted' }
    it { should be_setuid }
    its('mode') { should cmp '04750' }
  end

  describe file '/usr/bin/chsh' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/gpasswd' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/usr/bin/expiry' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/lib64/dbus-1/dbus-daemon-launch-helper' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'messagebus' }
    it { should be_setuid }
    its('mode') { should cmp '04750' }
  end

  describe file '/sbin/unix_chkpwd' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/sbin/unix2_chkpwd' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'shadow' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/opt/likewise/bin/ksu' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/bin/su' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/bin/ping' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/bin/ping6' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/bin/mount' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end

  describe file '/bin/umount' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    it { should be_setuid }
    its('mode') { should cmp '04755' }
  end
end