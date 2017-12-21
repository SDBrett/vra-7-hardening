control 'vra7-appliance-rootAccount-3.1' do
  title 'Ensure password history and retry limits are set'
  desc "Validates failed login retry limit and password history"
  describe file('/etc/pam.d/common-password') do
    its(:content) { should match(/^password(\s+)required(\s+)pam_pwhistory\.so(\s+)enforce_for_root(\s+)(\S+\s+)*retry=[3210]/) }
    its(:content) { should match(/^password(\s+)required(\s+)pam_pwhistory\.so(\s+)enforce_for_root(\s+)(\S+\s+)*remember=[56789]/) }
  end
end

control 'vra7-appliance-rootAccount-3.2' do
  title 'Ensure use_authok is configured'
  desc  'When password changing enforce the module to set the new password to the one provided by a previously stacked password module'
  describe file("/etc/pam.d/common-password") do
    its(:content) { should match(/^password(\s+)required(\s+)pam_unix2\.so(\s+)(\S+\s+)*use_authtok/) }
  end
end

control 'vra7-appliance-rootAccount-3.3' do
  title 'Ensure root password hashing algorithm is SHA-512'
  desc  'The use of SHA-512 encryption for the root password provides stronger protection about brute force attacks'
  describe file("/etc/shadow") do
    its(:content) { should match(/^^root:\$6\$/) }
  end
end
 
control 'vra7-appliance-rootAccount-3.3' do
  title 'Check that root password expiration time has not been increased above default of 365 days'
  desc  'The root account has a default password expiration of 365 days. For hardended systems this should be reduced to 90 days'
  describe shadow.users('root') do
    its('max_days') {should cmp <= 365}
  end
end
