control 'vra7-appliance-userAccounts-3.1' do
  title 'Ensure password creation requirements are configured'
  desc "The pam_cracklib.so module checks the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the pam_cracklib.so options.\n\n* try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.\n* retry=3 - Allow 3 tries before sending back a failure.\n* minlen=14 - password must be 14 characters or more\n* dcredit=-1 - provide at least one digit\n* ucredit=-1 - provide at least one uppercase character\n* ocredit=-1 - provide at least one special character\n* lcredit=-1 - provide at least one lowercase character\n\nThe pam_pwquality.so module functions similarly but the minlen , dcredit , ucredit , ocredit , and lcredit parameters are stored in the /etc/security/pwquality.conf file. The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies.\n\nRationale: Strong passwords protect systems from being hacked through brute force methods."


  describe.one do
    %w(common-password system-auth).each do |f|
      describe file("/etc/pam.d/#{f}") do
        its(:content) { should match(/^password required pam_cracklib\.so (\S+\s+)*try_first_pass/) }
        its(:content) { should match(/^password required pam_cracklib\.so (\S+\s+)*retry=[3210]/) }
      end
    end
  end

  describe.one do
    %w(common-password system-auth).each do |f|
      describe file("/etc/pam.d/#{f}") do
        its(:content) { should match(/^password requisite pam_pwquality\.so (\S+\s+)*try_first_pass/) }
        its(:content) { should match(/^password requisite pam_pwquality\.so (\S+\s+)*retry=[3210]/) }
      end
    end
  end

  describe file('/etc/security/pwquality.conf') do
    its(:content) { should match(/^minlen = (1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\s*(?:#.*)?$/) }
    its(:content) { should match(/^dcredit= -[1-9][0-9]*\s*(?:#.*)?$/) }
    its(:content) { should match(/^lcredit= -[1-9][0-9]*\s*(?:#.*)?$/) }
    its(:content) { should match(/^ucredit= -[1-9][0-9]*\s*(?:#.*)?$/) }
    its(:content) { should match(/^ocredit= -[1-9][0-9]*\s*(?:#.*)?$/) }
  end
end

control 'cis-dil-benchmark-5.3.2' do
  title 'Ensure lockout for failed password attempts is configured'
  desc  "Lock out users after n unsuccessful consecutive login attempts. The first sets of changes are made to the PAM configuration files. The second set of changes are applied to the program specific PAM configuration file. The second set of changes must be applied to each program that will lock out users. Check the documentation for each secondary program for instructions on how to configure them to work with PAM. Set the lockout number to the policy in effect at your site.\n\nRationale: Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems."
  impact 0.0

  tag cis: 'distribution-independent-linux:5.3.2'
  tag level: 1

  describe 'cis-dil-benchmark-5.3.2' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-5.3.3' do
  title 'Ensure password reuse is limited'
  desc  "The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.\n\nRationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password. Note that these change only apply to accounts configured on the local system."
  impact 0.0

  tag cis: 'distribution-independent-linux:5.3.3'
  tag level: 1

  describe.one do
    %w(common-password system-auth).each do |f|
      describe file("/etc/pam.d/#{f}") do
        its(:content) { should match(/^password (\S+\s+)+pam_unix\.so (\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
      end

      describe file("/etc/pam.d/#{f}") do
        its(:content) { should match(/^password (\S+\s+)+pam_pwhistory\.so (\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
      end
    end
  end
end

control 'cis-dil-benchmark-5.3.4' do
  title 'Ensure password hashing algorithm is SHA-512'
  desc  "The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.\n\nRationale: The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords. Note that these change only apply to accounts configured on the local system."
  impact 0.0

  tag cis: 'distribution-independent-linux:5.3.4'
  tag level: 1

  describe.one do
    %w(common-password system-auth password-auth).each do |f|
      describe file("/etc/pam.d/#{f}") do
        its(:content) { should match(/^password (\S+\s+)+pam_unix\.so (\S+\s+)*sha512/) }
      end
    end
  end
end

shadow_files = ['/etc/shadow']
shadow_files << '/usr/share/baselayout/shadow' if file('/etc/nsswitch.conf').content =~ /^shadow:\s+(\S+\s+)*usrfiles/

passwd_files = ['/etc/passwd']
passwd_files << '/usr/share/baselayout/passwd' if file('/etc/nsswitch.conf').content =~ /^passwd:\s+(\S+\s+)*usrfiles/

control 'cis-dil-benchmark-5.4.1.1' do
  title 'Ensure password expiration is 90 days or less'
  desc  "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 90 days.\n\nRationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity."
  impact 1.0

  tag cis: 'distribution-independent-linux:5.4.1.1'
  tag level: 1

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 90 }
  end

  shadow_files.each do |f|
    shadow(f).users(/.+/).entries.each do |user|
      next if (user.passwords & %w(* !)).any?

      describe user do
        its(:max_days) { should cmp <= 90 }
      end
    end
  end
end