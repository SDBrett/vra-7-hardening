# frozen_string_literal: true

shadow_files = ['/etc/shadow']
shadow_files << '/usr/share/baselayout/shadow' if file('/etc/nsswitch.conf').content =~ /^shadow:\s+(\S+\s+)*usrfiles/

control 'cis-dil-benchmark-5.4.1.1' do
  title 'Ensure password expiration is 90 days or less'
  desc  ''
  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 365 }
  end

  shadow_files.each do |f|
    shadow(f).users(/.+/).entries.each do |user|
      next if (user.passwords & %w[* !]).any?

      describe user do
        its(:max_days) { should cmp <= 90 }
      end
    end
  end
end

control '4_Appliance_User_Accounts_4.2' do
  title 'Verify at least one additional administrative account has been created'
  desc 'As a security best practice, create and configure local administrative accounts for Secure Shell (SSH) on your
  virtual appliance host machines. Also, remove root SSH access after you create the appropriate accounts.'
  describe etc_group.where(name: 'wheel').users do
    its('count') { should be > 2 }
  end
end
