# frozen_string_literal: true

control '5_Appliance_NTP_5.1' do
  title 'Validate permissions and configuration of /etc/ntp.conf file'
  describe file '/etc/ntp.conf' do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
    its('mode') { should cmp '0640' }
  end
  describe ntp_conf('/etc/ntp.conf') do
    its('restrict') { should include 'default kod nomodify notrap nopeer noquery' }
    its('restrict') { should include '-6 default kod nomodify notrap nopeer noquery' }
    its('restrict') { should include '127.0.0.1' }
    its('restrict') { should include '-6 ::1' }
  end
end

control '5_Appliance_NTP_5.2' do
  title 'Validate permissions and configuration of /etc/ntp.conf file'
  describe package 'ntp' do
    it { should be_installed }
  end

  describe service('ntp') do
    it { should be_enabled }
    it { should be_running }
  end
end
