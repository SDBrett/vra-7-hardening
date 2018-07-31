# frozen_string_literal: true

control '6_Appliance_VAMI_6.1' do
  title 'Verify root account as been removed from vami group'
  desc 'An additional VAMI user account should be created and added to the vami group. After this has been done, it is recommended that the root account is removed from the vami group.'
  describe etc_group.where(name: 'vami') do
    its('users') { should_not include 'root' }
  end
end

control '1_Appliance_VAMI_6.2' do
  title 'Validate if FIPS has been enabled'
  desc 'The vRealize Automation appliance now uses the Federal Information Processing Standard (FIPS) 140-2 certified version of OpenSSL for data-in-transit over TLS on all inbound and outbound network traffic.'
  describe command 'vcac-vami fips status' do
    its('stdout') { should_not match 'FIPS is DISABLED!' }
  end
end
