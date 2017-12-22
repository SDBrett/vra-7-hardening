control '6_Appliance_VAMI_6.1' do
    title 'Verify at least one additional VAMI user has been created'
    desc 'The root user account for the Virtual Appliance Management Interface uses PAM for authentication, so the clipping levels set by PAM also apply. If you have not appropriately isolated the Virtual Appliance Management Interface, a lock out of the system root account could occur if an attacker attempts to brute force the login. In addition, where the root account is considered insufficient to provide non-repudiation by more than one person in your organization, then you might elect to change the admin user for the management interface.'
    describe etc_group.where(name: 'vami').users do
        its('count') { should be > 2}
    end
end