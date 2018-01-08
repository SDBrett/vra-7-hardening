control 'cis-dil-benchmark-1.4.2' do
  title 'Ensure bootloader password is set'
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."
  impact 1.0

  describe.one do
    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      describe file(f) do
        its(:content) { should match(/^set superusers/) }
        its(:content) { should match(/^password/) }
      end
    end
  end
end


control '1_Appliance_1.2' do
  title 'validate SSLv3 is disabled'
  desc 'As part of your hardening process, ensure that the deployed vRealize Automation appliance uses secure transmission channels.'
  
  describe file('/etc/haproxy/conf.d/20-vcac.cfg') do
  its('content') {should include 'no-sslv3'}
  end

  describe file('/etc/haproxy/conf.d/30-vro-config.cfg') do
  its('content') {should include 'no-sslv3'}
  end
end
