control 'cis-dil-benchmark-1.4.2' do
  title 'Ensure bootloader password is set'
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.4.2'
  tag level: 1

  describe.one do
    %w(/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst).each do |f|
      describe file(f) do
        its(:content) { should match(/^set superusers/) }
        its(:content) { should match(/^password/) }
      end
    end
  end
end
