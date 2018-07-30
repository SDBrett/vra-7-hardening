# frozen_string_literal: true

control 'cis-dil-benchmark-1.4.2' do
  title 'Ensure bootloader password is set'
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."
  impact 1.0

  describe.one do
    %w[/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst].each do |f|
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
    its('content') { should include 'no-sslv3' }
  end

  describe file('/etc/haproxy/conf.d/30-vro-config.cfg') do
    its('content') { should include 'no-sslv3' }
  end

  describe file('/etc/apache2/vhosts.d/vcac.conf') do
    its('content') { should include 'SSLProtocol all -SSLv2 -SSLv3' }
  end

  describe file('/opt/vmware/etc/lighttpd/lighttpd.conf') do
    its('content') { should include 'ssl.use-sslv2 = "disable' }
    its('content') { should include 'ssl.use-sslv3 = "disable' }
  end

  describe file('/etc/vcac/security.properties') do
    its('content') { should include 'consoleproxy.ssl.server.protocols = TLSv1.2, TLSv1.1, TLSv1' }
  end

  describe xml('/etc/vco/app-server/server.xml') do
    its('Server/Service/Connector/attribute::sslEnabledProtocols') { should eq ['TLSv1.1,TLSv1.2,TLSv1'] }
  end

  describe xml('/etc/vcac/server.xml') do
    its('Server/Service/Connector/attribute::sslEnabledProtocols') { should eq ['TLSv1.1,TLSv1.2,TLSv1'] }
  end

  describe rabbitmq_config.params('ssl', 'versions') do
    it { should cmp ['tlsv1.2', 'tlsv1.1'] }
  end

  describe rabbitmq_config.params('rabbit', 'ssl_options', 'versions') do
    it { should cmp ['tlsv1.2', 'tlsv1.1'] }
  end

  describe xml('/opt/vmware/horizon/workspace/config/server.xml') do
    its { should include sslEnabledProtocols = 'TLSv1.1,TLSv1.2' }
  end

  describe file('/opt/vmware/share/htdocs/service/cafe-services/services.py') do
    its('content') { should include 'conn = httplib.HTTPS()' }
    its('content') { should_not include 'conn = httplib.HTTPS()' }
  end

  describe xml('/opt/vmware/horizon/workspace/conf/server.xml') do
    its('Server/Service/Connector[0]/attribute::SSLEnabled') { should eq ['true'] }
    its('Server/Service/Connector[1]/attribute::SSLEnabled') { should eq ['true'] }
    its('Server/Service/Connector[2]/attribute::SSLEnabled') { should eq ['true'] }
  end
end

control '1_Appliance_1.3' do
  title 'Validate appliance TLS settings'
  desc 'By default some localhost communication does not use TLS. You can enable TLS across all localhost connections to provide enhanced security.'

  describe file('/etc/vcac/vcac.keystore') do
    describe file(key) do
      it { should be_owned_by 'vcac' }
      it { should be_grouped_into 'pivotal' }
      its('mode') { should cmp '0640' }
    end
  end

  describe file('/etc/haproxy/conf.d/20-vcac-config.cfg') do
    its(:content) { should match(/(^server local 127.0.0.1)*1500/) }
  end

  describe file('/etc/apache2/vhosts.d/vcac.conf') do
    its('content') { should include 'SSLProtocol all -SSLv2 -SSLv3' }
  end

  describe file '/etc/haproxy/conf.d/20-vcac.cfg' do
    its('content') { should_not match(/^\s+server local 127.0.0.1:8080/) }
  end
end

control 'Disabled TLS 1.0' do
  title 'Disable TLS 1.0 in applicable vRealize Automation components'
  desc 'There is no directive to disable TLS 1.0 in Lighttpd. The restriction on TLS 1.0 use can be partially mitigated by enforcing that OpenSSL does not use cipher suites of TLS 1.0 as described in step 2 below.'

  describe file('/etc/haproxy/conf.d/20-vcac.cfg') do
    its('content') { should include 'bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers TLSv1+HIGH:!aNULL:!eNULL:!3DES:!RC4:!CAMELLIA:!DH:!kECDHE:@STRENGTH no-sslv3 no-tlsv10' }
  end

  describe file('/etc/haproxy/conf.d/30-vro-config.cfg') do
    its('content') { should include 'bind :8283 ssl crt /opt/vmware/etc/lighttpd/server.pem ciphers TLSv1+HIGH:!aNULL:!eNULL:!3DES:!RC4:!CAMELLIA:!DH:!kECDHE:@STRENGTH no-sslv3 no-tls10' }
  end

  describe file('/opt/vmware/etc/lighttpd/lighttpd.conf') do
    its('content') { should include 'ssl.cipher-list = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSACHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSAAES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"' }
  end
end
