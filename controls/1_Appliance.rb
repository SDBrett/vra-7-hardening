# frozen_string_literal: true

disallowed_ciphers = %w[TLS_DH_DSS_WITH_AES_128_CBC_SHA
                        TLS_DH_DSS_WITH_AES_256_CBC_SHA
                        TLS_DH_RSA_WITH_AES_256_CBC_SHA
                        TLS_DHE_DSS_WITH_AES_128_CBC_SHA
                        TLS_DHE_DSS_WITH_AES_256_CBC_SHA
                        TLS_DHE_RSA_WITH_AES_128_CBC_SHA
                        TLS_DHE_RSA_WITH_AES_256_CBC_SHA]

strong_ciphers = %w[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    TLS_EC
                    DHE_ECDSA_WITH_AES_128_CBC_SHA256
                    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
                    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
                    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384]

control '1_Appliance_1.1' do
  title 'Ensure bootloader password is set'
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."

      describe file('/boot/grub/menu.lst') do
        its(:content) { should match(/^set superusers/) }
        its(:content) { should match(/^password/) }
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
    before do
      skip if not File.exist?('/etc/apache2/vhosts.d/vcac.conf')
    end
  end

  describe file('/opt/vmware/etc/lighttpd/lighttpd.conf') do
    its('content') { should include 'ssl.use-sslv2 = "disable' }
    its('content') { should include 'ssl.use-sslv3 = "disable' }
  end

  describe file('/etc/vcac/security.properties') do
    its('content') { should include 'consoleproxy.ssl.server.protocols = TLSv1.2, TLSv1.1, TLSv1' }
  end

  describe xml('/etc/vco/app-server/server.xml') do
    its('/Server/Service/Connector@sslEnabledProtocols') { should eq ['TLSv1.1,TLSv1.2,TLSv1'] }
  end

  describe xml('/etc/vcac/server.xml') do
    its('/Server/Service/Connector/@sslEnabledProtocols') { should eq ['TLSv1.1,TLSv1.2,TLSv1'] }
  end

  # Errors found using the rabbitmq_config resource
 # describe rabbitmq_config.params('ssl', 'versions') do
 #   it { should cmp ['tlsv1.2', 'tlsv1.1'] }
 # end

 # describe json('/etc/rabbitmq/('ssl', 'versions') do
 #   it { should cmp 'tlsv1.2' }
 # end

  describe file('/opt/vmware/share/htdocs/service/cafe-services/services.py') do
    its('content') { should include 'conn = httplib.HTTPS()' }
    its('content') { should_not include 'conn = httplib.HTTPS()' }
  end

  describe xml('/opt/vmware/horizon/workspace/conf/server.xml') do
    its('/Server/Service/Connector[1]/@SSLEnabled') { should eq ['true'] }
    its('/Server/Service/Connector[1]/@sslEnabledProtocols') { should cmp 'TLSv1.1,TLSv1.2' }
    its('/Server/Service/Connector[3]/@SSLEnabled') { should eq ['true'] }
    its('/Server/Service/Connector[3]/@sslEnabledProtocols') { should cmp 'TLSv1.1,TLSv1.2' }
  end
end

control '1_Appliance_1.3' do
  title 'Validate appliance TLS settings'
  desc 'By default some localhost communication does not use TLS. You can enable TLS across all localhost connections to provide enhanced security.'

  describe file('/etc/vcac/vcac.keystore') do
    it { should be_owned_by 'vcac' }
    it { should be_grouped_into 'pivotal' }
    its('mode') { should cmp '0640' }
  end

  describe file('/etc/haproxy/conf.d/20-vcac.cfg') do
    its(:content) { should match(/(^server local 127.0.0.1)*1500/) }
  end

  describe file('/etc/apache2/vhosts.d/vcac.conf') do
    its('content') { should include 'SSLProtocol all -SSLv2 -SSLv3' }
    	before do
	  skip if not File.exist?('/etc/apache2/vhosts.d/vcac.conf')
	end
  end

  describe file '/etc/haproxy/conf.d/20-vcac.cfg' do
    its('content') { should_not match(/^\s+server local 127.0.0.1:8080/) }
  end
end

control '1_Appliance_1.4' do
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

control '1_Appliance_1.5' do
  title 'Validate appliance TLS settings'
  desc 'By default some localhost communication does not use TLS. You can enable TLS across all \
        localhost connections to provide enhanced security.'
  describe xml('/etc/vcac/server.xml') do
    its('/Server/Service/Connector@scheme') { should eq 'https' }
    its('/Server/Service/Connector@secure') { should eq 'true' }
    its('/Server/Service/Connector@SSLEnabled') { should eq 'true' }
    its('/Server/Service/Connector@sslProtocol') { should eq 'TLS' }
    its('/Server/Service/Connector@keystoreFile') { should eq '/etc/vcac/vcac.keystore' }
    its('/Server/Service/Connector@keyAlias') { should eq 'apache' }
    its('/Server/Service/Connector@keystorePass') { should_not eq nil }
  end

  describe xml('/etc/vco/app/server.xml') do
    its('/Server/Service/Connector@scheme') { should eq 'https' }
    its('/Server/Service/Connector@secure') { should eq 'true' }
    its('/Server/Service/Connector@SSLEnabled') { should eq 'true' }
    its('/Server/Service/Connector@sslProtocol') { should eq 'TLS' }
    its('/Server/Service/Connector@keystoreFile') { should eq '/etc/vcac/vcac.keystore' }
    its('/Server/Service/Connector@keyAlias') { should eq 'apache' }
    its('/Server/Service/Connector@keystorePass') { should_not eq nil }
  end
end

control '1_Appliance_1.6' do
  title 'Disable disallowed ciphers'
  desc 'Validates disallowed ciphers are disallowed'
  security_properties_file = File.open('/etc/vcac/security.properties').read
  current_disallowed = security_properties_file.match(/(?<=consoleproxy.ssl.ciphers.disallowed=).*$/)[0]
  describe current_disallowed do
    disallowed_ciphers.each do |s|
      its('content') { should_not include s }
    end
  end
end

control '1_Appliance_1.7' do
  title 'Validate appliance TLS settings'
  desc 'By default some localhost communication does not use TLS. You can enable TLS across all localhost connections \
        to provide enhanced security.'
  describe xml('/etc/vcac/server.xml') do
    its('/Server/Service/Connector@ciphers') { should_not eq nil }
    strong_ciphers.each do |s|
      its('/Server/Service/Connector@ciphers') { should include s }
    end
  end
end


control '1_Appliance_1.8' do
  title 'Verify TLS encryption on local transmission'
  desc 'By default some localhost communication does not use TLS. You can enable TLS across all localhost connections \
 to provide enhanced security.'
  describe file('/etc/haproxy/conf.d/20-vcac.cfg') do
    its('content') { should_not match(/^(\s+)((server local 127.0.0.1).)((?!ssl verify none).)*$/) }
  end
end