control 'cis-dil-benchmark-2.2.1.1' do
    title 'Ensure time synchronization is in use'
    desc  "System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.\n\nRationale: Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations."
    impact 0.0
  
    tag cis: 'distribution-independent-linux:2.2.1.1'
    tag level: 1
  
    describe.one do
      describe package('ntp') do
        it { should be_installed }
      end
  
      describe command('ntpd') do
        it { should exist }
      end
  
      describe package('chrony') do
        it { should be_installed }
      end
  
      describe command('chronyd') do
        it { should exist }
      end
    end
  end
  
  control 'cis-dil-benchmark-2.2.1.2' do
    title 'Ensure ntp is configured'
    desc "ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on NTP can be found at http://www.ntp.org. ntp can be configured to be a client and/or a server.\nThis recommendation only applies if ntp is in use on the system.\n\nRationale: If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
    impact 1.0
  
    tag cis: 'distribution-independent-linux:2.2.1.2'
    tag level: 1
  
    only_if do
      package('ntp').installed? || command('ntpd').exist?
    end
  
    describe ntp_conf do
      its(:server) { should_not eq nil }
    end
  
    describe ntp_conf.restrict.to_s do
      it { should match(/default\s+(\S+\s+)*kod(?:\s+|\s?")/) }
      it { should match(/default\s+(\S+\s+)*nomodify(?:\s+|\s?")/) }
      it { should match(/default\s+(\S+\s+)*notrap(?:\s+|\s?")/) }
      it { should match(/default\s+(\S+\s+)*nopeer(?:\s+|\s?")/) }
      it { should match(/default\s+(\S+\s+)*noquery(?:\s+|\s?")/) }
    end
  
    describe.one do
      describe file('/etc/init.d/ntp') do
        its(:content) { should match(/^RUNASUSER=ntp\s*(?:#.*)?$/) }
      end
  
      describe file('/etc/sysconfig/ntpd') do
        its(:content) { should match(/^OPTIONS="(?:.)?-u ntp:ntp\s*(?:.)?"\s*(?:#.*)?$/) }
      end
  
      describe file('/usr/lib/systemd/system/ntpd.service') do
        its(:content) { should match(%r{^ExecStart=/usr/s?bin/ntpd (?:.)?-u ntp:ntp\s*(?:.)?$}) }
      end
    end
  end