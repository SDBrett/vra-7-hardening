# frozen_string_literal: true

control '10_Appliance_Data_At_Rest_10.1' do
  title ''
  desc ''

  describe postgres_hba_conf('/storage/db/pgdata/pg_hba.conf').where { type == 'local' and user == 'postgres'} do
    its('auth_method') { should eq ['trust'] }
  end
  describe postgres_hba_conf('/storage/db/pgdata/pg_hba.conf').where { type == 'local' and user != 'postgres'} do
    its('auth_method') { should_not eq ['trust'] }
  end
  describe postgres_hba_conf('/storage/db/pgdata/pg_hba.conf').where { type != 'local'} do
    its('auth_method') { should include 'md5' }
    its('auth_method') { should_not include 'trust' }
  end
end
