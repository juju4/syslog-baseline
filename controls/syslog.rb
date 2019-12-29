# frozen_string_literal: true

# copyright: 2015, The Authors
# license: All rights reserved

title 'syslog section'

syslog_servers = input('syslog_servers', value: false, description: 'Should we control that central syslog servers are configured')
# syslog_servers = %( syslog1.example.com syslog2.example.com)
syslog_servers_files = input('syslog_servers_files', value: false, description: 'Where central syslog servers should be configured')
# syslog_servers_files = %( /etc/rsyslog.conf /etc/rsyslog.d/myfile )
syslog_content_check = input(
  'syslog_content_check',
  value: [
    'Linux version',
    'kernel: ',
    'systemd[',
    'origin software="rsyslogd"'
  ],
  description: 'list of strings to check as present in system log'
)
syslog_notcontent_check = input(
  'syslog_notcontent_check',
  value: [
    'open error: Permission denied',
    'syslogd: action \'action .*\' resumed',
    'syslogd: action \'action .*\' suspended'
  ],
  description: 'list of strings to check as not present in system log'
)

control 'syslog-1.0' do # A unique ID for this control
  impact 0.7 # The criticality, if this control fails.
  title 'syslogd should be present'
  desc 'Ensure syslogd executable and configuration are present'
  if os.darwin?
    describe file('/usr/sbin/syslogd') do
      it { should be_file }
      it { should be_executable }
      it { should be_owned_by 'root' }
    end
  elsif os.redhat?
    describe file('/sbin/rsyslogd') do
      it { should be_file }
      it { should be_executable }
      it { should be_owned_by 'root' }
    end
  elsif os.suse?
    describe file('/sbin/rsyslogd') do
      it { should be_file }
      it { should be_executable }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0755' }
    end
  else
    describe file('/usr/sbin/rsyslogd') do
      it { should be_file }
      it { should be_executable }
      it { should be_owned_by 'root' }
    end
  end
end

control 'syslog-2.0' do
  impact 0.7
  title 'syslog.conf'
  desc 'Check syslog configuration'
  if os.darwin?
    describe file('/etc/syslog.conf') do
      it { should be_file }
      ## https://discussions.apple.com/thread/524392?start=0&tstart=0
      its('content') { should match 'install.*\s+@127.0.0.1:32376' }
      ## TODO: add SIEM collector
    end
  elsif os.redhat?
    describe file('/etc/rsyslog.conf') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
    end
  elsif os.suse?
    describe file('/etc/syslog.conf') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0640' }
    end
  else
    describe file('/etc/rsyslog.conf') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end

control 'syslog-3.0' do
  impact 0.7
  title 'syslogd should be running'
  desc 'Ensure syslogd is running'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') }
  if os.darwin?
    describe processes('syslogd') do
      its('users') { should eq ['root'] }
      its('entries.length') { should eq 1 }
    end
  elsif os.redhat?
    describe processes('rsyslogd') do
      its('users') { should eq ['root'] }
      its('entries.length') { should eq 1 }
    end
  else
    describe processes('rsyslogd') do
      its('users') { should eq ['syslog'] }
      its('entries.length') { should eq 1 }
    end
  end
end

control 'syslog-4.0a' do
  impact 0.7
  title 'syslogd should have log files - darwin'
  desc 'Ensure syslogd logs file are present'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') }
  if os.darwin?
    describe file('/var/log') do
      it { should be_directory }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0755' }
    end
    describe file('/var/log/system.log') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0640' }
    end
    describe file('/var/log/asl/StoreData') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end

control 'syslog-4.0b' do
  impact 0.7
  title 'syslogd should have log files - redhat'
  desc 'Ensure syslogd logs file are present'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') }
  if os.redhat?
    describe file('/var/log') do
      it { should be_directory }
      it { should be_owned_by 'root' }
      its('group') { should eq 'root' }
      it { should_not be_more_permissive_than('0755') }
    end
    describe file('/var/log/messages') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('group') { should eq 'root' }
      it { should_not be_more_permissive_than('0600') }
    end
    describe file('/var/log/secure') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('group') { should eq 'root' }
      it { should_not be_more_permissive_than('0600') }
    end
    describe file('/var/log/wtmp') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('group') { should eq 'utmp' }
      it { should_not be_more_permissive_than('0664') }
    end
  end
end

control 'syslog-4.0c' do
  impact 0.7
  title 'syslogd should have log files - debian/ubuntu'
  desc 'Ensure syslogd logs file are present'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') }
  if os.debian?
    ## ubuntu
    describe file('/var/log') do
      it { should be_directory }
      it { should be_owned_by 'root' }
      its('group') { should eq 'syslog' }
      it { should_not be_more_permissive_than('0775') }
    end
    describe file('/var/log/auth.log') do
      it { should be_file }
      it { should be_owned_by 'syslog' }
      its('group') { should eq 'adm' }
      it { should_not be_more_permissive_than('0640') }
    end
    describe file('/var/log/syslog') do
      it { should be_file }
      it { should be_owned_by 'syslog' }
      its('group') { should eq 'adm' }
      it { should_not be_more_permissive_than('0640') }
    end
    describe file('/var/log/wtmp') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('group') { should eq 'utmp' }
      it { should_not be_more_permissive_than('0664') }
    end
  end
end

# content may vary depending on recent boot and general system state
control 'syslog-4.1' do
  impact 0.7
  title 'syslogd log files content check'
  desc 'Validate syslogd logs file content'
  if os.darwin?
    describe file('/var/log/system.log') do
      its('content') { should match 'last message repeated' }
      its('content') { should match 'WindowServer' }
    end
  elsif os.redhat?
    describe file('/var/log/messages') do
      syslog_content_check.each do |str|
        its('content') { should match str }
      end
      syslog_notcontent_check.each do |str|
        its('content') { should_not match str }
      end
    end
  else
    ## ubuntu
    describe file('/var/log/syslog') do
      syslog_content_check.each do |str|
        its('content') { should match str }
      end
      syslog_notcontent_check.each do |str|
        its('content') { should_not match str }
      end
    end
  end
end

control 'syslog-5.0' do
  impact 0.7
  title 'syslogd updated log files'
  desc 'Ensure syslogd logs file were updated less than 900s in the past'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') }
  if os.darwin?
    describe file('/var/log/system.log').mtime.to_i do
      it { should <= Time.now.to_i }
      it { should >= Time.now.to_i - 900 }
    end
  elsif os.redhat?
    describe file('/var/log/messages').mtime.to_i do
      it { should <= Time.now.to_i }
      it { should >= Time.now.to_i - 900 }
    end
  else
    describe file('/var/log/syslog').mtime.to_i do
      it { should <= Time.now.to_i }
      it { should >= Time.now.to_i - 900 }
    end
  end
end

if syslog_servers
  control 'syslog-6.0' do
    title 'Central syslog servers'
    desc 'Ensure central remote syslog servers are configured in defined files'
    syslog_servers.each do |server|
      syslog_servers_files.each do |file|
        describe file(file.to_s) do
          it { should be_file }
          its('content') { should match "^[^#].*@#{server}" }
        end
      end
    end
  end
end
