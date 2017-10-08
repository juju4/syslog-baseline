# encoding: utf-8
# copyright: 2015, The Authors
# license: All rights reserved

title 'syslog section'

syslog_servers = attribute('syslog_servers', default: false, description: 'Should we control that central syslog servers are configured')
# syslog_servers = %( syslog1.example.com syslog2.example.com)
syslog_servers_files = attribute('syslog_servers_files', default: false, description: 'Where central syslog servers should be configured')
# syslog_servers_files = %( /etc/rsyslog.conf /etc/rsyslog.d/myfile )

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
      its('mode') { should cmp %r{064[04]} }
    end
  end
end

control 'syslog-3.0' do
  impact 0.7
  title 'syslogd should be running'
  desc 'Ensure syslogd is running'
  if os.darwin?
    describe processes('syslogd') do
      its('users') { should eq ['root'] }
      its('list.length') { should eq 1 }
    end
  elsif os.redhat?
    describe processes('rsyslogd') do
      its('users') { should eq ['root'] }
      its('list.length') { should eq 1 }
    end
  else
    describe processes('rsyslogd') do
      its('users') { should eq ['syslog'] }
      its('list.length') { should eq 1 }
    end
  end
end

control 'syslog-4.0' do
  impact 0.7
  title 'syslogd should have log files'
  desc 'Ensure syslogd logs file are present'
  if os.darwin?
    describe file('/var/log') do
      it { should be_directory }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0755' }
    end
    describe file('/var/log/system.log') do
      it { should be_file }
u
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0640' }
      its('content') { should match 'last message repeated' }
      its('content') { should match 'WindowServer' }
    end
    describe file('/var/log/asl/StoreData') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0644' }
    end
  elsif os.redhat?
    describe file('/var/log/messages') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0600' }
      # its('mode') { should cmp '0640' }
      # its('content') { should match 'last message repeated' }
    end
  else
    ## ubuntu
    describe file('/var/log/syslog') do
      it { should be_file }
      it { should be_owned_by 'syslog' }
      its('mode') { should cmp '0644' }
      # its('content') { should match 'last message repeated' }
    end
  end
end

control 'syslog-5.0' do
  impact 0.7
  title 'syslogd updated log files'
  desc 'Ensure syslogd logs file were updated less than 900s in the past'
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
