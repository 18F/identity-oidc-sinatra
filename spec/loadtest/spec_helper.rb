# Spec helper for the load-test harness.
#
# Deliberately separate from spec/spec_helper.rb: that one boots the Sinatra
# application, and the harness under test is a standalone HTTP client that does
# not depend on it. Keeping them apart means these specs stay fast and cannot be
# broken by unrelated application changes.

require 'logger'
require 'rspec'

ENV['RACK_ENV'] = 'test'

# The application's spec_helper loads webmock/rspec, which disables all real
# connections process-wide. When the whole suite runs in one process that would
# break these specs, which deliberately talk to a local stub server over real
# sockets to cover cookie handling, redirects, and form encoding -- behavior a
# stubbed transport cannot exercise.
#
# Re-enable loopback only. Connections to anywhere else stay blocked, so a spec
# still cannot reach a real IdP by accident.
begin
  require 'webmock'
  WebMock.disable_net_connect!(allow_localhost: true)
rescue LoadError
  # webmock is not loaded when these specs run on their own; nothing to relax.
  nil
end

RSpec.configure do |config|
  config.disable_monkey_patching!
end
