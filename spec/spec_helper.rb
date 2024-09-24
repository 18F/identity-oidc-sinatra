require 'rack/test'
require 'rspec'
require 'simplecov'
require 'webmock/rspec'

ENV['RACK_ENV'] = 'test'

SimpleCov.start do
  add_filter '/spec'
end

require_relative '../app'

module RSpecMixin
  include Rack::Test::Methods

  def app
    described_class
  end

  def read_fixture_file(file)
    File.read(
      File.join(File.expand_path(File.dirname(__FILE__)), 'fixtures', file),
    )
  end
end

RSpec.configure do |config|
  config.include RSpecMixin
  config.disable_monkey_patching!
end
