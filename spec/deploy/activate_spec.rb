require 'spec_helper'
require 'fakefs/spec_helpers'
require 'login_gov/hostdata/fake_s3_client'

load File.expand_path('../../deploy/activate', File.dirname(__FILE__))

RSpec.describe 'deploy/activate' do
  let(:app_root) { File.expand_path('../../', File.dirname(__FILE__)) }

  around(:each) do |ex|
    LoginGov::Hostdata.reset!

    @logger = Logger.new('/dev/null')

    FakeFS do
      FakeFS::FileSystem.clone(app_root)

      ex.run
    end
  end

  subject(:script) { Deploy::Activate.new(logger: logger, s3_client: s3_client) }

  let(:logger) { @logger }
  let(:s3_client) { LoginGov::Hostdata::FakeS3Client.new }

  describe '#run' do
    context 'in a deployed production environment' do
      before do
        stub_request(:get, 'http://169.254.169.254/2016-09-02/dynamic/instance-identity/document').
          to_return(body: {
            'region' => 'us-west-1',
            'accountId' => '12345'
          }.to_json)

        s3_client.put_object(
          bucket: 'login-gov.app-secrets.12345-us-west-1',
          key: '/int/sp-oidc-sinatra/v1/.env',
          body: dot_env
        )

        FileUtils.mkdir_p('/etc/login.gov/info')
        File.open('/etc/login.gov/info/env', 'w') { |file| file.puts 'int' }
      end

      let(:dot_env) { "FOO=bar\n" }

      it 'downloads configs from s3' do
        script.run

        expect(File.read(File.join(app_root, '.env'))).to eq(dot_env)
      end
    end

    context 'outside a deployed production environment' do
      before do
        stub_request(:get, 'http://169.254.169.254/2016-09-02/dynamic/instance-identity/document').
          to_timeout
      end

      it 'errors' do
        expect { script.run }.to raise_error(Net::OpenTimeout)
      end
    end
  end

  describe '#default_logger' do
    it 'sets the progname' do
      expect(script.default_logger.progname).to eq('deploy/activate')
    end
  end
end
