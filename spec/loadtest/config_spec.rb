require_relative 'spec_helper'
require 'tmpdir'
require_relative '../../lib/loadtest/config'

RSpec.describe LoginGov::OidcSinatra::Loadtest::Config do
  let(:error) { LoginGov::OidcSinatra::Loadtest::ConfigError }

  def write_config(contents, name: 'loadtest.yml')
    dir = Dir.mktmpdir
    path = File.join(dir, name)
    File.write(path, contents)
    path
  end

  describe 'defaults' do
    it 'targets local IdP and relying party when nothing is configured' do
      config = described_class.new(env: {}, overrides: { 'flow_runs' => { 'auth_only' => 1 } })

      expect(config.idp_url).to eq('http://localhost:3000')
      expect(config.rp_url).to eq('http://localhost:9292')
    end

    it 'treats every flow as disabled until runs are requested' do
      config = described_class.new(env: {}, overrides: { 'flow_runs' => { 'signup' => 3 } })

      expect(config.active_flow_types).to eq(['signup'])
      expect(config.total_runs).to eq(3)
    end
  end

  describe 'precedence' do
    let(:path) do
      write_config(<<~YAML)
        idp_url: http://file-idp:3000
        vus: 2
        flows:
          auth_only:
            runs: 5
      YAML
    end

    it 'prefers the config file over built-in defaults' do
      config = described_class.new(file: path, env: {})

      expect(config.idp_url).to eq('http://file-idp:3000')
      expect(config.vus).to eq(2)
    end

    it 'prefers environment variables over the config file' do
      config = described_class.new(file: path, env: { 'LOADTEST_IDP_URL' => 'http://env-idp:3000' })

      expect(config.idp_url).to eq('http://env-idp:3000')
    end

    it 'prefers command-line overrides over everything else' do
      config = described_class.new(
        file: path,
        env: { 'LOADTEST_IDP_URL' => 'http://env-idp:3000', 'LOADTEST_VUS' => '7' },
        overrides: { 'idp_url' => 'http://cli-idp:3000', 'vus' => 9 },
      )

      expect(config.idp_url).to eq('http://cli-idp:3000')
      expect(config.vus).to eq(9)
    end

    it 'lets --flow-runs override per-flow counts from the file' do
      config = described_class.new(
        file: path,
        env: {},
        overrides: { 'flow_runs' => { 'auth_only' => 50 } },
      )

      expect(config.flows.fetch('auth_only').fetch('runs')).to eq(50)
    end

    it 'strips a trailing slash so URLs join predictably' do
      config = described_class.new(
        env: {},
        overrides: { 'rp_url' => 'http://localhost:9292/', 'flow_runs' => { 'auth_only' => 1 } },
      )

      expect(config.rp_url).to eq('http://localhost:9292')
    end
  end

  describe 'validation' do
    it 'rejects a run with no work to do' do
      expect { described_class.new(env: {}) }.to raise_error(error, /at least 1/)
    end

    it 'rejects fewer than one virtual user' do
      expect do
        described_class.new(env: {}, overrides: { 'vus' => 0, 'flow_runs' => { 'idv' => 1 } })
      end.to raise_error(error, /vus must be at least 1/)
    end

    it 'rejects an unknown flow type in the config file' do
      path = write_config("flows:\n  teleport:\n    runs: 1\n")

      expect { described_class.new(file: path, env: {}) }.
        to raise_error(error, /unknown flow type/)
    end

    it 'rejects overlapping auth_only and idv user pools' do
      # An idv run handed an unproofed user would be diverted into identity
      # verification, so overlapping ranges must fail loudly at startup rather
      # than produce confusing mid-run failures.
      path = write_config(<<~YAML)
        flows:
          auth_only:
            runs: 1
            user_index_start: 0
            user_pool_size: 10
          idv:
            runs: 1
            user_index_start: 5
            user_pool_size: 10
      YAML

      expect { described_class.new(file: path, env: {}) }.
        to raise_error(error, /user pools overlap/)
    end

    it 'allows adjacent, non-overlapping pools' do
      path = write_config(<<~YAML)
        flows:
          auth_only:
            runs: 1
            user_index_start: 10
            user_pool_size: 10
          idv:
            runs: 1
            user_index_start: 0
            user_pool_size: 10
      YAML

      expect { described_class.new(file: path, env: {}) }.not_to raise_error
    end

    it 'ignores pool overlap when only one of the two flows runs' do
      path = write_config(<<~YAML)
        flows:
          auth_only:
            runs: 1
            user_index_start: 0
            user_pool_size: 10
          idv:
            runs: 0
            user_index_start: 0
            user_pool_size: 10
      YAML

      expect { described_class.new(file: path, env: {}) }.not_to raise_error
    end

    it 'reports a missing config file' do
      expect { described_class.new(file: '/nonexistent/loadtest.yml', env: {}) }.
        to raise_error(error, /not found/)
    end

    it 'reports an unsupported config format' do
      path = write_config('nope', name: 'loadtest.toml')

      expect { described_class.new(file: path, env: {}) }.
        to raise_error(error, /unsupported config format/)
    end

    it 'reports malformed YAML' do
      path = write_config("flows:\n  auth_only:\n   - runs: : :\n")

      expect { described_class.new(file: path, env: {}) }.
        to raise_error(error, /could not parse/)
    end
  end

  describe 'JSON config files' do
    it 'accepts .json as well as .yml' do
      path = write_config('{"vus": 3, "flows": {"signup": {"runs": 2}}}', name: 'loadtest.json')
      config = described_class.new(file: path, env: {})

      expect(config.vus).to eq(3)
      expect(config.flows.fetch('signup').fetch('runs')).to eq(2)
    end
  end
end
