# frozen_string_literal: true

require 'json'
require 'yaml'

require_relative 'errors'

module LoginGov
  module OidcSinatra
    module Loadtest
      # Resolved harness configuration.
      #
      # Precedence is CLI > ENV > config file > DEFAULTS. The config file is the
      # primary interface (it is where per-flow run counts live); CLI and ENV
      # exist so a run can be tweaked without editing a checked-in file.
      class Config
        FLOW_TYPES = %w[auth_only idv_legacy idv_facial_match signup].freeze

        DEFAULTS = {
          'idp_url' => 'http://localhost:3000',
          'rp_url' => 'http://localhost:9292',
          'vus' => 4,
          'ramp_seconds' => 0,
          'timeout_seconds' => 30,
          'csv' => nil,
          'json' => nil,
          'flows' => {},
        }.freeze

        # Defaults applied per flow type. `user_index_start` implements the
        # non-overlapping seed-range convention: `rake dev:random_users` creates
        # testuser0..N-1, and a VERIFIED=1 pass must be seeded into a different
        # index range than the plain pass, otherwise an idv run could be handed
        # an unproofed user (which would bounce into identity verification) or an
        # auth_only run a proofed one. See README for the seeding commands.
        FLOW_DEFAULTS = {
          'auth_only' => {
            'runs' => 0,
            'email_format' => 'testuser%d@example.com',
            'password' => 'salty pickles',
            'user_index_start' => 1_000,
            'user_pool_size' => 100,
          }.freeze,
          'idv_legacy' => {
            'runs' => 0,
            'email_format' => 'testuser%d@example.com',
            'password' => 'salty pickles',
            'user_index_start' => 0,
            'user_pool_size' => 100,
          }.freeze,
          'idv_facial_match' => {
            'runs' => 0,
            'email_format' => 'testuser%d@example.com',
            'password' => 'salty pickles',
            'user_index_start' => 0,
            'user_pool_size' => 100,
          }.freeze,
          'signup' => {
            'runs' => 0,
            'email_prefix' => 'loadtest',
            # Must satisfy the IdP's password rules: Devise.password_length is
            # 12..128 and FormPasswordValidator requires a zxcvbn score >= 3.
            'password' => 'loadtest sturdy pass w0rd',
            'phone' => '202-555-1212',
          }.freeze,
        }.freeze

        attr_reader :idp_url, :rp_url, :vus, :ramp_seconds, :timeout_seconds, :csv_path,
                    :json_path, :flows

        # @param file [String, nil] path to a .yml/.yaml/.json config file
        # @param env [Hash] environment variables
        # @param overrides [Hash] already-parsed CLI overrides
        def initialize(file: nil, env: ENV, overrides: {})
          merged = DEFAULTS.merge(from_file(file))
          merged = merged.merge(from_env(env))
          merged = merged.merge(stringify(overrides.reject { |_k, v| v.nil? }))

          @idp_url = merged.fetch('idp_url').to_s.chomp('/')
          @rp_url = merged.fetch('rp_url').to_s.chomp('/')
          @vus = Integer(merged.fetch('vus'))
          @ramp_seconds = Float(merged.fetch('ramp_seconds'))
          @timeout_seconds = Float(merged.fetch('timeout_seconds'))
          @csv_path = presence(merged['csv'])
          @json_path = presence(merged['json'])
          @flows = build_flows(merged['flows'], overrides['flow_runs'])

          validate!
        end

        # Flow types with at least one run requested, in a stable order.
        # @return [Array<String>]
        def active_flow_types
          FLOW_TYPES.select { |type| flows.fetch(type).fetch('runs').positive? }
        end

        def total_runs
          active_flow_types.sum { |type| flows.fetch(type).fetch('runs') }
        end

        def to_h
          {
            'idp_url' => idp_url,
            'rp_url' => rp_url,
            'vus' => vus,
            'ramp_seconds' => ramp_seconds,
            'timeout_seconds' => timeout_seconds,
            'csv' => csv_path,
            'json' => json_path,
            'flows' => flows,
          }
        end

        private

        def from_file(file)
          return {} if file.nil?
          raise ConfigError.new("config file not found: #{file}") unless File.exist?(file)

          parsed = parse_file(file)
          unless parsed.is_a?(Hash)
            raise ConfigError.new("config file must contain a mapping: #{file}")
          end

          stringify(parsed)
        end

        def parse_file(file)
          case File.extname(file).downcase
          when '.json' then JSON.parse(File.read(file))
          when '.yml', '.yaml' then YAML.safe_load(File.read(file))
          else raise ConfigError.new("unsupported config format: #{file} (use .yml or .json)")
          end
        rescue JSON::ParserError, Psych::SyntaxError => e
          raise ConfigError.new("could not parse #{file}: #{e.message}")
        end

        def from_env(env)
          {
            'idp_url' => env['LOADTEST_IDP_URL'],
            'rp_url' => env['LOADTEST_RP_URL'],
            'vus' => env['LOADTEST_VUS'],
            'ramp_seconds' => env['LOADTEST_RAMP_SECONDS'],
            'timeout_seconds' => env['LOADTEST_TIMEOUT_SECONDS'],
            'csv' => env['LOADTEST_CSV'],
            'json' => env['LOADTEST_JSON'],
          }.compact
        end

        def build_flows(from_config, run_overrides)
          configured = stringify(from_config || {})
          unknown = configured.keys - FLOW_TYPES
          if unknown.any?
            raise ConfigError.new(
              "unknown flow type(s): #{unknown.join(', ')} (valid: #{FLOW_TYPES.join(', ')})",
            )
          end

          FLOW_TYPES.to_h do |type|
            settings = FLOW_DEFAULTS.fetch(type).merge(stringify(configured[type] || {}))
            settings['runs'] = Integer((run_overrides || {})[type] || settings['runs'])
            [type, settings]
          end
        end

        def validate!
          raise ConfigError.new('vus must be at least 1') unless vus.positive?
          raise ConfigError.new('ramp_seconds cannot be negative') if ramp_seconds.negative?
          if total_runs.zero?
            raise ConfigError.new('total runs across all flows must be at least 1')
          end

          validate_pool_sizes!
          validate_pool_ranges!
        end

        def validate_pool_sizes!
          %w[auth_only idv_legacy idv_facial_match].each do |type|
            settings = flows.fetch(type)
            next unless settings.fetch('runs').positive?
            next if Integer(settings.fetch('user_pool_size')).positive?

            raise ConfigError.new("#{type}.user_pool_size must be at least 1")
          end
        end

        # Overlapping pools would silently hand an idv run an unproofed user (or
        # vice versa), producing failures that look like IdP bugs. Fail fast
        # instead, naming the fix.
        def validate_pool_ranges!
          idv_flows = %w[idv_legacy idv_facial_match]
          active_flows = (['auth_only'] + idv_flows).select do |type|
            flows.fetch(type).fetch('runs').positive?
          end
          return if active_flows.length < 2

          ranges = active_flows.to_h { |type| [type, pool_range(flows.fetch(type))] }
          
          # Check auth_only against both idv flows
          if ranges.key?('auth_only')
            idv_flows.each do |idv_type|
              next unless ranges.key?(idv_type)
              next if (ranges.fetch('auth_only').to_a & ranges.fetch(idv_type).to_a).empty?

              message = "auth_only and #{idv_type} user pools overlap " \
                        "(#{ranges.fetch('auth_only')} vs #{ranges.fetch(idv_type)}); " \
                        "seed them into separate index ranges and set user_index_start accordingly"
              raise ConfigError.new(message)
            end
          end
        end

        def pool_range(settings)
          start = Integer(settings.fetch('user_index_start'))
          start...(start + Integer(settings.fetch('user_pool_size')))
        end

        def stringify(hash)
          hash.to_h { |key, value| [key.to_s, value.is_a?(Hash) ? stringify(value) : value] }
        end

        def presence(value)
          str = value.to_s
          str.empty? ? nil : str
        end
      end
    end
  end
end
