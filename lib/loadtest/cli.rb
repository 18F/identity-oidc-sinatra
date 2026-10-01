# frozen_string_literal: true

require 'logger'
require 'optparse'

require_relative 'config'
require_relative 'errors'
require_relative 'report'
require_relative 'scheduler'

module LoginGov
  module OidcSinatra
    module Loadtest
      # Command-line entry point. Parses options, resolves configuration, runs
      # the scheduler, and writes the outputs.
      class CLI
        DEFAULT_CONFIG_PATHS = %w[loadtest.yml config/loadtest.yml].freeze

        EXIT_OK = 0
        EXIT_RUN_FAILURES = 1
        EXIT_CONFIG_ERROR = 2

        def initialize(argv:, stdout: $stdout, stderr: $stderr, env: ENV)
          @argv = argv
          @stdout = stdout
          @stderr = stderr
          @env = env
        end

        # @return [Integer] process exit status
        def run
          options = parse_options
          return EXIT_OK if options[:help]

          config = Config.new(
            file: options[:config] || default_config_path,
            env: @env,
            overrides: options.fetch(:overrides),
          )

          return print_plan(config) if options[:plan]

          execute(config)
        rescue ConfigError => e
          @stderr.puts("configuration error: #{e.message}")
          EXIT_CONFIG_ERROR
        end

        private

        def execute(config)
          logger = build_logger(config: config, verbose: @argv.include?('--verbose'))
          @stdout.puts(startup_banner(config))

          results, wall_clock = Scheduler.new(config: config, logger: logger).run
          report = Report.new(results: results, wall_clock_seconds: wall_clock, config: config)

          @stdout.puts(report.text)
          write_outputs(report, config)

          # A nonzero status on any failed run makes the harness usable as a
          # gate, not just a benchmark.
          report.failed? ? EXIT_RUN_FAILURES : EXIT_OK
        end

        def write_outputs(report, config)
          if config.csv_path
            report.write_csv(config.csv_path)
            @stdout.puts("Wrote per-run CSV to #{config.csv_path}")
          end

          return unless config.json_path

          report.write_json(config.json_path)
          @stdout.puts("Wrote JSON summary to #{config.json_path}")
        end

        # Print the work list without sending a single request. Useful to confirm
        # a config change does what was intended before pointing it at an IdP.
        def print_plan(config)
          scheduler = Scheduler.new(config: config, logger: Logger.new(File::NULL))
          # Enumerable#tally ignores a block, so group explicitly rather than
          # silently counting whole hashes.
          counts = scheduler.work_list.
            group_by { |item| item.fetch(:flow) }.
            transform_values(&:length)

          @stdout.puts(startup_banner(config))
          @stdout.puts('Planned runs (no requests sent):')
          counts.each { |flow, count| @stdout.puts(format('  %-10s %d', flow, count)) }
          @stdout.puts(format('  %-10s %d', 'total', config.total_runs))
          EXIT_OK
        end

        def startup_banner(config)
          [
            format('RP:  %s', config.rp_url),
            format('IdP: %s', config.idp_url),
            format(
              'VUs: %d   Total runs: %d   Flows: %s',
              config.vus,
              config.total_runs,
              config.active_flow_types.join(', '),
            ),
          ].join("\n")
        end

        def build_logger(config:, verbose:)
          logger = Logger.new(@stderr)
          logger.level = verbose ? Logger::DEBUG : Logger::WARN
          logger.formatter = proc { |severity, _time, _prog, msg| "#{severity.downcase}: #{msg}\n" }
          logger
        end

        def default_config_path
          DEFAULT_CONFIG_PATHS.find { |path| File.exist?(path) }
        end

        def parse_options
          options = { overrides: {}, help: false, plan: false }
          parser = build_parser(options)
          parser.parse!(@argv)
          options
        rescue OptionParser::ParseError => e
          raise ConfigError.new(e.message)
        end

        def build_parser(options)
          OptionParser.new do |opts|
            opts.banner = 'Usage: bundle exec ruby bin/loadtest [options]'
            add_target_options(opts, options)
            add_load_options(opts, options)
            add_output_options(opts, options)
            add_mode_options(opts, options)
          end
        end

        def add_target_options(opts, options)
          opts.on('-c', '--config PATH', 'Config file (.yml or .json)') do |value|
            options[:config] = value
          end
          opts.on('--idp-url URL', 'IdP base URL') { |v| options[:overrides]['idp_url'] = v }
          opts.on('--rp-url URL', 'Sinatra RP base URL') { |v| options[:overrides]['rp_url'] = v }
        end

        def add_load_options(opts, options)
          opts.on('--vus N', Integer, 'Concurrent virtual users') do |value|
            options[:overrides]['vus'] = value
          end

          opts.on(
            '--flow-runs SPEC',
            'Per-flow run counts, e.g. auth_only=100,idv=50,signup=20',
          ) do |value|
            options[:overrides]['flow_runs'] = parse_flow_runs(value)
          end

          opts.on('--ramp SECONDS', Float, 'Stagger VU start times over N seconds') do |value|
            options[:overrides]['ramp_seconds'] = value
          end
        end

        def add_output_options(opts, options)
          opts.on('--csv PATH', 'Write per-run CSV here') { |v| options[:overrides]['csv'] = v }
          opts.on('--json PATH', 'Write JSON summary here') { |v| options[:overrides]['json'] = v }
        end

        def add_mode_options(opts, options)
          opts.on('--plan', 'Print the planned runs and exit without sending requests') do
            options[:plan] = true
          end

          opts.on('--verbose', 'Log every run, not just failures') { options[:verbose] = true }

          opts.on('-h', '--help', 'Show this message') do
            @stdout.puts(opts)
            options[:help] = true
          end
        end

        def parse_flow_runs(spec)
          spec.split(',').to_h do |pair|
            flow, _, count = pair.strip.partition('=')
            unless Config::FLOW_TYPES.include?(flow)
              valid = Config::FLOW_TYPES.join(', ')
              raise ConfigError.new("unknown flow '#{flow}' (valid: #{valid})")
            end
            raise ConfigError.new("missing run count for flow '#{flow}'") if count.empty?

            [flow, Integer(count)]
          end
        rescue ArgumentError => e
          raise ConfigError.new("could not parse --flow-runs '#{spec}': #{e.message}")
        end
      end
    end
  end
end
