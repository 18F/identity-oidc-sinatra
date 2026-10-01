# frozen_string_literal: true

require_relative 'config'
require_relative 'errors'
require_relative 'flows/auth_only'
require_relative 'flows/idv'
require_relative 'flows/signup'
require_relative 'http_client'
require_relative 'results'
require_relative 'user_pool'

module LoginGov
  module OidcSinatra
    module Loadtest
      # Builds the work list from the per-flow run counts and executes it across
      # a fixed pool of virtual-user threads.
      class Scheduler
        FLOW_CLASSES = {
          'auth_only' => Flows::AuthOnly,
          'idv' => Flows::Idv,
          'signup' => Flows::Signup,
        }.freeze

        def initialize(config:, logger:)
          @config = config
          @logger = logger
          @results = Results.new
          @user_pool = UserPool.new(config)
        end

        # The ordered list of (flow, run_index) pairs this run will execute.
        #
        # Flows are interleaved rather than run in blocks so that a mixed
        # configuration produces mixed concurrent traffic, which is the point of
        # specifying several flows at once. Exposed separately from #run so
        # `--plan` can print it without sending any requests.
        #
        # @return [Array<Hash>]
        def work_list
          remaining = @config.active_flow_types.to_h do |type|
            [type, @config.flows.fetch(type).fetch('runs')]
          end

          items = []
          until remaining.empty?
            remaining.each_key do |type|
              items << { flow: type, run_index: items.length }
              remaining[type] -= 1
            end
            remaining.reject! { |_type, count| count.zero? }
          end

          items
        end

        # @return [Results]
        def run
          queue = Queue.new
          work_list.each { |item| queue << item }
          @config.vus.times { queue << :done }

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          threads = (1..@config.vus).map { |vu| spawn_worker(vu, queue) }
          threads.each(&:join)
          duration = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

          [@results, duration]
        end

        private

        def spawn_worker(vu, queue)
          Thread.new do
            # Ramp spreads thread start times so the IdP is not hit by every VU
            # in the same instant, which otherwise measures a thundering herd
            # rather than steady-state throughput.
            sleep(stagger_for(vu)) if @config.ramp_seconds.positive?

            while (item = queue.pop) != :done
              execute(item, vu: vu)
            end
          end
        end

        def stagger_for(vu)
          return 0 if @config.vus <= 1

          @config.ramp_seconds * ((vu - 1).to_f / (@config.vus - 1))
        end

        def execute(item, vu:)
          flow_type = item.fetch(:flow)

          @user_pool.with_identity(flow_type) do |identity|
            @results.add(perform_run(item, vu: vu, identity: identity))
          end
        end

        def perform_run(item, vu:, identity:)
          flow_type = item.fetch(:flow)
          recorder = StepRecorder.new
          # A fresh client per run means a fresh cookie jar, i.e. a fresh browser
          # session. Reusing one would let a prior run's IdP session satisfy the
          # next run's authorize request and silently skip authentication.
          http = HttpClient.new(timeout_seconds: @config.timeout_seconds)
          flow = FLOW_CLASSES.fetch(flow_type).new(config: @config, http: http, recorder: recorder)

          started_at = Time.now
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          status, error = attempt(flow, identity)
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

          log_run(flow_type, identity, status, error)

          Run.new(
            flow: flow_type,
            run_index: item.fetch(:run_index),
            vu: vu,
            identity: identity.fetch(:email),
            started_at: started_at,
            duration_ms: (elapsed * 1000).round(2),
            status: status,
            failed_step: recorder.failed_step,
            error: error,
            steps: recorder.steps,
          )
        end

        # Failures are contained to a single run so one bad iteration does not
        # end a thread or the test. They are never swallowed: the status, failing
        # step, and message all reach the results and the log.
        def attempt(flow, identity)
          flow.run(user: identity)
          ['ok', nil]
        rescue Error => e
          ['failed', e.message]
        rescue StandardError => e
          ['error', "#{e.class}: #{e.message}"]
        end

        def log_run(flow_type, identity, status, error)
          if status == 'ok'
            @logger.debug("#{flow_type} #{identity.fetch(:email)} ok")
          else
            @logger.warn("#{flow_type} #{identity.fetch(:email)} #{status}: #{error}")
          end
        end
      end
    end
  end
end
