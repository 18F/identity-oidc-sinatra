# frozen_string_literal: true

require_relative 'errors'

module LoginGov
  module OidcSinatra
    module Loadtest
      # One completed (or failed) flow iteration.
      Run = Struct.new(
        :flow,
        :run_index,
        :vu,
        :identity,
        :started_at,
        :duration_ms,
        :status,
        :failed_step,
        :error,
        :steps,
        keyword_init: true,
      ) do
        def ok?
          status == 'ok'
        end
      end

      # Collects timings for the steps of a single run.
      #
      # One recorder per run, handed to the flow. Flows never touch the shared
      # results list, which keeps the only cross-thread mutation in Results.
      class StepRecorder
        attr_reader :steps

        def initialize
          @steps = []
        end

        def record_step(name:, duration_ms:, error: nil)
          @steps << { name: name, duration_ms: duration_ms, error: error }
        end

        # @return [String, nil] the step that raised, if any
        def failed_step
          @steps.find { |step| step[:error] }&.fetch(:name)
        end
      end

      # Thread-safe collection of completed runs.
      class Results
        def initialize
          @runs = []
          @mutex = Mutex.new
        end

        def add(run)
          @mutex.synchronize { @runs << run }
        end

        # @return [Array<Run>] ordered by run index for stable output
        def runs
          @mutex.synchronize { @runs.sort_by(&:run_index) }
        end
      end
    end
  end
end
