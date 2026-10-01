# frozen_string_literal: true

require 'csv'
require 'json'
require 'time'

module LoginGov
  module OidcSinatra
    module Loadtest
      # Turns completed runs into the three outputs the harness produces: a
      # human-readable summary, a per-run CSV, and an optional JSON blob.
      class Report
        # Percentiles reported per flow. p95 matters more than the mean for
        # latency work, and max catches the outlier a mean would hide.
        PERCENTILES = [50, 95].freeze

        CSV_HEADERS = %w[
          flow
          run_index
          vu
          identity
          started_at
          status
          duration_ms
          failed_step
          error
          steps
        ].freeze

        def initialize(results:, wall_clock_seconds:, config:)
          @runs = results.runs
          @wall_clock_seconds = wall_clock_seconds
          @config = config
        end

        # @return [String]
        def text
          lines = ['', 'Load test summary', '=' * 72]
          lines << format('Target RP:  %s', @config.rp_url)
          lines << format('Target IdP: %s', @config.idp_url)
          lines << format(
            'VUs: %d   Runs: %d   Wall clock: %.2fs   Throughput: %.2f runs/s',
            @config.vus,
            @runs.length,
            @wall_clock_seconds,
            throughput,
          )
          lines << ''
          lines.concat(flow_table)
          lines.concat(step_table)
          lines.concat(failure_section)
          lines << ''
          lines.join("\n")
        end

        # One row per run, as requested: the rawest useful form, so timings can be
        # pivoted externally without the harness deciding the analysis up front.
        # Per-step timings ride along in a single packed column to keep the row
        # grain at one-per-run.
        def write_csv(path)
          CSV.open(path, 'w') do |csv|
            csv << CSV_HEADERS
            @runs.each do |run|
              csv << [
                run.flow,
                run.run_index,
                run.vu,
                run.identity,
                run.started_at.utc.iso8601(3),
                run.status,
                run.duration_ms,
                run.failed_step,
                run.error,
                packed_steps(run),
              ]
            end
          end
        end

        def write_json(path)
          File.write(path, JSON.pretty_generate(to_h))
        end

        def to_h
          {
            'config' => @config.to_h,
            'wall_clock_seconds' => @wall_clock_seconds.round(3),
            'throughput_runs_per_second' => throughput.round(3),
            'totals' => totals,
            'flows' => flow_stats,
            'steps' => step_stats,
            'failures' => failures.map { |run| failure_hash(run) },
          }
        end

        def failed?
          @runs.any? { |run| !run.ok? }
        end

        private

        def throughput
          return 0.0 if @wall_clock_seconds.zero?

          @runs.length / @wall_clock_seconds
        end

        def totals
          {
            'runs' => @runs.length,
            'ok' => @runs.count(&:ok?),
            'failed' => @runs.count { |run| !run.ok? },
          }
        end

        def flow_stats
          @runs.group_by(&:flow).transform_values do |runs|
            ok = runs.select(&:ok?)
            # Latency is computed from successful runs only: a run that failed at
            # step two is fast for the wrong reason and would flatter the numbers.
            stats(ok.map(&:duration_ms)).merge(
              'runs' => runs.length,
              'ok' => ok.length,
              'failed' => runs.length - ok.length,
            )
          end
        end

        def step_stats
          rows = {}
          @runs.select(&:ok?).each do |run|
            run.steps.each do |step|
              key = [run.flow, step.fetch(:name)]
              (rows[key] ||= []) << step.fetch(:duration_ms)
            end
          end

          rows.map do |(flow, name), durations|
            { 'flow' => flow, 'step' => name }.merge(stats(durations))
          end
        end

        def stats(durations)
          return { 'count' => 0 } if durations.empty?

          sorted = durations.sort
          result = {
            'count' => sorted.length,
            'min_ms' => sorted.first.round(2),
            'max_ms' => sorted.last.round(2),
            'mean_ms' => (sorted.sum / sorted.length).round(2),
          }
          PERCENTILES.each { |p| result["p#{p}_ms"] = percentile(sorted, p) }
          result
        end

        # Nearest-rank percentile. Exact interpolation is not worth the
        # complexity at these sample sizes, and nearest-rank never reports a
        # latency that was not actually observed.
        def percentile(sorted, pct)
          return nil if sorted.empty?

          rank = (pct / 100.0) * sorted.length
          index = rank.ceil - 1
          sorted[index.clamp(0, sorted.length - 1)].round(2)
        end

        def flow_table
          lines = ['Per flow', '-' * 72]
          lines << format(
            '%-10s %6s %5s %7s %9s %9s %9s %9s',
            'flow', 'runs', 'ok', 'failed', 'mean ms', 'p50 ms', 'p95 ms', 'max ms'
          )

          flow_stats.each do |flow, stat|
            lines << format(
              '%-10s %6d %5d %7d %9s %9s %9s %9s',
              flow,
              stat.fetch('runs'),
              stat.fetch('ok'),
              stat.fetch('failed'),
              stat['mean_ms'] || '-',
              stat['p50_ms'] || '-',
              stat['p95_ms'] || '-',
              stat['max_ms'] || '-',
            )
          end

          lines << ''
          lines
        end

        def step_table
          stats = step_stats
          return [] if stats.empty?

          lines = ['Per step (successful runs only)', '-' * 72]
          lines << format('%-10s %-22s %6s %9s %9s %9s', 'flow', 'step', 'count', 'mean ms',
                          'p95 ms', 'max ms')

          stats.each do |stat|
            lines << format(
              '%-10s %-22s %6d %9s %9s %9s',
              stat.fetch('flow'),
              stat.fetch('step'),
              stat.fetch('count'),
              stat['mean_ms'] || '-',
              stat['p95_ms'] || '-',
              stat['max_ms'] || '-',
            )
          end

          lines << ''
          lines
        end

        def failure_section
          return [] if failures.empty?

          lines = ['Failures', '-' * 72]
          grouped = failures.group_by { |run| [run.flow, run.failed_step, run.error] }

          grouped.each do |(flow, failed_step, error), runs|
            lines << format('%-10s %-22s x%-4d %s', flow, failed_step || '-', runs.length, error)
          end

          lines << ''
          lines
        end

        def failures
          @failures ||= @runs.reject(&:ok?)
        end

        def failure_hash(run)
          {
            'flow' => run.flow,
            'run_index' => run.run_index,
            'identity' => run.identity,
            'failed_step' => run.failed_step,
            'error' => run.error,
          }
        end

        def packed_steps(run)
          run.steps.map { |step| "#{step.fetch(:name)}=#{step.fetch(:duration_ms)}" }.join(' ')
        end
      end
    end
  end
end
