require_relative 'spec_helper'
require 'csv'
require 'tmpdir'
require_relative '../../lib/loadtest/config'
require_relative '../../lib/loadtest/report'
require_relative '../../lib/loadtest/results'

RSpec.describe LoginGov::OidcSinatra::Loadtest::Report do
  let(:config) do
    LoginGov::OidcSinatra::Loadtest::Config.new(
      env: {},
      overrides: { 'vus' => 2, 'flow_runs' => { 'auth_only' => 3 } },
    )
  end

  def run(flow:, index:, status:, duration:, steps:, error: nil, failed_step: nil)
    LoginGov::OidcSinatra::Loadtest::Run.new(
      flow: flow,
      run_index: index,
      vu: 1,
      identity: "testuser#{index}@example.com",
      started_at: Time.at(0),
      duration_ms: duration,
      status: status,
      failed_step: failed_step,
      error: error,
      steps: steps,
    )
  end

  def results_for(runs)
    results = LoginGov::OidcSinatra::Loadtest::Results.new
    runs.each { |r| results.add(r) }
    results
  end

  let(:ok_runs) do
    [
      run(
        flow: 'auth_only', index: 0, status: 'ok', duration: 100.0,
        steps: [{ name: 'sign_in_submit', duration_ms: 60.0, error: nil }]
      ),
      run(
        flow: 'auth_only', index: 1, status: 'ok', duration: 300.0,
        steps: [{ name: 'sign_in_submit', duration_ms: 200.0, error: nil }]
      ),
    ]
  end

  describe 'aggregation' do
    subject(:report) do
      described_class.new(
        results: results_for(ok_runs),
        wall_clock_seconds: 2.0,
        config: config,
      )
    end

    it 'counts runs by outcome' do
      expect(report.to_h.fetch('totals')).to eq('runs' => 2, 'ok' => 2, 'failed' => 0)
    end

    it 'reports throughput over wall clock time' do
      expect(report.to_h.fetch('throughput_runs_per_second')).to eq(1.0)
    end

    it 'summarizes latency per flow' do
      stats = report.to_h.fetch('flows').fetch('auth_only')

      expect(stats).to include('min_ms' => 100.0, 'max_ms' => 300.0, 'mean_ms' => 200.0)
    end

    it 'summarizes latency per step' do
      stats = report.to_h.fetch('steps').find { |s| s.fetch('step') == 'sign_in_submit' }

      expect(stats).to include('count' => 2, 'max_ms' => 200.0)
    end
  end

  describe 'failure handling' do
    let(:mixed_runs) do
      ok_runs + [
        run(
          flow: 'auth_only', index: 2, status: 'failed', duration: 5.0,
          steps: [{ name: 'otp_submit', duration_ms: 5.0, error: 'no prefilled code' }],
          error: 'no prefilled code', failed_step: 'otp_submit'
        ),
      ]
    end

    subject(:report) do
      described_class.new(
        results: results_for(mixed_runs),
        wall_clock_seconds: 3.0,
        config: config,
      )
    end

    it 'excludes failed runs from latency statistics' do
      # A run that died at step two is fast for the wrong reason; including it
      # would flatter the latency numbers.
      expect(report.to_h.fetch('flows').fetch('auth_only')).to include(
        'count' => 2,
        'min_ms' => 100.0,
      )
    end

    it 'still counts failed runs in the totals' do
      expect(report.to_h.fetch('totals')).to eq('runs' => 3, 'ok' => 2, 'failed' => 1)
    end

    it 'reports the failing step and message' do
      expect(report.to_h.fetch('failures').first).to include(
        'failed_step' => 'otp_submit',
        'error' => 'no prefilled code',
      )
    end

    it 'flags the run as failed so the exit status is nonzero' do
      expect(report.failed?).to be(true)
    end

    it 'names the failure in the text summary' do
      expect(report.text).to include('Failures').and include('no prefilled code')
    end
  end

  describe 'text summary' do
    subject(:report) do
      described_class.new(results: results_for(ok_runs), wall_clock_seconds: 2.0, config: config)
    end

    it 'names the targets so output is self-describing' do
      expect(report.text).to include(config.rp_url).and include(config.idp_url)
    end

    it 'includes a per-flow and a per-step table' do
      expect(report.text).to include('Per flow').and include('Per step')
    end
  end

  describe '#write_csv' do
    it 'writes exactly one row per run plus a header' do
      report = described_class.new(
        results: results_for(ok_runs),
        wall_clock_seconds: 2.0,
        config: config,
      )

      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        report.write_csv(path)
        rows = CSV.read(path)

        expect(rows.length).to eq(3)
        expect(rows.first).to eq(described_class::CSV_HEADERS)
      end
    end

    it 'creates missing parent directories' do
      report = described_class.new(
        results: results_for(ok_runs),
        wall_clock_seconds: 2.0,
        config: config,
      )

      Dir.mktmpdir do |dir|
        path = File.join(dir, 'nested', 'runs.csv')
        report.write_csv(path)

        expect(File.exist?(path)).to be(true)
      end
    end

    it 'packs per-step timings into the run row' do
      report = described_class.new(
        results: results_for(ok_runs),
        wall_clock_seconds: 2.0,
        config: config,
      )

      Dir.mktmpdir do |dir|
        path = File.join(dir, 'runs.csv')
        report.write_csv(path)
        row = CSV.read(path, headers: true).first

        expect(row.fetch('steps')).to eq('sign_in_submit=60.0')
        expect(row.fetch('flow')).to eq('auth_only')
        expect(row.fetch('status')).to eq('ok')
      end
    end
  end

  describe '#write_json' do
    it 'writes the aggregated summary' do
      report = described_class.new(
        results: results_for(ok_runs),
        wall_clock_seconds: 2.0,
        config: config,
      )

      Dir.mktmpdir do |dir|
        path = File.join(dir, 'summary.json')
        report.write_json(path)

        summary = JSON.parse(File.read(path))
        expect(summary.fetch('totals')).to eq('runs' => 2, 'ok' => 2, 'failed' => 0)
      end
    end

    it 'creates missing parent directories' do
      report = described_class.new(
        results: results_for(ok_runs),
        wall_clock_seconds: 2.0,
        config: config,
      )

      Dir.mktmpdir do |dir|
        path = File.join(dir, 'nested', 'summary.json')
        report.write_json(path)

        expect(File.exist?(path)).to be(true)
      end
    end
  end
end
