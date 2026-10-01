require_relative 'spec_helper'
require_relative '../../lib/loadtest/config'
require_relative '../../lib/loadtest/scheduler'

RSpec.describe LoginGov::OidcSinatra::Loadtest::Scheduler do
  let(:logger) { Logger.new(File::NULL) }

  def scheduler_for(flow_runs, vus: 2)
    config = LoginGov::OidcSinatra::Loadtest::Config.new(
      env: {},
      overrides: { 'vus' => vus, 'flow_runs' => flow_runs },
    )
    described_class.new(config: config, logger: logger)
  end

  describe '#work_list' do
    it 'produces one item per requested run' do
      list = scheduler_for({ 'auth_only' => 3, 'signup' => 2 }).work_list

      expect(list.length).to eq(5)
    end

    it 'honors the per-flow run counts exactly' do
      list = scheduler_for({ 'auth_only' => 4, 'idv_legacy' => 2, 'signup' => 1 }).work_list

      counts = list.group_by { |item| item.fetch(:flow) }.
        transform_values(&:count)
      expect(counts).to eq('auth_only' => 4, 'idv_legacy' => 2, 'signup' => 1)
    end

    it 'interleaves flows so a mixed config generates mixed concurrent traffic' do
      # Running flows in blocks would measure three separate tests back to back
      # rather than the mixed load the configuration asks for.
      flows = scheduler_for({ 'auth_only' => 2, 'signup' => 2 }).work_list.
        map { |item| item.fetch(:flow) }

      expect(flows).to eq(%w[auth_only signup auth_only signup])
    end

    it 'keeps emitting the longer flow once a shorter one is exhausted' do
      flows = scheduler_for({ 'auth_only' => 3, 'signup' => 1 }).work_list.
        map { |item| item.fetch(:flow) }

      expect(flows).to eq(%w[auth_only signup auth_only auth_only])
    end

    it 'skips flows with zero runs' do
      flows = scheduler_for({ 'idv_legacy' => 2 }).work_list.map { |item| item.fetch(:flow) }

      expect(flows).to eq(%w[idv_legacy idv_legacy])
    end

    it 'assigns a unique, contiguous run index' do
      list = scheduler_for({ 'auth_only' => 3, 'idv_legacy' => 2 }).work_list

      expect(list.map { |item| item.fetch(:run_index) }).to eq([0, 1, 2, 3, 4])
    end
  end

  describe 'flow coverage' do
    it 'maps every configurable flow type to an implementation' do
      # A flow accepted by the config but missing here would fail at runtime
      # rather than at startup.
      expect(described_class::FLOW_CLASSES.keys).
        to match_array(LoginGov::OidcSinatra::Loadtest::Config::FLOW_TYPES)
    end
  end
end
