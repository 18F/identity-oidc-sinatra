require_relative 'spec_helper'
require_relative '../../lib/loadtest/config'
require_relative '../../lib/loadtest/user_pool'

RSpec.describe LoginGov::OidcSinatra::Loadtest::UserPool do
  def config_for(flows, vus: 4)
    LoginGov::OidcSinatra::Loadtest::Config.new(
      env: {},
      overrides: { 'vus' => vus, 'flows' => flows }.merge(
        'flow_runs' => flows.transform_values { |settings| settings.fetch('runs') },
      ),
    )
  end

  describe 'seeded identities' do
    let(:config) do
      config_for(
        {
          'auth_only' => {
            'runs' => 3,
            'user_index_start' => 1000,
            'user_pool_size' => 3,
            'email_format' => 'testuser%d@example.com',
            'password' => 'salty pickles',
          },
        },
      )
    end

    it 'builds emails from the dev:random_users seeding convention' do
      pool = described_class.new(config)
      emails = 3.times.map { pool.with_identity('auth_only') { |id| id.fetch(:email) } }

      expect(emails).to contain_exactly(
        'testuser1000@example.com',
        'testuser1001@example.com',
        'testuser1002@example.com',
      )
    end

    it 'supplies the configured password' do
      pool = described_class.new(config)

      pool.with_identity('auth_only') do |identity|
        expect(identity.fetch(:password)).to eq('salty pickles')
      end
    end

    it 'returns an identity to the pool so runs can reuse it sequentially' do
      # runs may exceed the pool size; reuse is fine as long as it is not
      # concurrent. Identities are returned to the back of the pool, so reuse
      # cycles through the whole pool rather than hammering one user row.
      pool = described_class.new(config)
      emails = 4.times.map { pool.with_identity('auth_only') { |id| id.fetch(:email) } }

      expect(emails.last).to eq(emails.first)
      expect(emails.first(3).uniq.length).to eq(3)
    end
  end

  describe 'concurrency safety' do
    it 'never hands the same user to two runs at once' do
      # identity-idp signs out a user's previous session when they sign in
      # again, so concurrent reuse would make runs knock each other over.
      config = config_for(
        {
          'auth_only' => {
            'runs' => 20,
            'user_index_start' => 0,
            'user_pool_size' => 2,
            'email_format' => 'testuser%d@example.com',
            'password' => 'pw',
          },
        },
      )
      pool = described_class.new(config)
      mutex = Mutex.new
      in_use = {}
      collisions = []

      threads = 8.times.map do
        Thread.new do
          5.times do
            pool.with_identity('auth_only') do |identity|
              email = identity.fetch(:email)
              mutex.synchronize do
                collisions << email if in_use[email]
                in_use[email] = true
              end
              sleep(0.001)
              mutex.synchronize { in_use.delete(email) }
            end
          end
        end
      end
      threads.each(&:join)

      expect(collisions).to be_empty
    end
  end

  describe 'signup identities' do
    let(:config) do
      config_for(
        {
          'signup' => {
            'runs' => 5,
            'email_prefix' => 'loadtest',
            'password' => 'loadtest sturdy pass w0rd',
            'phone' => '202-555-1212',
          },
        },
      )
    end

    it 'mints a unique email per run so registration is never a duplicate' do
      pool = described_class.new(config)
      emails = 5.times.map { pool.with_identity('signup') { |id| id.fetch(:email) } }

      expect(emails.uniq.length).to eq(5)
    end

    it 'uses the configured prefix and an obviously synthetic domain' do
      pool = described_class.new(config)

      pool.with_identity('signup') do |identity|
        expect(identity.fetch(:email)).to match(/\Aloadtest\+[0-9a-f]+@example\.com\z/)
      end
    end

    it 'supplies the phone number the signup flow submits' do
      pool = described_class.new(config)

      pool.with_identity('signup') do |identity|
        expect(identity.fetch(:phone)).to eq('202-555-1212')
      end
    end

    it 'does not block, since signup needs no shared pool' do
      pool = described_class.new(config)

      expect do
        threads = 4.times.map { Thread.new { pool.with_identity('signup') { |id| id } } }
        threads.each { |thread| thread.join(5) || raise('signup checkout blocked') }
      end.not_to raise_error
    end
  end
end
