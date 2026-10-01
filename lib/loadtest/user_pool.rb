# frozen_string_literal: true

require 'securerandom'

require_relative 'config'
require_relative 'errors'

module LoginGov
  module OidcSinatra
    module Loadtest
      # Hands out the identity each run signs in as.
      #
      # This exists to enforce one hard IdP constraint: a user may only have one
      # active session. identity-idp's Devise `session_limitable` module signs out
      # any previous session when a user signs in again, so two concurrent runs
      # sharing a user would knock each other over and produce failures that look
      # like IdP faults.
      #
      # The pool therefore guarantees a seeded user is checked out by at most one
      # run at a time. Runs may reuse a user *sequentially* (so `runs` can exceed
      # the pool size), just never concurrently.
      #
      # Signup identities need no pool: each run mints a fresh synthetic email.
      class UserPool
        def initialize(config)
          @config = config
          @available = build_available
          @mutex = Mutex.new
          @condition = ConditionVariable.new
        end

        # Check out an identity, run the block, then return it to the pool.
        #
        # Blocks when every user in the flow's pool is busy. That is the intended
        # back-pressure: concurrency above the pool size queues rather than
        # double-booking a user.
        def with_identity(flow_type)
          identity = checkout(flow_type)
          begin
            yield identity
          ensure
            checkin(flow_type, identity)
          end
        end

        private

        def build_available
          Config::FLOW_TYPES.to_h do |type|
            [type, type == 'signup' ? nil : seeded_identities(type)]
          end
        end

        # Build the identity list from the seed convention of
        # `rake dev:random_users`: testuser{index}@example.com, all sharing one
        # password. `user_index_start` keeps the auth_only and idv pools in
        # separate, non-overlapping index ranges.
        def seeded_identities(type)
          settings = @config.flows.fetch(type)
          start = Integer(settings.fetch('user_index_start'))
          size = Integer(settings.fetch('user_pool_size'))
          format_string = settings.fetch('email_format')
          password = settings.fetch('password')

          (start...(start + size)).map do |index|
            { email: format(format_string, index), password: password, index: index }
          end
        end

        def checkout(flow_type)
          return synthetic_identity if flow_type == 'signup'

          @mutex.synchronize do
            pool = @available.fetch(flow_type)
            @condition.wait(@mutex) while pool.empty?
            pool.shift
          end
        end

        def checkin(flow_type, identity)
          return if flow_type == 'signup'

          @mutex.synchronize do
            @available.fetch(flow_type) << identity
            @condition.signal
          end
        end

        # A brand-new, obviously-synthetic account for each signup run.
        #
        # The local part is unique per run because registration is rejected for
        # an already-confirmed address; these rows persist in the IdP's
        # development database after the run by design (see README).
        def synthetic_identity
          settings = @config.flows.fetch('signup')
          prefix = settings.fetch('email_prefix')

          {
            email: "#{prefix}+#{SecureRandom.hex(8)}@example.com",
            password: settings.fetch('password'),
            phone: settings.fetch('phone'),
          }
        end
      end
    end
  end
end
