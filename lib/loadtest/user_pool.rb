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
      # Signup identities need no pool: each run mints a fresh synthetic email
      # and phone number.
      class UserPool
        # Area codes paired with the 555-01XX line range below. Any valid area
        # code may be used; these are real, assigned codes so the number passes
        # the IdP's phone validation.
        #
        # 225 is deliberately absent: Telephony::Test::ErrorSimulator maps
        # several 225-555-XXXX numbers to simulated delivery failures, and
        # keeping the whole area code out of the pool means a future change to
        # that list cannot silently start failing runs.
        PHONE_AREA_CODES = %w[
          202 212 213 312 404 415 503 512 602 617 702 713 801 804 901 919
        ].freeze

        # 555-0100 through 555-0199 is the block reserved for fictitious use, so
        # these numbers are guaranteed never to reach a real subscriber.
        PHONE_LINE_NUMBERS = (100..199).freeze

        def initialize(config)
          @config = config
          @available = build_available
          @mutex = Mutex.new
          @condition = ConditionVariable.new
          @phone_mutex = Mutex.new
          @phone_counter = -1
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
        #
        # The phone is unique per run too, which is what lets signup runs
        # overlap. The IdP rate-limits OTP delivery per phone number
        # (OtpRateLimiter keys on the phone fingerprint, and
        # otp_delivery_blocklist_maxretry defaults to 10 per 5 minutes), so
        # every run sharing one number serialises behind that limit and later
        # runs fail with no prefilled code. Distinct numbers give each run its
        # own budget. Setting `phone` in the signup config pins a single number
        # instead, which is useful for exercising the rate-limited path on
        # purpose.
        def synthetic_identity
          settings = @config.flows.fetch('signup')
          prefix = settings.fetch('email_prefix')

          {
            email: "#{prefix}+#{SecureRandom.hex(8)}@example.com",
            password: settings.fetch('password'),
            phone: presence(settings['phone']) || next_synthetic_phone,
          }
        end

        # Walks the area code x line number space in order so a single run never
        # repeats a number, starting at a random offset so consecutive
        # invocations of the harness do not all reuse the same first numbers and
        # land on a rate limit set by the previous invocation.
        def next_synthetic_phone
          index = @phone_mutex.synchronize do
            @phone_offset ||= SecureRandom.random_number(phone_space_size)
            @phone_counter += 1
            (@phone_offset + @phone_counter) % phone_space_size
          end

          area_code = PHONE_AREA_CODES.fetch(index % PHONE_AREA_CODES.length)
          line = PHONE_LINE_NUMBERS.to_a.fetch(
            (index / PHONE_AREA_CODES.length) % PHONE_LINE_NUMBERS.count,
          )

          format('%<area>s-555-%<line>04d', area: area_code, line: line)
        end

        def phone_space_size
          PHONE_AREA_CODES.length * PHONE_LINE_NUMBERS.count
        end

        def presence(value)
          str = value.to_s
          str.empty? ? nil : str
        end
      end
    end
  end
end
