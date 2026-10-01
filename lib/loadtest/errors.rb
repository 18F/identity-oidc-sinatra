# frozen_string_literal: true

module LoginGov
  module OidcSinatra
    module Loadtest
      # Raised for every harness-level failure: transport errors, unexpected
      # pages, missing form fields. Flows let these propagate; the scheduler
      # catches them per run so one bad iteration does not kill a thread.
      class Error < StandardError; end

      # Raised when configuration is invalid. Separate from Error because this
      # is fatal for the whole run rather than for a single iteration.
      class ConfigError < StandardError; end
    end
  end
end
