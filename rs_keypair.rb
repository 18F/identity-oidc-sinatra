require 'openssl'
require 'fileutils'

module LoginGov
  module OidcSinatra
    # Generates the resource server key pair when it is missing. The pair is
    # local key material and is never committed (see .gitignore); a fresh clone
    # gets one from `make setup`, `rake login:rs_keypair` or the spec helper.
    # Equivalent to:
    #   openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    #     -subj "/CN=records-api.agency.localdev" -keyout rs_demo.key -out rs_demo.crt
    module RsKeypair
      DEFAULT_KEY_PATH = File.expand_path('config/rs_demo.key', __dir__)
      DEFAULT_CRT_PATH = File.expand_path('config/rs_demo.crt', __dir__)
      SUBJECT = '/CN=records-api.agency.localdev'
      VALIDITY_SECONDS = 10 * 365 * 24 * 60 * 60

      # @return [Boolean] true if a new pair was written
      def self.ensure!(key_path: DEFAULT_KEY_PATH, crt_path: DEFAULT_CRT_PATH)
        return false if File.exist?(key_path) && File.exist?(crt_path)

        generate!(key_path:, crt_path:)
        true
      end

      def self.generate!(key_path: DEFAULT_KEY_PATH, crt_path: DEFAULT_CRT_PATH)
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = OpenSSL::BN.rand(64)
        cert.subject = cert.issuer = OpenSSL::X509::Name.parse(SUBJECT)
        cert.public_key = key.public_key
        cert.not_before = Time.now
        cert.not_after = cert.not_before + VALIDITY_SECONDS
        cert.sign(key, OpenSSL::Digest.new('SHA256'))

        FileUtils.mkdir_p(File.dirname(key_path))
        File.write(key_path, key.to_pem, perm: 0o600)
        File.write(crt_path, cert.to_pem)
        [key_path, crt_path]
      end
    end
  end
end
