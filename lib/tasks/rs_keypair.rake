# rake login:rs_keypair — create the resource server key pair (config/rs_demo.key
# and config/rs_demo.crt) when missing. The pair is local key material and is
# git-ignored; see rs_keypair.rb.
require_relative '../../rs_keypair'

namespace :login do
  desc 'Generate config/rs_demo.key and config/rs_demo.crt if missing (FORCE=1 to regenerate)'
  task :rs_keypair do
    if ENV['FORCE']
      LoginGov::OidcSinatra::RsKeypair.generate!
      puts 'Regenerated config/rs_demo.key and config/rs_demo.crt'
    elsif LoginGov::OidcSinatra::RsKeypair.ensure!
      puts 'Generated config/rs_demo.key and config/rs_demo.crt'
    else
      puts 'config/rs_demo.key already exists; leaving it alone'
    end
  end
end
