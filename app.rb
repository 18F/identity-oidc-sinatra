# frozen_string_literal: true

require 'dotenv/load'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/object/to_query'
require 'erubi'
require 'httparty'
require 'json'
require 'json/jwt'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'sinatra/base'
require 'time'

require_relative './config'

module LoginGov::OidcSinatra
  class AppError < StandardError; end

  class OpenidConnectRelyingParty < Sinatra::Base

    # Auto escape parameters in ERB.
    # Use `<%=` to escape HTML, or use `<%==` to inject unescaped raw HTML.
    set :erb, escape_html: true

    enable :sessions

    configure :development do
      require 'byebug'
    end

    def config
      @config ||= Config.new
    end

    get '/' do
      begin
        login_msg = session.delete(:login_msg)
        logout_msg = session.delete(:logout_msg)
        user_email = session[:email]
        logout_uri = session[:logout_uri]
        userinfo = session.delete(:userinfo)

        erb :index, locals: {
            ial_url: ial_url,
            ial1_link_class: ial1_link_class,
            ial2_link_class: ial2_link_class,
            ialmax_link_class: ialmax_link_class,
            login_msg: login_msg,
            logout_msg: logout_msg,
            user_email: user_email,
            logout_uri: logout_uri,
            userinfo: userinfo,
        }
      rescue AppError => err
        [500, erb(:errors, locals: { error: err.message })]
      rescue Errno::ECONNREFUSED => err
        [500, erb(:errors, locals: { error: err.inspect })]
      end
    end

    get '/auth/result' do
      code = params[:code]

      if code
        token_response = token(code)
        id_token = token_response[:id_token]
        userinfo_response = userinfo(id_token)

        session[:login_msg] = 'ok'
        session[:logout_uri] = logout_uri(token_response[:id_token])
        session[:userinfo] = userinfo_response
        session[:email] = session[:userinfo][:email]

        redirect to('/')
      else
        error = params[:error] || 'missing callback param: code'

        erb :errors, locals: { error: error }
      end
    end

    get '/logout' do
      session[:logout_msg] = 'ok'
      session.delete(:logout_uri)
      session.delete(:userinfo)
      session.delete(:email)
      redirect to('/')
    end

    get '/api/health' do
      begin
        content_type :json
        {
          authorization_endpoint: openid_configuration.fetch('authorization_endpoint'),
          private_key_fingerprint: Digest::SHA1.hexdigest(config.sp_private_key.to_der),
          healthy: true,
        }.to_json
      rescue StandardError => err
        halt 500, {
          error: err.inspect,
          healthy: false,
        }.to_json
      end
    end

    private

    def authorization_url(loa)
      openid_configuration[:authorization_endpoint] + '?' + {
        client_id: config.client_id,
        response_type: 'code',
        acr_values: 'http://idmanagement.gov/ns/assurance/' + (loa.zero? ? 'ial/0' : "loa/#{loa}"),
        scope: scopes_for(loa),
        redirect_uri: File.join(config.redirect_uri, '/auth/result'),
        state: random_value,
        nonce: random_value,
        prompt: 'select_account',
      }.to_query
    end

    def scopes_for(loa)
      case loa
      when 0
        'openid email social_security_number'
      when 1
        'openid email'
      when 3
        'openid email profile social_security_number phone'
      else
        raise ArgumentError.new("Unexpected LOA: #{loa.inspect}")
      end
    end

    def openid_configuration
      @openid_configuration ||= begin
        response = openid_configuration_response
        if response.code == 200
          json(response.body)
        else
          msg = 'Error: Unable to retrieve OIDC configuration from IdP.'
          msg += " #{config.idp_url} responded with #{response.code}."

          if response.code == 401
            msg += ' Perhaps we need to reimplement HTTP Basic Auth.'
          end

          raise AppError.new(msg)
        end
      end
    end

    def openid_configuration_response
      HTTParty.get(URI.join(config.idp_url, '/.well-known/openid-configuration'))
    end

    def token(code)
      json HTTParty.post(
        openid_configuration[:token_endpoint],
        body: {
          grant_type: 'authorization_code',
          code: code,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: client_assertion_jwt,
        }
      ).body
    end

    def client_assertion_jwt
      jwt_payload = {
        iss: config.client_id,
        sub: config.client_id,
        aud: openid_configuration[:token_endpoint],
        jti: random_value,
        nonce: random_value,
        exp: Time.now.to_i + 1000,
      }

      JWT.encode(jwt_payload, config.sp_private_key, 'RS256')
    end

    def userinfo(id_token)
      JWT.decode(id_token, idp_public_key, true, algorithm: 'RS256', leeway: 5).
        first.
        with_indifferent_access
    end

    def logout_uri(id_token)
      openid_configuration[:end_session_endpoint] + '?' + {
        id_token_hint: id_token,
        post_logout_redirect_uri: File.join(config.redirect_uri, 'logout'),
        state: SecureRandom.hex,
      }.to_query
    end

    def json(response)
      JSON.parse(response.to_s).with_indifferent_access
    end

    def idp_public_key
      certs_response = json(
        HTTParty.get(openid_configuration[:jwks_uri]).body
      )
      JSON::JWK.new(certs_response[:keys].first).to_key
    end

    def random_value
      SecureRandom.hex
    end

    def maybe_redact_ssn(ssn)
      if config.redact_ssn?
        # redact all characters since they're all sensitive
        ssn = ssn&.gsub(/\d/, '#')
      end

      ssn
    end

    def ial_url
      return authorization_url(3) if params[:ial] == '2'
      authorization_url(0) if params[:ial] == '0'
      authorization_url(1)
    end

    def ial1_link_class
      return 'text-underline' unless params[:ial] == '2'

      nil
    end

    def ial2_link_class
      return 'text-underline' if params[:ial] == '2'

      nil
    end

    def ialmax_link_class
      return 'text-underline' if params[:ial] == 'max'

      nil
    end
  end
end
