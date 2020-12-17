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
require 'logger'

require_relative './config'
require_relative './openid_configuration'

module LoginGov::OidcSinatra
  class AppError < StandardError; end

  class OpenidConnectRelyingParty < Sinatra::Base

    # Auto escape parameters in ERB.
    # Use `<%=` to escape HTML, or use `<%==` to inject unescaped raw HTML.
    set :erb, escape_html: true
    set :logger, Logger.new(STDOUT)

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
            ial: params[:ial],
            aal: params[:aal],
            ial_url: authorization_url(ial: params[:ial], aal: params[:aal]),
            login_msg: login_msg,
            logout_msg: logout_msg,
            user_email: user_email,
            logout_uri: logout_uri,
            userinfo: userinfo,
            access_denied: params[:error]=='access_denied'
        }
      rescue AppError => err
        [500, erb(:errors, locals: { error: err.message })]
      rescue Errno::ECONNREFUSED => err
        [500, erb(:errors, locals: { error: err.inspect })]
      end
    end

    get '/auth/request' do
      idp_url = authorization_url(ial: params[:ial], aal: params[:aal])

      logger.info("Redirecting to #{idp_url}")

      redirect to(idp_url)
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

        if error == 'access_denied'
          redirect to('/?error=access_denied')
        else
          erb :errors, locals: { error: error }
        end
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

    def authorization_url(ial:, aal: nil)
      openid_configuration[:authorization_endpoint] + '?' + {
        client_id: config.client_id,
        response_type: 'code',
        acr_values: acr_values(ial: ial, aal: aal),
        scope: scopes_for(ial),
        redirect_uri: File.join(config.redirect_uri, '/auth/result'),
        state: random_value,
        nonce: random_value,
        prompt: 'select_account',
      }.to_query
    end

    def scopes_for(ial)
      case ial.to_i
      when 0
        'openid email social_security_number'
      when 1
        'openid email'
      when 2
        'openid email profile social_security_number phone'
      else
        raise ArgumentError.new("Unexpected IAL: #{ial.inspect}")
      end
    end

    def acr_values(ial:, aal:)
      values = []

      values << case ial
      when nil, '', '1'
        'http://idmanagement.gov/ns/assurance/ial/1'
      when '2'
        'http://idmanagement.gov/ns/assurance/ial/2'
      when '2-strict'
        'http://idmanagement.gov/ns/assurance/ial/2?strict=true'
      when '0'
        'http://idmanagement.gov/ns/assurance/ial/0'
      end

      values << case aal
      when '3'
        'http://idmanagement.gov/ns/assurance/aal/3'
      when '3-hspd12'
        'http://idmanagement.gov/ns/assurance/aal/3?hspd12=true'
      end

      values.join(' ')
    end

    def openid_configuration
      if config.cache_oidc_config?
        OpenidConfiguration.cached
      else
        OpenidConfiguration.live
      end
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
  end
end
