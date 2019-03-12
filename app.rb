# frozen_string_literal: true

require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/object/to_query'
require 'erb'
require 'httparty'
require 'json/jwt'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'sinatra/base'
require 'time'

require_relative './config'

module LoginGov::OidcSinatra; class OpenidConnectRelyingParty < Sinatra::Base

  def config
    @config ||= Config.new
  end

  get '/' do
    if openid_configuration
      erb :index, locals: { loa1_url: authorization_url(1), loa3_url: authorization_url(3) }
    else
      erb :errors, locals: { error: openid_configuration_error }
    end
  end

  get '/auth/result' do
    code = params[:code]

    if code
      token_response = token(code)
      id_token = token_response[:id_token]
      userinfo_response = userinfo(id_token)

      erb :success, locals: {
        userinfo: userinfo_response,
        logout_uri: logout_uri(token_response[:id_token]),
      }
    else
      error = params[:error] || 'missing callback param: code'

      erb :errors, locals: { error: error }
    end
  end

  private

  def authorization_url(loa)
    openid_configuration[:authorization_endpoint] + '?' + {
      client_id: config.client_id,
      response_type: 'code',
      acr_values: 'http://idmanagement.gov/ns/assurance/loa/' + loa.to_s,
      scope: scopes_for(loa),
      redirect_uri: File.join(config.redirect_uri, '/auth/result'),
      state: random_value,
      nonce: random_value,
      prompt: 'select_account',
    }.to_query
  end

  def scopes_for(loa)
    case loa
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
        false
      end
    end
  end

  def openid_configuration_response
    HTTParty.get(URI.join(config.idp_url, '/.well-known/openid-configuration'))
  end

  def openid_configuration_error
    response_code = openid_configuration_response.code

    if response_code == 401
      "Error: #{config.idp_url} responded with #{response_code}.
       Perhaps we need to reimplement HTTP Basic Auth."
    else
      "Error: #{config.idp_url} responded with #{response_code}."
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
      post_logout_redirect_uri: config.redirect_uri,
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
      ssn = ssn.gsub(/\d/, '#')
    end

    ssn
  end
end; end
