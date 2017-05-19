# frozen_string_literal: true
require 'dotenv/load'
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

class OpenidConnectRelyingParty < Sinatra::Base
  SERVICE_PROVIDER = ENV['IDP_SP_URL']
  CLIENT_ID = ENV['CLIENT_ID']
  BASIC_AUTH = { username: ENV['IDP_USER'], password: ENV['IDP_PASSWORD'] }.freeze
  REDIRECT_URI = ENV['REDIRECT_URI']

  get '/' do
    if openid_configuration
      erb :index, locals: { authorization_url: authorization_url }
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

  def authorization_url
    openid_configuration[:authorization_endpoint] + '?' + {
      client_id: CLIENT_ID,
      response_type: 'code',
      acr_values: ENV['ACR_VALUES'],
      scope: 'openid email',
      redirect_uri: File.join(REDIRECT_URI, '/auth/result'),
      state: random_value,
      nonce: random_value,
      prompt: 'select_account',
    }.to_query
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
    HTTParty.get(
      URI.join(SERVICE_PROVIDER, '/.well-known/openid-configuration'),
      basic_auth: BASIC_AUTH
    )
  end

  def openid_configuration_error
    response_code = openid_configuration_response.code

    if response_code == 401
      "Error: #{SERVICE_PROVIDER} responded with #{response_code}.
       Check basic authentication in IDP_USER and IDP_PASSSWORD environment variables."
    else
      "Error: #{SERVICE_PROVIDER} responded with #{response_code}."
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
      },
      basic_auth: BASIC_AUTH
    ).body
  end

  def client_assertion_jwt
    jwt_payload = {
      iss: CLIENT_ID,
      sub: CLIENT_ID,
      aud: openid_configuration[:token_endpoint],
      jti: random_value,
      nonce: random_value,
      exp: Time.now.to_i + 1000,
    }

    JWT.encode(jwt_payload, sp_private_key, 'RS256')
  end

  def userinfo(id_token)
    JWT.decode(id_token, idp_public_key, true, algorithm: 'RS256', leeway: 5).
      first.
      with_indifferent_access
  end

  def logout_uri(id_token)
    openid_configuration[:end_session_endpoint] + '?' + {
      id_token_hint: id_token,
      post_logout_redirect_uri: REDIRECT_URI,
      state: SecureRandom.hex,
    }.to_query
  end

  def json(response)
    JSON.parse(response.to_s).with_indifferent_access
  end

  def idp_public_key
    certs_response = json(
      HTTParty.get(
        openid_configuration[:jwks_uri],
        basic_auth: BASIC_AUTH
      ).body
    )
    JSON::JWK.new(certs_response[:keys].first).to_key
  end

  def sp_private_key
    @sp_private_key ||= OpenSSL::PKey::RSA.new(File.read('config/demo_sp.key'))
  end

  def random_value
    SecureRandom.hex
  end
end
