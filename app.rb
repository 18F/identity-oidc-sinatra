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

  get '/' do
    authorization_url = openid_configuration[:authorization_endpoint] + '?' + {
      client_id: CLIENT_ID,
      response_type: 'code',
      acr_values: ENV['ACR_VALUES'],
      scope: 'openid email',
      redirect_uri: ENV['REDIRECT_URI'],
      state: SecureRandom.hex,
      nonce: SecureRandom.hex,
      prompt: 'select_account',
    }.to_query

    erb :index, locals: { authorization_url: authorization_url }
  end

  get '/auth/result' do
    token_response = token(params[:code])
    userinfo_response = userinfo(token_response[:id_token])

    erb :success, locals: { userinfo: userinfo_response }
  end

  private

  def openid_configuration
    @openid_configuration ||= begin
      json(HTTParty.get(URI.join(SERVICE_PROVIDER, '/.well-known/openid-configuration')).body)
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
      iss: CLIENT_ID,
      sub: CLIENT_ID,
      aud: openid_configuration[:token_endpoint],
      jti: SecureRandom.urlsafe_base64,
      exp: Time.now.to_i + 1000,
    }

    JWT.encode(jwt_payload, sp_private_key, 'RS256')
  end

  def userinfo(id_token)
    JWT.decode(id_token, idp_public_key, true, algorithm: 'RS256', leeway: 5).
      first.
      with_indifferent_access
  end

  def json(response)
    JSON.parse(response.to_s).with_indifferent_access
  end

  def idp_public_key
    certs_response = json(HTTParty.get(openid_configuration[:jwks_uri]).body)

    JSON::JWK.new(certs_response[:keys].first).to_key
  end

  def sp_private_key
    @sp_private_key ||= OpenSSL::PKey::RSA.new(File.read('config/demo_sp.key'))
  end
end
