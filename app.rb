# frozen_string_literal: true
require 'dotenv/load'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/object/to_query'
require 'erb'
require 'http'
require 'json/jwt'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'sinatra/base'
require 'time'

class OpenidConnectRelyingParty < Sinatra::Base
  SERVICE_PROVIDER = ENV['IDP_SP_URL']

  CLIENT_ID = 'urn:gov:gsa:openidconnect:sp:sinatra'

  get '/' do
    authorization_url = openid_configuration[:authorization_endpoint] + '?' + {
      client_id: CLIENT_ID,
      response_type: 'code',
      acr_values: ENV['ACR_VALUES'],
      scope: 'openid email',
      redirect_uri: ENV['REDIRECT_URI'],
      state: SecureRandom.urlsafe_base64,
      nonce: SecureRandom.urlsafe_base64,
      prompt: 'select_account',
    }.to_query

    erb :index, locals: { authorization_url: authorization_url }
  end

  get '/test' do
    erb :test
  end

  get '/auth/result' do
    token_response = token(params[:code])
    userinfo_response = userinfo(token_response[:id_token])

    erb :success, locals: { userinfo: userinfo_response }
  end

  private

  def openid_configuration
    @openid_configuration ||= begin
      uri = URI.join(SERVICE_PROVIDER, '/.well-known/openid-configuration')
      if ENV['IDP_USER'] && ENV['IDP_PASS']
        resp = HTTP.basic_auth(:user => ENV['IDP_USER'], :pass => ENV['IDP_PASS']).get(uri)
      else
        resp = HTTP.get(uri)
      end
      json(resp)
    end
  end

  def token(code)
    json HTTP.post(
      openid_configuration[:token_endpoint],
      json: {
        grant_type: 'authorization_code',
        code: code,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: client_assertion_jwt,
      }
    )
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
    certs_response = json(HTTP.get(openid_configuration[:jwks_uri]))

    JSON::JWK.new(certs_response[:keys].first).to_key
  end

  def sp_private_key
    @sp_private_key ||= OpenSSL::PKey::RSA.new(File.read('config/demo_sp.key'))
  end
end
