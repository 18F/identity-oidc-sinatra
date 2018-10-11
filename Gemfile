# frozen_string_literal: true

git_source(:github) { |repo_name| "https://github.com/#{repo_name}.git" }

source 'https://rubygems.org'

ruby '~> 2.3.5'

gem 'activesupport'
gem 'dotenv'
gem 'httparty'
gem 'identity-hostdata', github: '18F/identity-hostdata', branch: 'master'
gem 'json-jwt'
gem 'jwt'
gem 'sinatra'

group :development do
  gem 'pry-byebug'
  gem 'reek'
  gem 'rubocop', require: false
end

group :test do
  gem 'fakefs', require: 'fakefs/safe'
  gem 'nokogiri', '>= 1.8.5'
  gem 'rack-test'
  gem 'rspec', '~> 3.5.0'
  gem 'webmock'
end
