# frozen_string_literal: true

git_source(:github) { |repo_name| "https://github.com/#{repo_name}.git" }

source 'https://rubygems.org'

ruby "~> #{File.read(File.join(__dir__, '.ruby-version')).strip}"

gem 'aws-sdk-secretsmanager', '~> 1.21'
gem 'dotenv'
gem 'erubi', '~> 1.8'
gem 'faraday'
gem 'json-jwt', '~> 1.16.6'
gem 'jwe'
gem 'jwt', '~> 2.1'
gem 'nokogiri', '>= 1.18.8'
gem 'puma', '~> 5.6'
gem 'rake'
gem 'sinatra', '~> 2.2'
gem 'newrelic_rpm'

group :development do
  gem 'pry-byebug'
end

group :test do
  gem 'fakefs', require: 'fakefs/safe'
  gem 'rack-test', '>= 1.1.0'
  gem 'rspec', '~> 3.11'
  gem 'simplecov', require: false
  gem 'webmock'
end

group :development, :test do
  gem 'byebug'
  gem 'rubocop', require: false
  gem 'rubocop-rspec', require: false
end
