# frozen_string_literal: true

git_source(:github) { |repo_name| "https://github.com/#{repo_name}.git" }

source 'https://rubygems.org'

ruby '~> 2.6.5'

gem 'activesupport', '~> 5.2', '>= 5.2.4.3'
gem 'aws-sdk-secretsmanager', '~> 1.21'
gem 'dotenv'
gem 'erubi', '~> 1.8'
gem 'httparty', '~> 0.16'
gem 'json-jwt', '~> 1.11.0'
gem 'jwt', '~> 2.1'
gem 'rake'
gem 'sinatra', '~> 2.0', '>= 2.0.5'

group :development do
  gem 'pry-byebug'
  gem 'reek'
  gem 'rubocop', require: false
end

group :test do
  gem 'fakefs', require: 'fakefs/safe'
  gem 'nokogiri', '>= 1.11.0'
  gem 'rack-test', '>= 1.1.0'
  gem 'rspec', '~> 3.5.0'
  gem 'webmock'
end

group :development, :test do
  gem 'byebug'
end
