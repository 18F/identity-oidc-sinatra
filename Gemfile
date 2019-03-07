# frozen_string_literal: true

git_source(:github) { |repo_name| "https://github.com/#{repo_name}.git" }

source 'https://rubygems.org'

ruby '~> 2.3.5'

gem 'activesupport', '~> 5.2'
gem 'dotenv' # TODO
gem 'httparty', '~> 0.16'
gem 'identity-hostdata', github: '18F/identity-hostdata', branch: 'master'
gem 'json-jwt', '~> 1.9.4'
gem 'jwt', '~> 2.1'
gem 'sinatra', '~> 2.0', '>= 2.0.2'

group :development do
  gem 'pry-byebug'
  gem 'reek'
  gem 'rubocop', require: false
end

group :test do
  gem 'fakefs', require: 'fakefs/safe'
  gem 'nokogiri', '~> 1.10'
  gem 'rack-test'
  gem 'rspec', '~> 3.5.0'
  gem 'webmock'
end
