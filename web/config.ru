require 'rubygems'
require 'sinatra'
require 'sass/plugin/rack'
use Sass::Plugin::Rack

set :env, :production
set :port, 4567
disable :run, :reload

require File.dirname(__FILE__) + '/syslog'

run Syslog::Application
