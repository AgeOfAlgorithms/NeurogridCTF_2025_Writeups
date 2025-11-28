require_relative "boot"
require "rails/all"
Bundler.require(*Rails.groups)
module WebApp
  class Application < Rails::Application
    config.action_controller.relative_url_root = ENV['RAILS_RELATIVE_URL_ROOT']
    config.load_defaults 7.1
    config.generators.system_tests = nil
  end
end
