require "active_support/core_ext/integer/time"
Rails.application.configure do
  config.cache_classes = false
  config.eager_load = false
  config.consider_all_requests_local = true
  config.server_timing = true
  config.action_controller.perform_caching = false
  config.active_storage.service = :local
  config.hosts.clear

  config.assets.prefix = "#{ENV['RAILS_RELATIVE_URL_ROOT']}/assets"
  config.active_storage.routes_prefix = "#{ENV['RAILS_RELATIVE_URL_ROOT']}/rails/active_storage"
  config.action_cable.mount_path = "#{ENV['RAILS_RELATIVE_URL_ROOT']}/cable"

  routes.default_url_options = { script_name: ENV.fetch('RAILS_RELATIVE_URL_ROOT', '/') }
  config.action_controller.default_url_options = { script_name: ENV.fetch('RAILS_RELATIVE_URL_ROOT', '/') }

end
