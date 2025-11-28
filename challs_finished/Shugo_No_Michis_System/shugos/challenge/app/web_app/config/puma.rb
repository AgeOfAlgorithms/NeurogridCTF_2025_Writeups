threads_count = ENV.fetch("RAILS_MAX_THREADS", 5)
threads threads_count, threads_count
port ENV.fetch("PORT", 3000), ENV.fetch("HOST", "127.0.0.1")
environment ENV.fetch("RAILS_ENV", "development")
plugin :tmp_restart
