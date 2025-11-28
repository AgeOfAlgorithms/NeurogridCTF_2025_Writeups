module Admin
  class ParserController < ApplicationController
    before_action :require_login
    def index; end

    def tickets
      payload = DataParserClient.new.tickets_payload
      render json: payload
    end
  end
end
