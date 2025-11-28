class LogicController < ApplicationController
  protect_from_forgery with: :null_session

  def tracker
    client = LogicTrackerClient.new(
      url: ENV["LOGIC_TRACKER_URL"],
      one_based: ActiveModel::Type::Boolean.new.cast(ENV.fetch("LOGIC_TRACKER_ONE_BASED", "true")),
      timeout_sec: Integer(ENV.fetch("LOGIC_TRACKER_TIMEOUT", "1"))
    )
    buses = client.buses
    render json: [
      buses.map { _1[:start_id] },
      buses.map { _1[:current_id] },
      buses.map { _1[:end_id] }
    ]
  end
end
