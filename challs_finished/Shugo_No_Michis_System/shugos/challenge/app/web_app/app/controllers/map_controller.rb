class MapController < ApplicationController
  include MapHelper

  GRID_CFG = {
    rows:   Integer(ENV.fetch("MAP_ROWS", 8)),
    cols:   Integer(ENV.fetch("MAP_COLS", 28)),
    cell:   Integer(ENV.fetch("MAP_CELL", 56)),
    margin: Integer(ENV.fetch("MAP_MARGIN", 48))
  }

  def index
    @grid = build_grid(**GRID_CFG)
    @tracker_url = map_tracker_path
  end

  def tracker
    client = LogicTrackerClient.new(
      url: ENV["LOGIC_TRACKER_URL"],
      one_based: ActiveModel::Type::Boolean.new.cast(ENV.fetch("LOGIC_TRACKER_ONE_BASED", "true")),
      timeout_sec: Integer(ENV.fetch("LOGIC_TRACKER_TIMEOUT", "1"))
    )

    matrix = client.send(:fetch_matrix) || client.send(:mock_matrix)
    render json: { matrix: matrix }
  end
end
