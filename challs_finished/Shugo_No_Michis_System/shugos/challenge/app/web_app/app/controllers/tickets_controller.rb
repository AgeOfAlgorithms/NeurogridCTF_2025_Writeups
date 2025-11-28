class TicketsController < ApplicationController
  before_action :require_login, only: [:new, :create, :show, :rebook, :index]
  before_action :load_buses,    only: [:new, :create, :show, :rebook]

  PRICE_PER_EDGE_CENTS = Integer(ENV.fetch("TICKET_PRICE_PER_EDGE_CENTS", "125"))
  GRID_ROWS = Integer(ENV.fetch("MAP_ROWS", "8"))
  GRID_COLS = Integer(ENV.fetch("MAP_COLS", "28"))

  def index
    @tickets = ::Ticket.where(user_id: current_user.id).order(created_at: :desc)
  end

  def new
    @ticket = ::Ticket.new(travel_date: Date.current, seats: 1)
    @ticket.name = ::Ticket.generate_ticket_name
  end

  def create
    selection = @buses.find { |b| b[:code] == params.dig(:ticket, :bus_code) }
    unless selection
      redirect_to new_ticket_path, alert: "Please select a valid bus." and return
    end

    start_id   = selection[:start_id]
    current_id = selection[:current_id] || start_id
    end_id     = selection[:end_id]

    @ticket = ::Ticket.new(ticket_params.except(:start_node, :end_node))
    @ticket.user         = current_user
    @ticket.bus_code     = selection[:code]
    @ticket.start_node   = start_id
    @ticket.current_node = current_id
    @ticket.end_node     = end_id
    @ticket.metadata     = { source: (ENV["LOGIC_TRACKER_URL"].present? ? "logic_tracker" : "mock") }
    @ticket.name         = ::Ticket.generate_ticket_name if @ticket.name.blank?

    dist = manhattan_edges(current_id, end_id, GRID_COLS)
    seats = Integer(@ticket.seats.presence || 1)
    base  = dist * PRICE_PER_EDGE_CENTS * seats

    @ticket.distance_edges = dist
    @ticket.base_cents     = base
    @ticket.penalty_cents  = 0
    @ticket.total_cents    = base

    if @ticket.save
      redirect_to ticket_path(@ticket), notice: "Booked #{@ticket.name} (#{dist} edges, #{format_price(base)})."
    else
      flash.now[:alert] = @ticket.errors.full_messages.to_sentence
      render :new, status: :unprocessable_entity
    end
  end

  def show
    @ticket = ::Ticket.find(params[:id])
    if @ticket.user_id.present? && @ticket.user_id != current_user&.id
      redirect_to tickets_path, alert: "Not authorized" and return
    end
  end

  def rebook
    @ticket = ::Ticket.find(params[:id])
    if @ticket.user_id.present? && @ticket.user_id != current_user&.id
      redirect_to tickets_path, alert: "Not authorized" and return
    end

    selection = @buses.find { |b| b[:code] == params.dig(:ticket, :bus_code) }
    unless selection
      redirect_to ticket_path(@ticket), alert: "Choose a valid bus to rebook." and return
    end

    begin
      @ticket.bus_code     = selection[:code]
      @ticket.current_node = selection[:current_id] || selection[:start_id]

      @ticket.rebook_to!(new_start_id: selection[:start_id], new_end_id: selection[:end_id])
      dist  = manhattan_edges(@ticket.current_node, @ticket.end_node, GRID_COLS)
      seats = Integer(@ticket.seats.presence || 1)
      base  = dist * PRICE_PER_EDGE_CENTS * seats

      @ticket.distance_edges = dist
      @ticket.base_cents     = base
      @ticket.total_cents    = base + (@ticket.penalty_cents || 0)
      @ticket.save!

      redirect_to ticket_path(@ticket),
        notice: "Rebooked. Distance #{dist} edges, total #{format_price(@ticket.total_cents)} (penalty #{format_price(@ticket.penalty_cents)})."
    rescue => e
      Rails.logger.error("[rebook] #{e.class}: #{e.message}")
      redirect_to ticket_path(@ticket), alert: "Rebook failed."
    end
  end

  private

  def load_buses
    @buses = LogicTrackerClient.new.buses
  end

  def ticket_params
    params.require(:ticket).permit(:name, :bus_code, :travel_date, :seats)
  end

  def manhattan_edges(a_id, b_id, cols)
    return 0 if a_id.nil? || b_id.nil?
    ar, ac = a_id.divmod(cols)
    br, bc = b_id.divmod(cols)
    (ar - br).abs + (ac - bc).abs
  end

  def format_price(cents)
    format("$%.2f", cents.to_i / 100.0)
  end
end
