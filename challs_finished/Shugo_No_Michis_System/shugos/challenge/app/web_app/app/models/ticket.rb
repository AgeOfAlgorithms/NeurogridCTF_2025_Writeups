class Ticket < ApplicationRecord
  belongs_to :user, optional: true

  GRID_ROWS = Integer(ENV.fetch("GRID_ROWS", "8"))
  GRID_COLS = Integer(ENV.fetch("GRID_COLS", "12"))

  BASE_RATE_CENTS     = Integer(ENV.fetch("BASE_RATE_CENTS", "5000"))
  PENALTY_RATE_FACTOR = Float(ENV.fetch("PENALTY_RATE_FACTOR", "0.8"))

  validates :name, presence: true, uniqueness: true, length: { maximum: 255 }
  validates :bus_code, :start_node, :end_node, :travel_date, presence: true
  validates :seats, numericality: { only_integer: true, greater_than: 0 }

  before_validation :assign_ticket_name, on: :create
  before_validation :calculate_initial_pricing, on: :create

  def self.row_col_for(node_id)
    [node_id / GRID_COLS, node_id % GRID_COLS]
  end

  def self.distance_edges_between(a_id, b_id)
    ar, ac = row_col_for(a_id)
    br, bc = row_col_for(b_id)
    (ar - br).abs + (ac - bc).abs
  end

  def self.base_for(distance_edges:, seats:)
    (distance_edges * BASE_RATE_CENTS * seats).to_i
  end

  def self.penalty_for(old_distance:, new_distance:, seats:)
    extra_edges = new_distance - old_distance
    return 0 if extra_edges <= 0
    (extra_edges * BASE_RATE_CENTS * PENALTY_RATE_FACTOR * seats).round
  end

  def money_cents_to_s(cents)
    format('%.2f', cents.to_i / 100.0)
  end

  def price_base_s
    money_cents_to_s(base_cents)
  end

  def price_penalty_s
    money_cents_to_s(penalty_cents)
  end

  def price_total_s
    money_cents_to_s(total_cents)
  end

  def calculate_initial_pricing
    self.distance_edges = self.class.distance_edges_between(start_node, end_node)
    self.base_cents     = self.class.base_for(distance_edges: distance_edges, seats: seats.presence || 1)
    self.penalty_cents  = 0
    self.total_cents    = base_cents + penalty_cents
  end

  def rebook_to!(new_start_id:, new_end_id:)
    old_distance = distance_edges
    new_distance = self.class.distance_edges_between(new_start_id, new_end_id)

    new_base = self.class.base_for(distance_edges: new_distance, seats: seats)
    penalty  = self.class.penalty_for(old_distance: old_distance, new_distance: new_distance, seats: seats)

    self.start_node     = new_start_id
    self.end_node       = new_end_id
    self.distance_edges = new_distance
    self.base_cents     = new_base
    self.penalty_cents  = penalty
    self.total_cents    = new_base + penalty

    save!

    {
      old_distance: old_distance,
      new_distance: new_distance,
      base_cents:   new_base,
      penalty_cents: penalty,
      total_cents:  total_cents
    }
  end

  def self.generate_ticket_name
    "TICKET-" + SecureRandom.alphanumeric(10).upcase
  end

  private

  def assign_ticket_name
    return if name.present?
    
    10.times do
      candidate = self.class.generate_ticket_name
      unless self.class.exists?(name: candidate)
        self.name = candidate
        return
      end
    end
    self.name = "TICKET-" + SecureRandom.hex(4).upcase
  end
end
