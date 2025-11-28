require "socket"
require "json"

class DataParserClient
  def initialize(
    host: ENV["PARSER_HOST"],
    port: Integer(ENV.fetch("PARSER_PORT", "9099")),
    connect_timeout: Float(ENV.fetch("PARSER_CONNECT_TIMEOUT", "0.5")),
    read_timeout: Float(ENV.fetch("PARSER_READ_TIMEOUT", "1.0"))
  )
    @host, @port = host.presence, port
    @connect_timeout, @read_timeout = connect_timeout, read_timeout
  end

  # Public: returns a normalized payload:
  # { source: "parser"|"mock", fetched_at: "...", tickets: [ {name:, bus_code:, user_email:, travel_date:, seats:, start_node:, end_node:, total_cents:} ] }
  def tickets_payload
    payload = fetch_from_socket || mock_payload
    payload[:fetched_at] = Time.now.utc.iso8601
    payload
  end

  private

  def fetch_from_socket
    return nil unless @host
    raw = nil
    Socket.tcp(@host, @port, connect_timeout: @connect_timeout) do |sock|
      # Simple line protocol; your external app can change this—just return JSON.
      sock.write("TICKETS\n") rescue nil
      if IO.select([sock], nil, nil, @read_timeout)
        raw = (sock.readpartial(64 * 1024) rescue sock.read) rescue nil
      end
    end
    data = parse_json(raw) or return nil
    normalize(data).merge(source: "parser")
  rescue
    nil
  end

  def parse_json(raw)
    return nil if raw.nil? || raw.strip.empty?
    JSON.parse(raw)
  rescue JSON::ParserError
    nil
  end

  # Accepts either { "tickets": [...] } or a bare array
  def normalize(data)
    list = data.is_a?(Hash) ? (data["tickets"] || data[:tickets]) : data
    list = Array(list)

    tickets = list.map do |t|
      {
        name:         (t["name"] || t[:name] || "TKT-#{SecureRandom.hex(3)}"),
        bus_code:     (t["bus_code"] || t[:bus_code]).to_s,
        user_email:   (t["user_email"] || t[:user_email]).to_s.presence || "—",
        travel_date:  (t["travel_date"] || t[:travel_date]).to_s,
        seats:        (t["seats"] || t[:seats] || 1).to_i,
        start_node:   (t["start_node"] || t[:start_node]).to_i,
        end_node:     (t["end_node"] || t[:end_node]).to_i,
        total_cents:  (t["total_cents"] || t[:total_cents] || 0).to_i
      }
    end

    { tickets: tickets }
  end

  # Fallback: build from DB if available, else pseudo-random
  def mock_payload
    sample = ::Ticket.limit(5).order("RANDOM()") rescue []
    tickets =
      if sample.any?
        sample.map do |t|
          {
            name: "TKT-#{t.id}",
            bus_code: t.bus_code.to_s,
            user_email: t.user&.email || "—",
            travel_date: t.travel_date.to_s,
            seats: t.seats,
            start_node: t.start_node,
            end_node: t.end_node,
            total_cents: t.total_cents
          }
        end
      else
        # lightweight pseudo-randoms
        Array.new(5) do |i|
          s = rand(0..10); e = rand(30..95)
          dist = (e - s).abs
          total = (dist * 50 * 100) # 50.00 per edge
          {
            name: "MOCK-#{i+1}",
            bus_code: i.to_s,
            user_email: "—",
            travel_date: Date.current.to_s,
            seats: 1,
            start_node: s,
            end_node: e,
            total_cents: total
          }
        end
      end
    { source: "mock", tickets: tickets }
  end
end
