require "net/http"
require "json"
require "timeout"

class LogicTrackerClient
  DEFAULT_ROWS = 8
  DEFAULT_COLS = 12

  def initialize(
    url: ENV["LOGIC_TRACKER_URL"],
    one_based: ActiveModel::Type::Boolean.new.cast(ENV.fetch("LOGIC_TRACKER_ONE_BASED", "true")),
    timeout_sec: Integer(ENV.fetch("LOGIC_TRACKER_TIMEOUT", "1"))
  )
    @url       = url.presence
    @one_based = one_based
    @timeout   = timeout_sec
  end

  def buses
    matrix = fetch_matrix || mock_matrix
    starts, currents, ends = matrix
    n = [starts.length, currents.length, ends.length].min
    Array.new(n) do |i|
      s = normalize_id(starts[i])
      c = normalize_id(currents[i])
      e = normalize_id(ends[i])
      {
        code:       i.to_s,     # stable index → simple code
        start_id:   s,
        current_id: c,
        end_id:     e
      }
    end
  end

  private

  def normalize_id(v)
    return nil if v.nil?
    id = Integer(v)
    @one_based ? (id - 1) : id
  rescue
    nil
  end

  def fetch_matrix
    return nil unless @url
    Timeout.timeout(@timeout) do
      uri = URI(@url)
      resp = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
        http.read_timeout = @timeout
        http.open_timeout = @timeout
        http.get(uri.request_uri)
      end
      return nil unless resp.is_a?(Net::HTTPSuccess)
      json = JSON.parse(resp.body) rescue nil
      return json["matrix"] if json.is_a?(Hash) && json["matrix"].is_a?(Array)
      return json if json.is_a?(Array)
    end
  rescue
    nil
  end

  # Mock matrix: left-edge starts → right-edge ends; current anywhere on that path.
  def mock_matrix
    rows = DEFAULT_ROWS
    cols = DEFAULT_COLS
    m = Integer(ENV.fetch("LOGIC_TRACKER_MOCK_BUSES", "5"))
    starts, currents, ends = [], [], []
    m.times do |i|
      s = node_id(rows: rows, cols: cols, row: rand(0...rows), col: 0)
      e = node_id(rows: rows, cols: cols, row: rand(0...rows), col: cols - 1)
      path = shortest_path(rows, cols, s, e)
      c = path.empty? ? s : path.sample
      starts << export_id(s)
      currents << export_id(c)
      ends << export_id(e)
    end
    [starts, currents, ends]
  end

  # --- grid helpers (IDs are 0..rows*cols-1) ---
  def node_id(rows:, cols:, row:, col:)
    row * cols + col
  end

  def neighbors(rows, cols, id)
    r = id / cols
    c = id % cols
    n = []
    n << node_id(rows: rows, cols: cols, row: r,     col: c - 1) if c > 0
    n << node_id(rows: rows, cols: cols, row: r,     col: c + 1) if c + 1 < cols
    n << node_id(rows: rows, cols: cols, row: r - 1, col: c)     if r > 0
    n << node_id(rows: rows, cols: cols, row: r + 1, col: c)     if r + 1 < rows
    n
  end

  def shortest_path(rows, cols, s, g)
    prev = Array.new(rows * cols, -1)
    q = [s]
    seen = Array.new(rows * cols, false)
    seen[s] = true
    until q.empty?
      u = q.shift
      break if u == g
      neighbors(rows, cols, u).each do |v|
        next if seen[v]
        seen[v] = true
        prev[v] = u
        q << v
      end
    end
    return [] unless seen[g]
    path = []
    cur = g
    while cur != -1
      path << cur
      break if cur == s
      cur = prev[cur]
    end
    path.reverse
  end

  def export_id(id)
    @one_based ? (id + 1) : id
  end
end
