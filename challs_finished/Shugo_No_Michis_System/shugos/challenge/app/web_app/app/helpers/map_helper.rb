module MapHelper
  def build_grid(rows:, cols:, cell:, margin:)
    nodes = []
    idx = ->(r, c) { r * cols + c }

    rows.times do |r|
      cols.times do |c|
        nodes << {
          id: idx.call(r, c),
          row: r, col: c,
          x: margin + c * cell,
          y: margin + r * cell
        }
      end
    end

    edges = []
    rows.times do |r|
      cols.times do |c|
        a = idx.call(r, c)
        edges << edge_from(nodes[a], nodes[idx.call(r, c + 1)]) if c + 1 < cols
        edges << edge_from(nodes[a], nodes[idx.call(r + 1, c)]) if r + 1 < rows
      end
    end

    { nodes: nodes, edges: edges, rows: rows, cols: cols, cell: cell, margin: margin }
  end

  private

  def edge_from(a, b)
    { a: a[:id], b: b[:id], ax: a[:x], ay: a[:y], bx: b[:x], by: b[:y],
      len: Math.hypot(b[:x] - a[:x], b[:y] - a[:y]) }
  end
end
