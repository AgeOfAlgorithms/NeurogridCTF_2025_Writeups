from bisect import bisect_left

n = int(input())
ranks = [0] + list(map(int, input().split()))
adj = [[] for _ in range(n + 1)]
for _ in range(n - 1):
    u, v = map(int, input().split())
    adj[u].append(v)
    adj[v].append(u)

ans = 1

def lis(path):
    t = []
    for v in path:
        p = bisect_left(t, v)
        if p == len(t):
            t.append(v)
        else:
            t[p] = v
    return len(t)

def dfs(node, parent, path):
    global ans
    ans = max(ans, lis(path))
    for child in adj[node]:
        if child != parent:
            path.append(ranks[child])
            dfs(child, node, path)
            path.pop()

for start in range(1, n + 1):
    dfs(start, -1, [ranks[start]])

print(ans)
