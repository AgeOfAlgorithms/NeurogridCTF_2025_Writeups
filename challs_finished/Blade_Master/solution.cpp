#include <iostream>
#include <vector>
#include <algorithm>
#include <queue>
#include <chrono>

using namespace std;

const int MAXN = 25005;
vector<int> adj[MAXN];
int ranks[MAXN];
int n;
int ans = 1;
int max_dist[MAXN];

vector<int> lis_tails;

void bfs(int start, int* dist_array) {
    for (int i = 1; i <= n; ++i) dist_array[i] = -1;
    queue<int> q;
    q.push(start);
    dist_array[start] = 0;
    while (!q.empty()) {
        int u = q.front();
        q.pop();
        for (int v : adj[u]) {
            if (dist_array[v] == -1) {
                dist_array[v] = dist_array[u] + 1;
                q.push(v);
            }
        }
    }
}

void dfs(int u, int p) {
    if ((int)lis_tails.size() + max_dist[u] + 1 <= ans) {
        return;
    }

    int val = ranks[u];
    auto it = lower_bound(lis_tails.begin(), lis_tails.end(), val);
    
    int pos = distance(lis_tails.begin(), it);
    int old_val = -1;
    bool pushed = false;
    
    if (it == lis_tails.end()) {
        lis_tails.push_back(val);
        pushed = true;
    } else {
        old_val = *it;
        *it = val;
    }
    
    ans = max(ans, (int)lis_tails.size());
    
    for (int v : adj[u]) {
        if (v != p) {
            dfs(v, u);
        }
    }
    
    if (pushed) {
        lis_tails.pop_back();
    } else {
        lis_tails[pos] = old_val;
    }
}

int main() {
    auto start_time = chrono::high_resolution_clock::now();
    
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    
    if (!(cin >> n)) return 0;
    
    for (int i = 1; i <= n; ++i) {
        cin >> ranks[i];
    }
    
    for (int i = 0; i < n - 1; ++i) {
        int u, v;
        cin >> u >> v;
        adj[u].push_back(v);
        adj[v].push_back(u);
    }
    
    int distA[MAXN];
    bfs(1, distA);
    int A = 1;
    for (int i = 1; i <= n; ++i) if (distA[i] > distA[A]) A = i;
    
    bfs(A, distA);
    int B = 1;
    for (int i = 1; i <= n; ++i) if (distA[i] > distA[B]) B = i;
    
    int distB[MAXN];
    bfs(B, distB);
    
    for (int i = 1; i <= n; ++i) {
        max_dist[i] = max(distA[i], distB[i]);
    }
    
    vector<pair<int, int>> nodes_by_dist;
    for (int i = 1; i <= n; ++i) {
        nodes_by_dist.push_back({max_dist[i], i});
    }
    sort(nodes_by_dist.rbegin(), nodes_by_dist.rend());
    
    for (auto p : nodes_by_dist) {
        // Check time
        auto current_time = chrono::high_resolution_clock::now();
        double elapsed = chrono::duration_cast<chrono::duration<double>>(current_time - start_time).count();
        if (elapsed > 4.5) break; // Stop if close to 5s limit
        
        int start = p.second;
        lis_tails.clear();
        dfs(start, -1);
    }
    
    cout << ans << endl;
    
    return 0;
}
