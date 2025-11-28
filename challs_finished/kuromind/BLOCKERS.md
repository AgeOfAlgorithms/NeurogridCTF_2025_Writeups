# Blockers and Events Log

## 2025-11-22

### 🔴 Blocker: Process Isolation
- **Event**: Discovered that the bot runs in a separate process from the main app.
- **Impact**: This invalidated all previous attempts to exploit EJS RCE via prototype pollution, as the pollution in the main app doesn't affect the bot's process memory.
- **Resolution**: Shifted focus to exploiting the main app's behavior or finding a way to affect the bot's interaction with the main app.

### 🟢 Discovery: Array Inheritance from Object.prototype
- **Event**: Discovered that JavaScript Arrays inherit numeric keys from `Object.prototype`.
- **Impact**: This means if `rows` (from `mysql2`) is empty, `rows[0]` returns the polluted value from `Object.prototype[0]`. This allows spoofing non-existent database items.
- **Relevance**: While interesting, this wasn't the primary vector for the final exploit, but it helped understand the depth of the pollution.

### 🟢 Discovery: Session Object Inheritance
- **Event**: Realized that `req.session` (when using MemoryStore and no cookie is provided) is a fresh object that inherits from `Object.prototype`.
- **Impact**: By polluting `Object.prototype.user`, `req.session.user` becomes the polluted user object for any request without a session cookie.
- **Exploit**: Polluted `Object.prototype.user` with `{ username: 'Admin', role: 'admin' }`. This allowed bypassing `requireAuth` and `hasRole` checks, effectively granting Admin access to anyone without a session.

### 🟢 Discovery: Missing Access Control in Admin Route
- **Event**: Found that `/admin/knowledge/:id` checks `item.status === 'approved'` but fails to check `item.isRestricted`.
- **Impact**: This allowed reading restricted items (which contain the flag) once Admin access was achieved.

### 🏁 Resolution
- **Action**: Chained the session pollution with the missing access control to read the flag from the restricted knowledge items.
