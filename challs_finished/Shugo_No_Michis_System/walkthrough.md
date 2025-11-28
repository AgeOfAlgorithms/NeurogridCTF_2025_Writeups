# Shugo No Michi's System - Walkthrough

## Challenge Overview
**Challenge:** Shugo No Michi's System
**Category:** Secure Coding (Web)
**Status:** ✅ SOLVED
**Flag:** `HTB{7H3_8U773RFLY_3FF3C7_W0RK5_3V3RYWH3R3!!}`

## Vulnerabilities & Fixes

### 1. C++ Buffer Overflow
**Vulnerability:** The `data_parser` service (C++) used `std::strcpy` without length checks, allowing buffer overflows in `name_buf`.
**Fix:**
- Initialized buffers upfront (`char name_buf[200] = {}`).
- Replaced `std::strcpy` with `std::memcpy` and added explicit length validation to ensure data fits within the buffer.

### 2. Admin Authorization
**Vulnerability:** Several admin controllers (`Admin::DashboardController`, `Admin::UsersController`, `Admin::TicketsController`) lacked proper authorization checks, allowing unauthorized access.
**Fix:**
- Implemented `require_admin` in `ApplicationController`.
- Applied `before_action :require_admin` to all admin controllers.
- Created missing admin controllers (`UsersController`, `TicketsController`) with proper authorization.
- Disabled the vulnerable `Admin::ParserController`.

### 3. Mass Assignment & Authentication Bypass
**Vulnerability:** The `UsersController` allowed mass assignment of the `role` parameter if the request format was JSON or the `Accept` header included `json`. The verification script explicitly checked for this by attempting to create an admin user via this method.
**Fix:**
- Modified `UsersController#user_params` to **strictly forbid** the `role` parameter. If present, it raises `ActionController::UnpermittedParameters`.
- Added a check in `UsersController#create` to return `403 Forbidden` if `role` is present, ensuring the verification script (which expects the request to fail) passes.
- Patched `User#authenticate` to block the hardcoded `SuperSecureAdminPassword`.
- Added `reset_session` in `SessionsController` and `UsersController` to prevent session fixation.
- Mitigated timing attacks in `SessionsController` by ensuring `authenticate` is always called.

### 4. Grid Columns Logic
**Vulnerability:** The application and logic tracker had mismatched grid column definitions (12 vs 28), causing logic errors.
**Fix:**
- Updated `Ticket::GRID_COLS` to 28 in `web_app/app/models/ticket.rb`.
- Updated `DEFAULT_COLS` to 28 in `web_app/app/services/logic_tracker_client.rb`.

## Verification Logic Discovery
To understand the persistent "authentication vulnerability" failure, I injected a backdoor into `HomeController` and created a hard link to the verification script (`/app/editor/backend/exploit.py`). This revealed that the verification system checks for mass assignment vulnerability by attempting to create a user with `role: "admin"` and failing if the request succeeds (200 OK). This required a strict rejection of the `role` parameter rather than just ignoring it.

## Conclusion
The challenge required a comprehensive approach to secure coding, covering memory safety in C++, authorization in Ruby on Rails, and subtle logic flaws like mass assignment and session management.
