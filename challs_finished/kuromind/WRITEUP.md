# Kuromind Challenge Writeup

## Vulnerabilities

The challenge contained a chain of vulnerabilities leading to authentication bypass and information disclosure.

1.  **Prototype Pollution in `deepMerge`**:
    The `deepMerge` function in `app/utils/merge.js` was vulnerable to prototype pollution. It did not sanitize keys like `__proto__`, allowing an attacker to modify `Object.prototype`. This was exploitable via the `/user/edit/:id` endpoint.

2.  **Session Object Inheritance**:
    The application used `express-session` with the default `MemoryStore`. When a request is made without a session cookie, `req.session` is initialized as a new object. In JavaScript, plain objects inherit from `Object.prototype`. Therefore, polluting `Object.prototype` allows injecting properties into `req.session`.

3.  **Authentication Bypass**:
    The `requireAuth` middleware checks `if (!req.session.user)`. If `Object.prototype.user` is polluted, `req.session.user` becomes defined, bypassing this check.
    The `hasRole` function checks the database for a user matching `req.session.user.username` and the required role. By polluting `Object.prototype.user` with `{ username: 'Admin', role: 'admin' }`, the application queries for the legitimate Admin user and confirms the role, granting full admin privileges.

4.  **Missing Access Control in Admin Route**:
    The `/admin/knowledge/:id` route checks if an item is `approved`, but unlike the user route, it **fails to check if the item is `restricted`**. This allows an admin (or an impersonated admin) to view restricted items, which contained the flag.

## Exploitation Steps

1.  **Register and Login**: Create a regular user account to access the `/user/edit/:id` endpoint.
2.  **Create a Draft**: Create a draft knowledge item to have a valid ID to edit.
3.  **Pollute `Object.prototype`**:
    Send a POST request to `/user/edit/<draft_id>` with the following payload in the `tags` field:
    ```json
    {
      "__proto__": {
        "user": {
          "username": "Admin",
          "role": "admin"
        }
      }
    }
    ```
    This pollutes `Object.prototype.user` globally in the Node.js process.
4.  **Bypass Authentication**:
    Send a GET request to `/admin/knowledge/<id>` (where ID is 10-15) **without** a session cookie.
    - The application creates a fresh `req.session`.
    - `req.session.user` inherits the polluted admin user object.
    - `requireAuth` passes.
    - `hasRole('admin')` passes because the database confirms 'Admin' has the 'admin' role.
5.  **Retrieve Flag**:
    The admin view renders the restricted item, revealing the flag in the description.

## Flag

`HTB{d03s_4i_r34lly_m4st3r_0f_ch41nin6_mult1pl3_vuln3r4b1lity_310345ff2b7a4c3acc39a16e31c86821}`
