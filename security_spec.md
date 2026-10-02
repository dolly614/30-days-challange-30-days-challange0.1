# Security Specification — Uyanix 30 Days Challenge (AUTH-01 & AUTH-02)

## 1. Data Invariants
1. **Identity & Ownership**: A user profile `/users/{userId}` can only be created or updated by `request.auth.uid == userId` (with `email_verified == true`) or a verified Admin.
2. **No Self-Assigned Roles**: When creating `/users/{userId}`, `role` MUST be `'student'` and `idVerified` MUST be `false` unless the request is performed by `isAdmin()`. Users cannot escalate their `role` or `idVerified` fields on update.
3. **Teacher Role & Approval Isolation**: A user creating `/teachers/{teacherId}` can only create a record with `status == 'pending'` and `balance == 0`. Only `isAdmin()` can update teacher status (`approved` / `rejected`) or modify `balance`.
4. **PII Isolation**: Sensitive fields (`email`, `phone`) are isolated in `/users/{userId}/private/{infoId}` and readable strictly by `isOwner(userId)` or `isAdmin()`.
5. **Terminal State Locking**: `/examAttempts/{attemptId}` with `status == 'completed'` cannot be modified by students after submission.
6. **Query Enforcer**: Every `allow list` rule enforces ownership (`resource.data.uid == request.auth.uid`) or `isAdmin()`.

## 2. The "Dirty Dozen" Payloads
1. **Role Escalation on Create**: `{ uid: "u1", role: "admin", idVerified: true }` -> Rejected (`role == 'student'` enforced for non-admins).
2. **Role Escalation on Update**: `{ role: "admin" }` by student -> Rejected (`affectedKeys().hasOnly(['name', 'classNum', 'school', 'city', 'updatedAt'])`).
3. **Teacher Self-Approval Attack**: `{ uid: "u1", code: "TEACH1", status: "approved", balance: 5000 }` by non-admin -> Rejected (`status == 'pending' && balance == 0` enforced).
4. **Shadow Field Injection**: `{ uid: "u1", name: "A", isSuperAdmin: true }` -> Rejected (`keys().hasOnly(...)`).
5. **Cross-User Profile Hijack**: User `u2` writing to `/users/u1` -> Rejected (`isOwner(userId)` check).
6. **Unverified Admin Email Spoof**: User with `email == 'dollysingh1268@gmail.com'` and `email_verified == false` -> Rejected (`request.auth.token.email_verified == true` required).
7. **PII Scraping**: User `u2` reading `/users/u1/private/info` -> Rejected (`isOwner(userId) || isAdmin()`).
8. **ID Poisoning**: Creating document with 2000-byte ID or special characters -> Rejected (`isValidId(id)`).
9. **Value Poisoning**: Updating `name` to a 50KB string -> Rejected (`data.name.size() <= 100`).
10. **Timestamp Forgery**: Setting `createdAt` to a past/future timestamp -> Rejected (`incoming().createdAt == request.time`).
11. **Immutable Field Mutation**: Changing `uid` or `createdAt` during update -> Rejected (`incoming().uid == existing().uid && incoming().createdAt == existing().createdAt`).
12. **Terminal Exam Attempt Tampering**: Student updating score on `/examAttempts/{attemptId}` after `status == 'completed'` -> Rejected.
