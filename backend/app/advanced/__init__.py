"""Advanced authorized bug-hunting modules.

Every module here is authorized-only and safe-by-design:

* Only explicitly authorized scope is ever touched.
* Only explicitly authorized test accounts are used (never brute force or real
  user credentials).
* Modules that send requests are heavily rate/size limited and never bulk
  download. State-changing tests are not executed automatically — they produce
  manual-approval checklists instead.
* All risky results default to ``needs_review`` with redacted evidence.
* Every action is audit logged.
"""
