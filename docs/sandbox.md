# Sandbox

Global Agent Bureau is an agent bureau. The same API accepts live keys and test keys. Test rows are stored apart from production rows, so a test report does not change a production score.

`GAB_ENV` is `production` or `sandbox`. Production is the default. A sandbox deployment accepts only keys whose secret starts with `gab_test_`. A production deployment accepts both.

Ask for a test key with `"environment": "test"` when the key is issued. The secret is returned once, in that response. A later list of keys shows the prefix and `environment`, not the secret. Rotating a test key issues another `gab_test_` key.

Live and test registrations of the same agent id are different records. Inquiries, reports, agreements, and scores stay inside the environment of the key that wrote them.
