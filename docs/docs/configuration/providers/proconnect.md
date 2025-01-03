---
id: proconnect
title: ProConnect
---

ProConnect is an OIDC provider for the French Government.
If you are a French government agency, you can contact the ProConnect team through the contact information
that you can find on https://www.proconnect.gouv.fr/ and work with them to understand how to get ProConnect
accounts for integration/test and production access.

An integration guide is available here: https://github.com/numerique-gouv/proconnect-documentation, though this proxy handles everything but the data you need to create to register your application in ProConnect.

As a demo, we will assume that you are running your application that you want to secure locally on
http://localhost:3000/, that you will be starting your proxy up on http://localhost:4180/, and that
you have an agency integration account for testing.

First, register your application in ProConnect.

- Return to App URL: Make this be `http://localhost:4180/`
- Redirect URIs: Make this be `http://localhost:4180/oauth2/callback`.
- Attribute Bundle: Make sure that email is selected.

Now start the proxy up with the following options:

```
./oauth2-proxy -provider proconnect \
  -client-id=YOUR_PROCONNECT_CLIENT_ID \
  -client-secret=YOUR_PROCONNECT_CLIENT_SECRET \
  -redirect-url=http://localhost:4180/oauth2/callback \
  -oidc-issuer-url=https://fca.integ01.dev-agentconnect.fr/api/v2 \
  -cookie-secure=false \
  -upstream=http://localhost:3000/ \
  -cookie-secret=somerandomstring12341234567890AB \
  -cookie-domain=localhost \
  -skip-provider-button=true \
  -prompt=login \
  -skip_claims_from_profile_url=true
```

Once it is running, you should be able to go to `http://localhost:4180/` in your browser,
get authenticated by the ProConnect integration server, and then get proxied on to your
application running on `http://localhost:3000/`. In a real deployment, you would secure
your application with a firewall or something so that it was only accessible from the
proxy, and you would use real hostnames everywhere.
