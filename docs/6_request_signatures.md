---
layout: default
title: Request Signatures
permalink: /request-signatures
nav_order: 6
---

## Request signatures

If `signature_key` is defined, proxied requests will be signed with the
`GAP-Signature` header, which is a [Hash-based Message Authentication Code
(HMAC)](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
of selected request information and the request body [see `SIGNATURE_HEADERS`
in `oauthproxy.go`]({{ site.gitweb }}/oauthproxy.go).

`signature_key` must be of the form `algorithm:secretkey`, (ie: `signature_key = "sha1:secret0"`)

For more information about HMAC request signature validation, read the
following:

- [Amazon Web Services: Signing and Authenticating REST
  Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
- [rc3.org: Using HMAC to authenticate Web service
  requests](http://rc3.org/2011/12/02/using-hmac-to-authenticate-web-service-requests/)
