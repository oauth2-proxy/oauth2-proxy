---
id: logging
title: Logging
---

By default, OAuth2 Proxy logs all output to stdout. Logging can be configured to output to a rotating log file using the `--logging-filename` command.

If you are logging to a file instead of stdout. You can also configure the maximum file size (`--logging-max-size`), age (`--logging-max-age`), max backup logs (`--logging-max-backups`), and if backup logs should be compressed (`--logging-compress`).

There are three different types of logging: standard, authentication, and HTTP requests. These can be enabled or disabled with `--standard-logging`, `--auth-logging`, and `--request-logging` respectively.

Each type of logging has its own configurable format and variables. By default, these formats are similar to the Apache Combined Log.

Logging of requests to the `/ping` endpoint (or using `--ping-user-agent`) and the `/ready` endpoint can be disabled with `--silence-ping-logging` reducing log volume.

### Auth Log Format
Authentication logs are logs which are guaranteed to contain a username or email address of a user attempting to authenticate. These logs are output by default in the below format:

```
<REMOTE_ADDRESS> - <REQUEST ID> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] [<STATUS>] <MESSAGE>
```

The status block will contain one of the below strings:

- `AuthSuccess` If the user has authenticated successfully
- `AuthFailure` If the user failed to authenticate explicitly
- `AuthError` If there was an unexpected error during authentication

If you require a different format than that, you can configure it with the `--auth-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}
```

Available variables for auth logging:

| Variable | Example | Description |
| --- | --- | --- |
| Client | 74.125.224.72 | The client/remote IP address. Will use the X-Real-IP header it if exists & reverse-proxy is set to true. |
| Host  | domain.com | The value of the Host header. |
| Message | Authenticated via OAuth2 | The details of the auth attempt. |
| Protocol | HTTP/1.0 | The request protocol. |
| RequestID | 00010203-0405-4607-8809-0a0b0c0d0e0f | The request ID pulled from the `--request-id-header`. Random UUID if empty |
| RequestMethod | GET | The request method. |
| Timestamp | 19/Mar/2015:17:20:19 -0400 | The date and time of the logging event. |
| UserAgent | - | The full user agent as reported by the requesting client. |
| Username | username@email.com | The email or username of the auth request. |
| Status | AuthSuccess | The status of the auth request. See above for details. |

### Request Log Format
HTTP request logs will output by default in the below format:

```
<REMOTE_ADDRESS> - <REQUEST ID> - <user@domain.com> [19/Mar/2015:17:20:19 -0400] <HOST_HEADER> GET <UPSTREAM_HOST> "/path/" HTTP/1.1 "<USER_AGENT>" <RESPONSE_CODE> <RESPONSE_BYTES> <REQUEST_DURATION>
```

If you require a different format than that, you can configure it with the `--request-logging-format` flag.
The default format is configured as follows:

```
{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}
```

Available variables for request logging:

| Variable | Example | Description |
| --- | --- | --- |
| Client | 74.125.224.72 | The client/remote IP address. Will use the X-Real-IP header it if exists & reverse-proxy is set to true. |
| Host  | domain.com | The value of the Host header. |
| Protocol | HTTP/1.0 | The request protocol. |
| RequestDuration | 0.001 | The time in seconds that a request took to process. |
| RequestID | 00010203-0405-4607-8809-0a0b0c0d0e0f | The request ID pulled from the `--request-id-header`. Random UUID if empty |
| RequestMethod | GET | The request method. |
| RequestURI | "/oauth2/auth" | The URI path of the request. |
| ResponseSize | 12 | The size in bytes of the response. |
| StatusCode | 200 | The HTTP status code of the response. |
| Timestamp | 19/Mar/2015:17:20:19 -0400 | The date and time of the logging event. |
| Upstream | - | The upstream data of the HTTP request. |
| UserAgent | - | The full user agent as reported by the requesting client. |
| Username | username@email.com | The email or username of the auth request. |

### Standard Log Format
All other logging that is not covered by the two types mentioned above. Will be using the following standard logging format. This includes configuration information at startup and errors that occur outside of a session:

```
[19/Mar/2015:17:20:19 -0400] [main.go:40] <MESSAGE>
```

If you require a different format than that, you can configure it with the `--standard-logging-format` flag. By default the format is configured as follows:

```
[{{.Timestamp}}] [{{.File}}] {{.Message}}
```

Available variables for standard logging:

| Variable | Example | Description |
| --- | --- | --- |
| Timestamp | 19/Mar/2015:17:20:19 -0400 | The date and time of the logging event. |
| File | main.go:40 | The file and line number of the logging statement. |
| Message | HTTP: listening on 127.0.0.1:4180 | The details of the log statement. |