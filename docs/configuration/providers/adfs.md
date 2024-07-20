---
id: adfs
title: ADFS
---

1. Open the ADFS administration console on your Windows Server and add a new Application Group
2. Provide a name for the integration, select Server Application from the Standalone applications section and click Next
3. Follow the wizard to get the client-id, client-secret and configure the application credentials
4. Configure the proxy with

```
   --provider=adfs
   --client-id=<application ID from step 3>
   --client-secret=<value from step 3>
```

Note: When using the ADFS Auth provider with nginx and the cookie session store you may find the cookie is too large and 
doesn't get passed through correctly. Increasing the proxy_buffer_size in nginx or implementing the 
[redis session storage](../sessions.md#redis-storage) should resolve this.
