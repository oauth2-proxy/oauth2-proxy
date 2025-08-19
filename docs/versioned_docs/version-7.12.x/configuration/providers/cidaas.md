---
id: cidaas
title: Cidaas
---

[Cidaas](https://www.cidaas.com/) is an Identity as a Service (IDaaS) solution that provides authentication and authorization services. 
It supports various protocols including OpenID Connect, OAuth 2.0, and SAML.

However, Cidaas provides groups and their roles as hierarchical claims, which are not supported by oauth2-proxy yet.
The Cidaas provider transforms the hierarchical claims into a flat list of groups, which can be used by oauth2-proxy.

Example of groups and roles in Cidaas:

```json
{
  "groups": [
    {
      "groupId": "group1",
      "roles": ["role1", "role2"]
    },
    {
      "groupId": "group2",
      "roles": ["role3"]
    }
  ]
}
```

This will be transformed into a flat list of groups:

```json
{
  "groups": ["group1:role1", "group2:role2", "group2:role3"]
}
```

Apart from that the Cidaas provider inherits all the features of the [OpenID Connect provider](openid_connect.md).