---
id: allowed_groups
title: Allowing group based access
---

Limiting access to a resource based on the users group membership gives you a finer level of access control.  
You will need an oauth provider that supports adding the `group` claim in the `id_token`.

Configured providers are :

- [Azure](#azure-auth-provider)

### Azure Auth Provider

In azure, you can configure additional claims for a service principal in general as described here
[https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims).

The `groups` claim is a bit special, as its value comes from an existing value for the user and not a single static value 
[https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-group-claims](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-group-claims)  

1. Configure the service principal to get the groups from the logged in user   
   ```bash
   az ad app update --id <sp_object_id> --set groupMembershipClaims=ApplicationGroup
   ```
   The option here are `All` where every group the user is assigned to is sent to the oauth2-proxy. 
   And then `ApplicationGroup` where only the group that is configured for the service principal and the user belongs to
   is sent.
2. Configure the service principal to send the groups from above for the logged in user in the `idToken`
   ```bash
   az ad app update --id <sp_object_id> --optional-claims @claims.json
   # claims.json context
   {
     "accessToken": [],
     "idToken": [
       {
         "name": "groups",
         "source": null,
         "essential": false,
         "additionalProperties": ["group_id"]
       }
     ],
     "saml2Token": [],
     "samlToken": null
   }
   ```

An azure example: [github azure-samples](https://github.com/Azure-Samples/active-directory-aspnetcore-webapp-openidconnect-v2/blob/master/5-WebApp-AuthZ/5-2-Groups/README.md#configure-your-application-to-receive-the-groups-claim-values-from-a-filtered-set-of-groups-a-user-may-be-assigned-to)

## Usage
Use the
 
`--allowed-group` | string \| list | restrict logins to members of this group (may be given multiple times) | |

parameter to configure the ids of the groups that should have access to this resource.

Example:  
```bash
oauth2-proxy \
--http-address=0.0.0.0:4180 \
... \
--allowed-group=<object-id-of-group-1> \
--allowed-group=<object-id-of-group-2> \
--allowed-group=<object-id-of-group-x>
```

Notes for azure:  
* You need to configure the `object_id`s.
* Depending on the value of `groupMembershipClaims` configured in your service principal, not all user groups might be
presented to the oauth2-proxy

## Configuring this for new Provider

Check the existing implementation in 
* [`azure.go`](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/providers/azure.go)
  Using the
  ```go
  EnrichSession(ctx context.Context, s *sessions.SessionState) error;
  ```
  method to extract the `groups` claim from the `id_token` returned by azure
* [`oidc.go`](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/providers/oidc.go)
  Using a separate implementation
  ```go
  createSessionState(ctx context.Context, token *oauth2.Token, idToken *oidc.IDToken) (*sessions.SessionState, error);
  ```
  called from the `Redeem` and `redeemRefreshToken` methods