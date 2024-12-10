---
id: azure_ad
title: Microsoft Azure AD
---

## Config Options

| Flag             | Toml Field     | Type   | Description                                                      | Default    |
| ---------------- | -------------- | ------ | ---------------------------------------------------------------- | ---------- |
| `--azure-tenant` | `azure_tenant` | string | go to a tenant-specific or common (tenant-independent) endpoint. | `"common"` |
| `--resource`     | `resource`     | string | The resource that is protected (Azure AD only)                   |            |

## Usage

For adding an application to the Microsoft Azure AD follow [these steps to add an application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

Take note of your `TenantId` if applicable for your situation. The `TenantId` can be used to override the default 
`common` authorization server with a tenant specific server.
