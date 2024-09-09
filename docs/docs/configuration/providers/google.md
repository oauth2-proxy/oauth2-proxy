---
id: google
title: Google (default)
---

## Config Options

| Flag                                           | Toml Field                                   | Type   | Description                                                                                      | Default                                            |
| ---------------------------------------------- | -------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| `--google-admin-email`                         | `google_admin_email`                         | string | the google admin to impersonate for api calls                                                    |                                                    |
| `--google-group`                               | `google_groups`                              | string | restrict logins to members of this google group (may be given multiple times).                   |                                                    |
| `--google-service-account-json`                | `google_service_account_json`                | string | the path to the service account json credentials                                                 |                                                    |
| `--google-use-application-default-credentials` | `google_use_application_default_credentials` | bool   | use application default credentials instead of service account json (i.e. GKE Workload Identity) |                                                    |
| `--google-target-principal`                    | `google_target_principal`                    | bool   | the target principal to impersonate when using ADC                                               | defaults to the service account configured for ADC |

## Usage

For Google, the registration steps are:

1.  Create a new project: https://console.developers.google.com/project
2.  Choose the new project from the top right project dropdown (only if another project is selected)
3.  In the project Dashboard center pane, choose **"APIs & Services"**
4.  In the left Nav pane, choose **"Credentials"**
5.  In the center pane, choose **"OAuth consent screen"** tab. Fill in **"Product name shown to users"** and hit save.
6.  In the center pane, choose **"Credentials"** tab.
    - Open the **"New credentials"** drop down
    - Choose **"OAuth client ID"**
    - Choose **"Web application"**
    - Application name is freeform, choose something appropriate
    - Authorized JavaScript origins is your domain ex: `https://internal.yourcompany.com`
    - Authorized redirect URIs is the location of oauth2/callback ex: `https://internal.yourcompany.com/oauth2/callback`
    - Choose **"Create"**
7.  Take note of the **Client ID** and **Client Secret**

It's recommended to refresh sessions on a short interval (1h) with `cookie-refresh` setting which validates that the 
account is still authorized.

#### Restrict auth to specific Google groups on your domain. (optional)

1.  Create a [service account](https://developers.google.com/identity/protocols/OAuth2ServiceAccount) and configure it 
    to use [Application Default Credentials / Workload Identity / Workload Identity Federation (recommended)](#using-application-default-credentials-adc--workload-identity--workload-identity-federation-recommended) or, 
    alternatively download the JSON.
2.  Make note of the Client ID for a future step.
3.  Under "APIs & Auth", choose APIs.
4.  Click on Admin SDK and then Enable API.
5.  Follow the steps on https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account 
    and give the client id from step 2 the following oauth scopes:

    ```
    https://www.googleapis.com/auth/admin.directory.group.readonly
    https://www.googleapis.com/auth/admin.directory.user.readonly
    ```

6.  Follow the steps on https://support.google.com/a/answer/60757 to enable Admin API access.
7.  Create or choose an existing administrative email address on the Gmail domain to assign to the `google-admin-email` 
    flag. This email will be impersonated by this client to make calls to the Admin SDK. See the note on the link from 
    step 5 for the reason why.
8.  Create or choose an existing email group and set that email to the `google-group` flag. You can pass multiple instances 
    of this flag with different groups and the user will be checked against all the provided groups.

(Only if using a JSON file (see step 1))
9.  Lock down the permissions on the json file downloaded from step 1 so only oauth2-proxy is able to read the file and 
    set the path to the file in the `google-service-account-json` flag.
10. Restart oauth2-proxy.

Note: The user is checked against the group members list on initial authentication and every time the token is 
refreshed ( about once an hour ).

##### Using Application Default Credentials (ADC) / Workload Identity / Workload Identity Federation (recommended)
oauth2-proxy can make use of [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials).
When deployed within GCP, this means that it can automatically use the service account attached to the resource. When deployed to GKE, ADC
can be leveraged through a feature called Workload Identity. Follow Google's [guide](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
to set up Workload Identity.

When deployed outside of GCP, [Workload Identity Federation](https://cloud.google.com/docs/authentication/provide-credentials-adc#wlif) might be an option.
