---
id: arcgis
title: Arcgis
---

The Arcgis provider allows you to authenticate users on [ArcGIS Online](https://www.arcgis.com/) or on your premises [Portal for ArcGIS](https://enterprise.arcgis.com/en/portal/).
When you are using the ArcGIS provider to authenticate user on your on premises Portal for ArcGIS, you must specify the urls via configuration, environment variable, or command line argument. Depending on your Portal for ArcGIS instance your urls may be of the form `/webcontext/sharing/rest/*`.

Refer to the [OAuth2 documentation](https://developers.arcgis.com/documentation/security-and-authentication/app-authentication/tutorials/create-oauth-credentials-app-auth/) to set up the client id and client secret. Your "Redirection URI" will be `https://internalapp.yourcompany.com/oauth2/callback`.

Additionally, all the groups id a user belongs to are set as part of the X-Forwarded-Groups header. e.g. 15b7fa70521e409083d445dfbe62844a,30300c6e207f4fdd8c5b06bb7ef006ab,8d0d64cc4d054aefb55648c0783a740f. Note that groups ids are stored as names are not unique (cf. [ESRI Support](https://support.esri.com/en-us/bug/it-is-possible-to-have-two-groups-with-the-same-name-in-bug-000128049)).


Example of configuration for ArcGIS Online:
```
    -provider arcgis
    -provider-display-name="ArcGIS Online"
    -client-id <from arcgis admin>
    -client-secret <from arcgis admin>
```

Example of configuration for Portal for ArcGIS with URL https://gis.company.com/geoportail:
```
    -provider arcgis
    -provider-display-name="Geoportail"
    -client-id <from arcgis admin>
    -client-secret <from arcgis admin>
    -login-url="https://gis.company.com/geoportail/sharing/rest/oauth2/authorize"
    -redeem-url="https://gis.company.com/geoportail/sharing/rest/oauth2/token"
    -validate-url="https://gis.company.com/geoportail/sharing/rest/community/self"
```

