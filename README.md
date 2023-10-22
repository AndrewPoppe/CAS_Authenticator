# CAS Authenticator

This REDCap External Module enables the integration of CAS authentication in any survey, public report, or public dashboard.

## Installation

Install by downloading the latest release zip and unzipping in the modules directory of your REDCap's web server or by downloading directly from the REDCap REPO.

## Configuration

#### System configuration: 

- **CAS Host**: Full Hostname of your CAS Server (e.g., `secure.its.yale.edu`)
- **CAS Context**: Context of the CAS Server (e.g., `/cas`)
- **CAS Port**: Port of your CAS server (e.g., `443`)
- **CAS Server CA Cert File**: The PEM file containing your CAS server's cert (e.g., [cacert.pem](https://curl.se/docs/caextract.html))
- **HTTPS Override**: Check this if you experience the CAS server redirecting to http despite your REDCap server using https protocol.
- 
#### Project configuration:

- **Enable logging**: Check this to enable logging of CAS authentication events in the project's logging module
- **Survey subsettings** (repeatable)
  - **Event**: The specific event in which the CAS authentication should be enabled (leave blank to apply to all events)
  - **Survey**: The survey instrument CAS should be integrated with
  - **ID Field**: Optional. This allows the EM to store the username of the person who authenticated. It should be a text field on the survey defined above
- **Report**: The public report CAS should be integrated with (repeatable)
- **Dashboard**: The public dashboard CAS should be integrated with (repeatable)
