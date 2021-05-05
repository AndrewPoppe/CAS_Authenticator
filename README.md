# CAS Survey Login

This REDCap External Module enables the integration of CAS authentication in any survey.

## Installation

Install by downloading the latest release zip and unzipping in the modules directory of your REDCap's web server or by downloading directly from the REDCap REPO.

## Configuration

#### System configuration: 

- **CAS Host**: Full Hostname of your CAS Server (e.g., `secure.its.yale.edu`)
- **CAS Context**: Context of the CAS Server (e.g., `/cas`)
- **CAS Port**: Port of your CAS server (e.g., `443`)
- **CAS Server CA Cert File**: The PEM file containing your CAS server's cert (e.g., `secure-its-yale-edu.pem`)

#### Project configuration:

- **Survey subsettings** (repeatable)
    - **Survey**: The survey instrument CAS should be integrated with
    - **ID Field**: Optional. This allows the EM to store the username of the person who authenticated. It should be a text field on the survey defined above
