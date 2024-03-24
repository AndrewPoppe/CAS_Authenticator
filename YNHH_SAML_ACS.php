<?php

session_start();  // IMPORTANT: This is required in order to be able
                  // to store the user data in the session.

require_once 'vendor/autoload.php';

$settings = [
    'strict' => true,
    'debug' => true,
    'sp' => [
        'entityId' => 'http://localhost:33810',
        'assertionConsumerService' => [
            'url' => $module->framework->getUrl('YNHH_SAML_ACS.php', true),
        ],
        'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    ],
    'idp' => [
        'entityId' => 'https://saml.example.com/entityid',
        'singleSignOnService' => [
            'url' => 'https://mocksaml.com/api/saml/sso',
        ],
        'x509cert' => '-----BEGIN CERTIFICATE-----
        MIIC4jCCAcoCCQC33wnybT5QZDANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJV
        SzEPMA0GA1UECgwGQm94eUhRMRIwEAYDVQQDDAlNb2NrIFNBTUwwIBcNMjIwMjI4
        MjE0NjM4WhgPMzAyMTA3MDEyMTQ2MzhaMDIxCzAJBgNVBAYTAlVLMQ8wDQYDVQQK
        DAZCb3h5SFExEjAQBgNVBAMMCU1vY2sgU0FNTDCCASIwDQYJKoZIhvcNAQEBBQAD
        ggEPADCCAQoCggEBALGfYettMsct1T6tVUwTudNJH5Pnb9GGnkXi9Zw/e6x45DD0
        RuRONbFlJ2T4RjAE/uG+AjXxXQ8o2SZfb9+GgmCHuTJFNgHoZ1nFVXCmb/Hg8Hpd
        4vOAGXndixaReOiq3EH5XvpMjMkJ3+8+9VYMzMZOjkgQtAqO36eAFFfNKX7dTj3V
        pwLkvz6/KFCq8OAwY+AUi4eZm5J57D31GzjHwfjH9WTeX0MyndmnNB1qV75qQR3b
        2/W5sGHRv+9AarggJkF+ptUkXoLtVA51wcfYm6hILptpde5FQC8RWY1YrswBWAEZ
        NfyrR4JeSweElNHg4NVOs4TwGjOPwWGqzTfgTlECAwEAATANBgkqhkiG9w0BAQsF
        AAOCAQEAAYRlYflSXAWoZpFfwNiCQVE5d9zZ0DPzNdWhAybXcTyMf0z5mDf6FWBW
        5Gyoi9u3EMEDnzLcJNkwJAAc39Apa4I2/tml+Jy29dk8bTyX6m93ngmCgdLh5Za4
        khuU3AM3L63g7VexCuO7kwkjh/+LqdcIXsVGO6XDfu2QOs1Xpe9zIzLpwm/RNYeX
        UjbSj5ce/jekpAw7qyVVL4xOyh8AtUW1ek3wIw1MJvEgEPt0d16oshWJpoS1OT8L
        r/22SvYEo3EmSGdTVGgk3x3s+A0qWAqTcyjr7Q4s/GKYRFfomGwz0TZ4Iw1ZN99M
        m0eo2USlSRTVl7QHRTuiuSThHpLKQQ==
        -----END CERTIFICATE-----',
    ],
];
$auth = new \OneLogin\Saml2\Auth($settings);

if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
    $requestID = $_SESSION['AuthNRequestID'];
} else {
    $requestID = null;
}

$auth->processResponse($requestID);

unset($_SESSION['AuthNRequestID']);

$errors = $auth->getErrors();

if (!empty($errors)) {
    echo '<p>', implode(', ', $errors), '</p>';
    exit();
}

if (!$auth->isAuthenticated()) {
    echo "<p>Not authenticated</p>";
    exit();
}

$_SESSION['samlUserdata'] = $auth->getAttributes();
$_SESSION['samlNameId'] = $auth->getNameId();
$_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
$_SESSION['samlNameidNameQualifier'] = $auth->getNameIdNameQualifier();
$_SESSION['samlNameidSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
$_SESSION['samlSessionIndex'] = $auth->getSessionIndex();

if (isset($_POST['RelayState']) && \OneLogin\Saml2\Utils::getSelfURL() != $_POST['RelayState']) {
    // To avoid 'Open Redirect' attacks, before execute the
    // redirection confirm the value of $_POST['RelayState'] is a // trusted URL.

    \Authentication::autoLogin($_SESSION['samlUserdata']['firstName'][0]);
    $auth->redirectTo($_POST['RelayState']);
    exit();
}

$attributes = $_SESSION['samlUserdata'];
$nameId = $_SESSION['samlNameId'];

echo '<h1>Identified user: '. htmlentities($nameId) .'</h1>';

if (!empty($attributes)) {
    echo '<h2>User attributes:</h2>';
    echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
    foreach ($attributes as $attributeName => $attributeValues) {
        echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
        foreach ($attributeValues as $attributeValue) {
            echo '<li>' . htmlentities($attributeValue) . '</li>';
        }
        echo '</ul></td></tr>';
    }
    echo '</tbody></table>';
} else {
    echo 'No attributes found.';
}