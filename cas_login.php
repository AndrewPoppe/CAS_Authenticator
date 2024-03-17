<?php

namespace YaleREDCap\CASAuthenticator;

/** @var CASAuthenticator $module */
try {
    $module->initializeCas();
    parse_str($_SERVER['QUERY_STRING'], $query);
    if (!isset($query['cas_authed'])) {
        $module->renewAuthentication();
    }
    \phpCAS::forceAuthentication();
    $userid = \phpCAS::getUser();

    if ( !$userid ) {
        $module->framework->log('CAS Login E-Signature: Error authenticating user');
        exit;
    }

    $user     = $module->framework->getUser();
    $username = $user->getUsername();
    if ( strtolower(trim($username)) !== strtolower(trim($userid)) ) {
        $module->framework->log('CAS Login E-Signature: Usernames do not match');
        throw new \Exception('Usernames do not match');
    }
    $code = $module->createCode();
    $module->setCode($userid, $code);
    ?>
    <script>
        window.opener.postMessage({ username: '<?= $userid ?>', code: '<?= $code ?>' }, '*');
        window.close();
    </script>
    <?php
} catch ( \Exception $e ) {
    $module->log('error', [ 'message' => $e->getMessage() ]);
}