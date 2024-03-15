<?php

namespace YaleREDCap\CASAuthenticator;

/** @var CASAuthenticator $module */

$initialized = $module->initializeCas();
if ( $initialized === false ) {
    $module->framework->log('CAS Login E-Signature: Error initializing CAS');
    throw new \Exception('Error initializing CAS');
}
$userid = $module->renewAuthentication();
$module->log('ok', ['userid' => $userid]);

if ( $userid === false ) {
    $module->framework->log('CAS Login E-Signature: Error authenticating user');
    throw new \Exception('Error authenticating user');
}

$user = $module->framework->getUser();
$username = $user->getUsername();
if (strtolower(trim($username)) !== strtolower(trim($userid))) {
    $module->framework->log('CAS Login E-Signature: Usernames do not match');
    throw new \Exception('Usernames do not match');
}
$code = $module->createCode();
$module->setCode($userid, $code);

?>
<script>
    alert('<?= $userid ?>');
    window.opener.postMessage({username: '<?= $userid ?>', code: '<?=$code?>'}, '*');
    window.close();
</script>