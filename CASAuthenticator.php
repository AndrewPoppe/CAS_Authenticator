<?php

namespace YaleREDCap\CASAuthenticator;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */
class CASAuthenticator extends \ExternalModules\AbstractExternalModule
{

    public function redcap_every_page_before_render($project_id = null)
    {
        $page = defined('PAGE') ? PAGE : null;
        if ( empty($page) ) {
            return;
        }

        // Already logged in
        if ((defined('USERID') && defined('USERID') !== '') || $this->framework->isAuthenticated()) {
            return;
        }

        // url to redirect to after login
        $redirect = $this->curPageURL();
     
        // Only authenticate if we're asked to (but include the login page HTML if we're not logged in)
        parse_str($_SERVER['QUERY_STRING'], $query);
        if ( !isset($query['CAS_auth']) ) {
            return;
        }

        try {
           $initialized = $this->initializeCas();
            if ( $initialized === false ) {
                $this->framework->log('CAS Authenticator: Error initializing CAS');
                throw new \Exception('Error initializing CAS');
            }

        
            $this->framework->log('CAS Authenticator: Attempting to authenticate');
            $userid = $this->authenticate();
            if ( $userid === false ) {
                $this->framework->log('CAS Authenticator: Auth Failed', [
                    "page"       => $page
                ]);
                $this->exitAfterHook();
                return;
            }

            // Successful authentication
            $this->framework->log('CAS Authenticator: Auth Succeeded', [
                "CASAuthenticator_NetId" => $userid,
                "page"                   => $page
            ]);

            // strip the "CAS_auth" parameter from the URL
            $redirectStripped = $this->stripQueryParameter($redirect, 'CAS_auth');

            // Trigger login
            \Authentication::autoLogin($userid);
            
            // Update last login timestamp
            \Authentication::setUserLastLoginTimestamp($userid);
            
            // Log the login
            \Logging::logPageView("LOGIN_SUCCESS", $userid);
            
            // Redirect to the page we were on
            $this->framework->redirectAfterHook($redirectStripped);
            return;
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('CAS Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
                \phpCAS::logout();
                $this->exitAfterHook();
                return;
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error', [ 'error' => $e->getMessage() ]);
            \phpCAS::logout();
            $this->exitAfterHook();
            return;
        } finally {
            

            // $isTableUser = \Authentication::isTableUser($userid);
            // if ( !$isTableUser ) {
            //     $this->framework->log('CAS Authenticator: User not in table', [
            //         "CASAuthenticator_NetId" => $userid,
            //         "page"                   => $page
            //     ]);
            //     // // Get random value for temporary password
            //     // $pass = generateRandomHash(24);
            //     // $password_salt = \Authentication::generatePasswordSalt();
            //     // $hashed_password = \Authentication::hashPassword($pass, $password_salt);
            //     // // Add to table
            //     // $sql = "INSERT INTO redcap_auth (username, password, password_salt, temp_pwd)
            //     //         VALUES ('" . db_escape($userid) . "', '" . db_escape($hashed_password) . "', '" . db_escape($password_salt) . "', 0)";
            //     // $q = db_query($sql);

                
                
            //     //echo "You do not currently have an account in this REDCap Server.";
            //     // global $lang;
            //     // \System::$userJustLoggedIn = true;
            //     // $_POST['username'] = $userid;
            //     // $_SESSION['username'] = $userid;
            //     // \phpCAS::forceAuthentication();
            //     // var_dump(\phpCAS::getAttributes());
            //     // exit;
            //     // \Authentication::autoLogin($userid);
            //     // include APP_PATH_DOCROOT . "Profile/user_info.php";
            //     // $this->exitAfterHook();
            //     // return;
            // }

            
        }

    }

    public function redcap_every_page_top($project_id)
    {

        $page = defined('PAGE') ? PAGE : null;
        if ( empty($page) ) {
            return;
        }

        // If we're on the login page, inject the CAS login button
        $this->injectLoginPage($this->curPageURL());

        // If we're on the EM Manager page, add a little CSS to make the
        // setting descriptives wider in the project settings
        if ( $page === 'manager/project.php' ) {
            echo "<style>label:has(.cas-descriptive){width:100%;}</style>";
            return;
        }

        if ( $page !== 'surveys/index.php' ) {
            return;
        }

        // Note: This handles the survey condition as well, since it shares the same $page
        $initialized = $this->initializeCas();
        if ( $initialized === false ) {
            $this->casLog('CAS Authenticator: Error initializing CAS');
            $this->framework->exitAfterHook();
            return;
        }

        $dashboard_hash = filter_input(INPUT_GET, '__dashboard', FILTER_SANITIZE_STRING);
        $report_hash    = filter_input(INPUT_GET, '__report', FILTER_SANITIZE_STRING);
        $file_hash      = filter_input(INPUT_GET, '__file', FILTER_SANITIZE_STRING);

        if ( isset($dashboard_hash) ) {
            $this->handleDashboard($dashboard_hash);
        } elseif ( isset($report_hash) ) {
            $this->handleReport($report_hash);
        } elseif ( isset($file_hash) ) {
            $this->handleFile($file_hash);
        }
    }

    public function redcap_survey_page_top(
        $project_id,
        $record,
        $instrument,
        $event_id,
        $group_id,
        $survey_hash,
        $response_id,
        $repeat_instance
    ) {
        $projectSettings = $this->framework->getProjectSettings();

        foreach ( $projectSettings["survey"] as $index => $surveyName ) {

            if ( $projectSettings["event"][$index] !== null && $projectSettings["event"][$index] !== $event_id ) {
                continue;
            }

            if ( $projectSettings["survey"][$index] !== $instrument ) {
                continue;
            }

            $this->framework->log('CAS Authenticator: Handling Survey', [
                "instrument" => $instrument,
                "event_id"   => $event_id,
            ]);

            $surveyPage = filter_input(INPUT_GET, '__page__', FILTER_SANITIZE_NUMBER_INT);

            try {
                $id = $this->authenticate();
            } catch ( \CAS_GracefullTerminationException $e ) {
                if ( $e->getCode() !== 0 ) {
                    $this->framework->log('CAS Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
                }
            } catch ( \Throwable $e ) {
                $this->framework->log('CAS Authenticator: Error', [ 'error' => $e->getMessage() ]);
                $this->framework->exitAfterHook();
                return;
            } finally {
                if ( $id === false ) {
                    $this->framework->exitAfterHook();
                    return;
                }

                // Successful authentication
                if ( $surveyPage === 1 || empty($surveyPage) ) {
                    $this->casLog('CAS Authenticator: Survey Auth Succeeded', [
                        "CASAuthenticator_NetId" => $id,
                        "instrument"             => $instrument,
                        "event_id"               => $event_id,
                        "response_id"            => $response_id
                    ]);
                } else {
                    $this->framework->log('CAS Authenticator: Survey Auth Succeeded', [
                        "CASAuthenticator_NetId" => $id,
                        "instrument"             => $instrument,
                        "event_id"               => $event_id,
                        "response_id"            => $response_id,
                        "survey_page"            => $surveyPage
                    ]);
                }

                $field = $projectSettings["id-field"][$index];

                if ( $field !== null ) {
                    ?>
                    <script type='text/javascript' defer>
                        setTimeout(function () {
                            $(document).ready(function () {
                                field = $(`input[name="<?= $field ?>"]`);
                                id = "<?= $id ?>";
                                if (field.length) {
                                    field.val(id);
                                    field.closest('tr').addClass('@READONLY');
                                }
                            });
                        }, 0);
                    </script>
                    <?php
                }
                return;
            }
        }
    }

    public function redcap_module_configuration_settings($project_id, $settings)
    {
        if ( empty($project_id) ) {
            return $settings;
        }

        try {
            $surveys    = $this->getSurveys($project_id);
            $reports    = $this->getReports($project_id);
            $dashboards = $this->getDashboards($project_id);
            $files = $this->getFiles($project_id);
            $folders = $this->getFolders($project_id);

            foreach ( $settings as &$settingRow ) {
                $this->getChoices($settingRow, [
                    "surveys" => $surveys,
                    "reports" => $reports,
                    "dashboards" => $dashboards,
                    "files" => $files,
                    "folders" => $folders
                ]);

                if ( $settingRow['type'] == 'sub_settings' ) {
                    foreach ( $settingRow['sub_settings'] as &$subSettingRow ) {
                        $this->getChoices($subSettingRow, [
                            "surveys" => $surveys,
                            "reports" => $reports,
                            "dashboards" => $dashboards,
                            "files" => $files,
                            "folders" => $folders
                        ]);
                    }
                }
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error getting choices', [ 'error' => $e->getMessage() ]);
        } finally {
            return $settings;
        }
    }

    private function injectLoginPage(string $redirect) {
        ?>
        <style>
            .btn-cas {
                color: #fff;
                background-color: #00356b;
                border-color: #222222;
            }
            .btn-cas:hover {
                color: #fff;
                background-color: #286dc0;
                border-color: #286dc0;
            }
        </style>
        <script>
            $(document).ready(function () {
                if ($('#rc-login-form').length === 0) {
                    return;
                }
                $('#rc-login-form').hide();

                const loginButton = `<button class="btn btn-sm btn-cas fs15 my-2" onclick="showProgress(1);window.location.href='<?= $this->addQueryParameter($redirect, 'CAS_auth', '1')?>';"><i class="fas fa-sign-in-alt"></i> <span>Login with CAS</span></button>`;
                const orText = '<span class="text-secondary mx-3 my-2 nowrap">-- <?=\RCView::tt('global_46')?> --</span>';
                const loginChoiceSpan = $('span[data-rc-lang="global_257"]');
                if (loginChoiceSpan.length > 0) {
                    const firstButton = loginChoiceSpan.closest('div').find('button').eq(0);
                    firstButton.before(loginButton);
                    firstButton.before(orText);
                } else {
                    const loginDiv = `<div class="my-4 fs14">
                        <div class="mb-4"><?=\RCView::tt('global_253')?></div>
                        <div>
                            <span class="text-secondary my-2 me-3"><?=\RCView::tt('global_257')?></span>
                            ${loginButton}
                            ${orText}
                            <button class="btn btn-sm btn-rcgreen fs15 my-2" onclick="$('#rc-login-form').toggle();"><i class="fas fa-sign-in-alt"></i> <?=\RCView::tt('global_258')?></button>
                        </div>
                    </div>`;
                    $('#rc-login-form').before(loginDiv);
                }
            });
        </script>
        <?php
    }

    private function curPageURL() {
        $pageURL = 'http';
        if(isset($_SERVER["HTTPS"]))
        if ($_SERVER["HTTPS"] == "on") {
            $pageURL .= "s";
        }
        $pageURL .= "://";
        if ($_SERVER["SERVER_PORT"] != "80") {
            $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
        } else {
            $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
        }
        return $pageURL;
    }

    private function stripQueryParameter($url, $param) {
        $parsed = parse_url($url);
        $baseUrl = strtok($url, '?');
        if (isset($parsed['query'])) {
            parse_str($parsed['query'], $params);
            unset($params[$param]);
            $parsed = http_build_query($params);
        }
        return $baseUrl . (empty($parsed) ? '' : '?') . $parsed;
    }

    private function addQueryParameter(string $url, string $param, string $value = '') {
        $parsed = parse_url($url);
        $baseUrl = strtok($url, '?');
        if (isset($parsed['query'])) {
            parse_str($parsed['query'], $params);
            $params[$param] = $value;
            $parsed = http_build_query($params);
        } else {
            $parsed = http_build_query([$param => $value]);
        }
        return $baseUrl . (empty($parsed) ? '' : '?') . $parsed;
    }

    private function getChoices(&$row, $data)
    {
        if ( $row['key'] == 'survey' ) {
            $row['choices'] = $data['surveys'];
        } elseif ( $row['key'] == 'dashboard' ) {
            $row['choices'] = $data['dashboards'];
        } elseif ( $row['key'] == 'report' ) {
            $row['choices'] = $data['reports'];
        } elseif ($row['key'] == 'file' ) {
            $row['choices'] = $data['files'];
        } elseif ($row['key'] == 'folder' ) {
            $row['choices'] = $data['folders'];
        }
    }

    private function handleLogout()
    {
        if (isset($_GET['logout']) && $_GET['logout']) {
            \phpCAS::logout();
        }
    }

    private function handleDashboard($dashboard_hash)
    {
        $projectSettings = $this->framework->getProjectSettings();
        $dashboard       = $this->getDashboardFromHash($dashboard_hash);
        if ( $dashboard === null ) {
            $this->framework->log('CAS Authenticator: Dashboard not found', [ 'dashboard_hash' => $dashboard_hash ]);
            return;
        }
        foreach ( $projectSettings["dashboard"] as $thisDashId ) {

            if ( $dashboard['dash_id'] != $thisDashId ) {
                continue;
            }
            $this->framework->log('CAS Authenticator: Handling Dashboard', [
                "dashboard_hash" => $dashboard_hash,
                "dashboard_id"   => $dashboard['dash_id'],
                "dashboard"      => $dashboard['title']
            ]);

            try {
                $id = $this->authenticate();
            } catch ( \CAS_GracefullTerminationException $e ) {
                if ( $e->getCode() !== 0 ) {
                    $this->framework->log('CAS Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
                }
            } catch ( \Throwable $e ) {
                $this->framework->log('CAS Authenticator: Error', [ 'error' => $e->getMessage() ]);
                $this->framework->exitAfterHook();
            } finally {
                if ( $id === false ) {
                    $this->framework->exitAfterHook();
                    return;
                }

                // Successful authentication
                $this->casLog('CAS Authenticator: Dashboard Auth Succeeded', [
                    "CASAuthenticator_NetId" => $id,
                    "dashboard_hash"         => $dashboard_hash,
                    "dashboard_id"           => $dashboard['dash_id'],
                    "dashboard"              => $dashboard['title']
                ]);
            }
        }
    }

    private function handleReport($report_hash)
    {
        $projectSettings = $this->framework->getProjectSettings();

        $report = $this->getReportFromHash($report_hash);
        if ( $report === null ) {
            $this->framework->log('CAS Authenticator: Report not found', [ 'report_hash' => $report_hash ]);
            return;
        }

        foreach ( $projectSettings["report"] as $thisReportId ) {

            if ( $report['report_id'] != $thisReportId ) {
                continue;
            }

            $this->framework->log('CAS Authenticator: Handling Report', [
                "report_hash" => $report_hash,
                "report_id"   => $report['report_id'],
                "report"      => $report['title']
            ]);

            try {
                $id = $this->authenticate();
            } catch ( \CAS_GracefullTerminationException $e ) {
                if ( $e->getCode() !== 0 ) {
                    $this->framework->log('CAS Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
                }
            } catch ( \Throwable $e ) {
                $this->framework->log('CAS Authenticator: Error', [ 'error' => $e->getMessage() ]);
                $this->framework->exitAfterHook();
            } finally {
                if ( $id === false ) {
                    $this->framework->exitAfterHook();
                    return;
                }

                // Successful authentication
                $this->casLog('CAS Authenticator: Report Auth Succeeded', [
                    "CASAuthenticator_NetId" => $id,
                    "report_hash"            => $report_hash,
                    "report_id"              => $report['report_id'],
                    "report"                 => $report['title']
                ]);
            }
        }
    }

    private function handleFile ($file_hash) {
        $projectSettings = $this->framework->getProjectSettings();

        $file = $this->getFileFromHash($file_hash);
        
        if ( $file === null ) {
            $this->framework->log('CAS Authenticator: File not found', [ 'file_hash' => $file_hash ]);
            return;
        }

        // First check if this file individually should be CAS'd
        $matched = false;
        foreach ( $projectSettings["file"] as $thisDocsId ) {
            if ($file['docs_id'] == $thisDocsId) {
                $matched = true;
                break;
            }
        }

        // Check if the file is in a folder that should be CAS'd
        if ($matched === false && $file['folder_id'] !== null) {
            foreach ($projectSettings['folder'] as $thisFolderId) {
                $allFolderIds = $this->getAllFolderIds($file['folder_id']);
                if (in_array($thisFolderId, $allFolderIds)) {
                    $matched = true;
                    break;
                }
            }
        }

        if ($matched === false) {
            return;
        }

        try {
            $id = $this->authenticate();
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('CAS Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
            }
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error', [ 'error' => $e->getMessage() ]);
            $this->framework->exitAfterHook();
        } finally {
            if ( $id === false ) {
                $this->framework->exitAfterHook();
                return;
            }

            // Successful authentication
            $this->casLog('CAS Authenticator: File Auth Succeeded', [
                "CASAuthenticator_NetId" => $id,
                "file_hash"            => $file_hash,
                "docs_id"              => $file['docs_id'],
                "filename"                 => $file['docs_name']
            ]);
        }
    }

    private function getFileFromHash($hash) {
        $sql = "SELECT rds.docs_id, rdff.folder_id, rd.docs_name
                FROM redcap_docs_share rds
                LEFT JOIN redcap_docs_folders_files rdff 
                ON rds.docs_id = rdff.docs_id
                LEFT JOIN redcap_docs rd
                ON rds.docs_id = rd.docs_id
                WHERE rds.hash = ?";
        $result = $this->framework->query($sql, [ $hash ]);
        return $this->framework->escape($result->fetch_assoc());
    }


    /**
     * Get all parent folder IDs for a given folder ID (including self)
     * @param mixed $folder_id
     * @return array folder IDs
     */
    private function getAllFolderIds($folder_id) {
        if (empty($folder_id)) {
            return [];
        }
        $folders = [$folder_id];
        $nextFolderId = $this->getParentFolderId($folder_id);
        while ($nextFolderId !== null) {
            $folders[] = $nextFolderId;
            $nextFolderId = $this->getParentFolderId($nextFolderId);
        }
        return $folders;
    }

    private function getParentFolderId($folder_id) {
        if (empty($folder_id)) {
            return null;
        }
        $sql = "SELECT parent_folder_id
                FROM redcap_docs_folders
                WHERE folder_id = ?";
        $result = $this->framework->query($sql, [ $folder_id ]);
        $row = $result->fetch_assoc();
        if (empty($row)) {
            return null;
        }
        return $row['parent_folder_id'];
    }

    private function getDashboardFromHash($dashboard_hash)
    {
        $project_id = $this->framework->getProjectId();
        $sql        = 'SELECT dash_id, title, hash FROM redcap_project_dashboards WHERE hash = ? AND project_id = ?';
        $result     = $this->framework->query($sql, [ $dashboard_hash, $project_id ]);
        return $this->framework->escape($result->fetch_assoc());
    }

    private function getReportFromHash($report_hash)
    {
        $project_id = $this->framework->getProjectId();
        $sql        = 'SELECT report_id, title, hash FROM redcap_reports WHERE hash = ? AND project_id = ?';
        $result     = $this->query($sql, [ $report_hash, $project_id ]);
        return $this->framework->escape($result->fetch_assoc());
    }

    private function getSurveys($pid)
    {
        $forms = [];
        $surveys = [];

        $formsSql = "SELECT DISTINCT form_name
                    FROM redcap_metadata
                    WHERE project_id = ?
                    ORDER BY form_name";
        $formsResult = $this->framework->query($formsSql, [ $pid ]);
        while ($formsRow = $formsResult->fetch_assoc()) {
            $forms[] = $formsRow['form_name'];
        }

        $surveysSql    = "SELECT form_name
                    FROM redcap_surveys
                    WHERE project_id = ?
                    ORDER BY form_name";
        $surveysResult = self::query($surveysSql, [ $pid ]);

        while ( $surveysRow = $surveysResult->fetch_assoc() ) {
            if ( !in_array($surveysRow['form_name'], $forms) ) {
                continue;
            }
            $surveysRow       = static::escape($surveysRow);
            $surveys[] = [ 'value' => $surveysRow['form_name'], 'name' => strip_tags(nl2br($surveysRow['form_name'])) ];
        }
        return $surveys;
    }

    private function getDashboards($pid)
    {
        $dashboards = [];

        $sql = "SELECT dash_id, title
                FROM redcap_project_dashboards
                WHERE project_id = ?
                AND is_public = 1
                ORDER BY dash_id";

        $result = self::query($sql, [ $pid ]);

        while ( $row = $result->fetch_assoc() ) {
            $row          = static::escape($row);
            $dashboards[] = [ 'value' => $row['dash_id'], 'name' => strip_tags(nl2br($row['title'])) ];
        }
        return $dashboards;
    }

    private function getReports($pid)
    {
        $reports = [];
        $sql     = "SELECT report_id,title
                FROM redcap_reports
                WHERE project_id = ?
                AND is_public = 1
                ORDER BY report_id";
        $result  = self::query($sql, [ $pid ]);

        while ( $row = $result->fetch_assoc() ) {
            $row       = static::escape($row);
            $reports[] = [ 'value' => $row['report_id'], 'name' => strip_tags(nl2br($row['title'])) ];
        }
        return $reports;
    }

    private function getFiles($pid) {
        $files = [];
        $sql = "SELECT docs_id, docs_name
                FROM redcap_docs
                WHERE project_id = ?";
        $result = $this->framework->query($sql, [ $pid ]);
        while ( $row = $result->fetch_assoc() ) {
            $row       = $this->framework->escape($row);
            $files[] = [ 'value' => $row['docs_id'], 'name' => strip_tags(nl2br($row['docs_name'])) ];
        }
        return $files;
    }

    private function getFolders($pid) {
        $folders = [];
        $sql = "SELECT folder_id, name
                FROM redcap_docs_folders
                WHERE project_id = ?";
        $result = $this->framework->query($sql, [ $pid ]);
        while ( $row = $result->fetch_assoc() ) {
            $row       = $this->framework->escape($row);
            $folders[] = [ 'value' => $row['folder_id'], 'name' => strip_tags(nl2br($row['name'])) ];
        }
        return $folders;
    }

    private function initializeCas()
    {
        try {

            require_once __DIR__ . '/vendor/apereo/phpcas/CAS.php';

            $cas_host                = $this->getSystemSetting("cas-host");
            $cas_context             = $this->getSystemSetting("cas-context");
            $cas_port                = (int) $this->getSystemSetting("cas-port");
            $cas_server_ca_cert_id   = $this->getSystemSetting("cas-server-ca-cert-pem");
            $cas_server_ca_cert_path = empty($cas_server_ca_cert_id) ? $this->getSafePath('cacert.pem') : $this->getFile($cas_server_ca_cert_id);
            $server_force_https      = $this->getSystemSetting("server-force-https");
            $service_base_url        = (SSL ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'];//APP_PATH_WEBROOT_FULL;

            // Enable https fix
            if ( $server_force_https == 1 ) {
                $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
                $_SERVER['HTTP_X_FORWARDED_PORT']  = 443;
                $_SERVER['HTTPS']                  = 'on';
                $_SERVER['SERVER_PORT']            = 443;
            }

            // Initialize phpCAS
            \phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, $service_base_url, false);

            // Set the CA certificate that is the issuer of the cert
            // on the CAS server
            \phpCAS::setCasServerCACert($cas_server_ca_cert_path);

            // Don't exit, let me handle instead
            \CAS_GracefullTerminationException::throwInsteadOfExiting();
            return true;
        } catch ( \Throwable $e ) {
            $this->log('CAS Authenticator: Error initializing CAS', [ 'error' => $e->getMessage() ]);
            return false;
        }
    }

    /**
     * Initiate CAS authentication
     * 
     * 
     * @return string|boolean username of authenticated user (false if not authenticated)
     */
    private function authenticate()
    {
        try {
            // force CAS authentication
            \phpCAS::forceAuthentication();

            // Return authenticated username
            return \phpCAS::getUser();
        } catch ( \CAS_GracefullTerminationException $e ) {
            if ( $e->getCode() !== 0 ) {
                $this->framework->log('CAS Authenticator: Error getting code', [ 'error' => $e->getMessage() ]);
            }
            return false;
        } catch ( \Throwable $e ) {
            $this->framework->log('CAS Authenticator: Error authenticating', [ 'error' => json_encode($e, JSON_PRETTY_PRINT) ]);
            return false;
        }
    }


    /**
     * Get url to file with provided edoc ID.
     * 
     * @param string $edocId ID of the file to find
     * 
     * @return string path to file in edoc folder
     */
    private function getFile(string $edocId)
    {
        $filePath = "";
        if ( $edocId === null ) {
            return $filePath;
        }
        $result   = $this->query('SELECT stored_name FROM redcap_edocs_metadata WHERE doc_id = ?', $edocId);
        $filename = $result->fetch_assoc()["stored_name"];
        if ( defined('EDOC_PATH') ) {
            $filePath = $this->framework->getSafePath(EDOC_PATH . $filename, EDOC_PATH);
        }
        return $filePath;
    }

    /**
     * Make sure settings meet certain conditions.
     * 
     * This is called when a user clicks "Save" in either system or project
     * configuration.
     * 
     * @param mixed $settings Array of settings user is trying to set
     * 
     * @return string|null if not null, the error message to show to user
     */
    public function validateSettings($settings)
    {

        if ( empty($this->framework->getProjectId()) ) {
            return;
        }

        // project-level settings
        if ( count($settings["survey"]) > 0 ) {
            foreach ( $settings["survey"] as $i => $form ) {
                if ( empty($form) ) {
                    continue;
                }
                $id_field   = $settings["id-field"][$i];
                $project_id = $this->getProjectId();

                // form must be a survey
                $surveyResult = $this->query(
                    'SELECT survey_id FROM redcap_surveys
                    WHERE project_id = ?
                    AND form_name = ?',
                    [ $project_id, $form ]
                );
                if ( $surveyResult->num_rows < 1 ) {
                    return "The selected form ($form) is not enabled as a survey.";
                }

                if ( !$id_field ) {
                    continue;
                }

                // id_field must be a text input on that survey
                $fieldResult = $this->query(
                    'SELECT element_type FROM redcap_metadata
                    WHERE project_id = ?
                    AND form_name = ?
                    AND field_name = ?',
                    [ $project_id, $form, $id_field ]
                );
                if ( $fieldResult->num_rows < 1 ) {
                    return "The selected id field ($id_field) is not on the selected survey ($form).";
                }
                $row = $fieldResult->fetch_assoc();
                if ( $row["element_type"] !== "text" ) {
                    return "The selected id field ($id_field) is not a text input field.";
                }
            }
        }
    }

    private function casLog($message, $params = [], $record = null, $event = null)
    {
        $doProjectLogging = $this->getProjectSetting('logging');
        if ( $doProjectLogging ) {
            $changes = "";
            foreach ( $params as $label => $value ) {
                $changes .= $label . ": " . $value . "\n";
            }
            \REDCap::logEvent(
                $message,
                $changes,
                null,
                $record,
                $event
            );
        }
        $this->framework->log($message, $params);
    }
}