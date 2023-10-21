<?php

namespace YaleREDCap\CASLogin;

/**
 * @property \ExternalModules\Framework $framework
 * @see Framework
 */
class CASLogin extends \ExternalModules\AbstractExternalModule
{

    function redcap_every_page_top($project_id)
    {
        echo "<style>label:has(.cas-descriptive){width:100%;}</style>";
        if ( !defined('PAGE') || in_array(PAGE, [ 'surveys/index.php' ]) === false ) {
            return;
        }

        $dashboard_hash = filter_input(INPUT_GET, '__dashboard', FILTER_SANITIZE_STRING);
        $report_id = filter_input(INPUT_GET, 'report_id', FILTER_VALIDATE_INT);

        if (isset($dashboard_hash)) {
            $this->handleDashboard($dashboard_hash);
        } elseif (isset($report_id)) {
            $this->handleReport($report_id);
        }
    }

    function redcap_survey_page_top(
        $project_id,
        $record,
        $instrument,
        $event_id,
        $group_id,
        $survey_hash,
        $response_id,
        $repeat_instance
    ) {

        $projectSettings = $this->getProjectSettings();

        foreach ( $projectSettings["survey"] as $index => $surveyName ) {

            if ( $projectSettings["event"][$index] !== null && $projectSettings["event"][$index] !== $event_id ) {
                continue;
            }

            if ( $projectSettings["survey"][$index] !== $instrument ) {
                continue;
            }

            try {
                $id = $this->authenticate();
            } catch ( \CAS_GracefullTerminationException $e ) {
                if ( $e->getCode() !== 0 ) {
                    $this->log('error getting code', [ 'error' => $e->getMessage() ]);
                }
            } catch ( \Exception $e ) {
                $this->log('error', [ 'error' => $e->getMessage() ]);
                $this->exitAfterHook();
            } finally {
                if ( $id === FALSE ) {
                    $this->exitAfterHook();
                    return;
                }

                // Successful authentication
                $this->log('CAS Auth Succeeded', [
                    "CASLogin_NetId" => $id,
                    "instrument"     => $instrument,
                    "event_id"       => $event_id,
                    "response_id"    => $response_id
                ]);

                $field = $projectSettings["id-field"][$index];

                if ( $field !== NULL ) {
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
            }
        }
    }

    public function redcap_module_configuration_settings($project_id, $settings) {
        if (empty($project_id)) {
            return $settings;
        }

        foreach($settings as $index => $settingRow) {
            //$this->log('settingRow', [ 'settingRow' => json_encode($settingRow, JSON_PRETTY_PRINT) ]);
            if ($settingRow['key'] == 'dashboard') {
                $settingRow['choices'] = [
                    [
                        'value' => '1', 'name' => 'One'
                    ],
                    [
                        'value' => '2', 'name' => 'Two'
                    ],
                    [
                        'value' => '3', 'name' => 'Three'
                    ]
                ];
            }
            $settings[$index] = $settingRow;
        }

        return $settings;

    }

    private function handleDashboard($dashboard_hash) {
        $projectSettings = $this->getProjectSettings();
        $dashboard = $this->getDashboardFromHash($dashboard_hash);
        if ( $dashboard === null ) {
            return;
        }
        foreach ( $projectSettings["dashboard"] as $index => $thisDashId ) {

            if ( $dashboard['dash_id'] !== $thisDashId ) {
                continue;
            }

            try {
                $id = $this->authenticate();
            } catch ( \CAS_GracefullTerminationException $e ) {
                if ( $e->getCode() !== 0 ) {
                    $this->log('error getting code', [ 'error' => $e->getMessage() ]);
                }
            } catch ( \Exception $e ) {
                $this->log('error', [ 'error' => $e->getMessage() ]);
                $this->exitAfterHook();
            } finally {
                if ( $id === FALSE ) {
                    $this->exitAfterHook();
                    return;
                }

                // Successful authentication
                $this->log('CAS Auth Succeeded', [
                    "CASLogin_NetId" => $id,
                    "dashboard_hash"     => $dashboard_hash,
                    "dashboard_id"       => $dashboard['dash_id'],
                    "dashboard"    => $dashboard['title']
                ]);
            }
        }
    }

    private function getDashboardFromHash($dashboard_hash) {
        $project_id = $this->framework->getProjectId();
        $sql = 'SELECT dash_id, title, hash FROM redcap_project_dashboards WHERE hash = ? AND project_id = ?';
        $result = $this->query($sql, [$dashboard_hash, $project_id]);
        return $this->framework->escape($result->fetch_assoc());
    }

    /**
     * Initiate CAS authentication
     * 
     * 
     * @return string|boolean username of authenticated user (false if not authenticated)
     */
    function authenticate()
    {
        try {

            require_once __DIR__ . '/vendor/apereo/phpcas/CAS.php';

            $cas_host                = $this->getSystemSetting("cas-host");
            $cas_context             = $this->getSystemSetting("cas-context");
            $cas_port                = (int) $this->getSystemSetting("cas-port");
            $cas_server_ca_cert_id   = $this->getSystemSetting("cas-server-ca-cert-pem");
            $cas_server_ca_cert_path = empty($cas_server_ca_cert_id) ? $this->getSafePath('cacert.pem') : $this->getFile($cas_server_ca_cert_id);
            $server_force_https      = $this->getSystemSetting("server-force-https");
            $service_base_url        = APP_PATH_WEBROOT_FULL;

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

            // force CAS authentication
            \phpCAS::forceAuthentication();

            // Return authenticated username
            return \phpCAS::getUser();
        } catch ( \Throwable $e ) {
            $this->log('error authenticating', [ 'error' => $e->getMessage() ]);
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
        if ( $edocId === NULL ) {
            return "";
        }
        $result   = $this->query('SELECT stored_name FROM redcap_edocs_metadata WHERE doc_id = ?', $edocId);
        $filename = $result->fetch_assoc()["stored_name"];
        return EDOC_PATH . $filename;
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
    function validateSettings($settings)
    {

        // project-level settings
        if ( count($settings["survey"]) > 0 ) {
            foreach ( $settings["survey"] as $i => $form ) {
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
}