<?php

namespace YaleREDCap\CASLogin;

/**
 * Main EM class
 * 
 * @author Andrew Poppe
 */
class CASLogin extends \ExternalModules\AbstractExternalModule {


    function redcap_survey_page_top($project_id, $record, $instrument, 
    $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        
        $projectSettings = $this->getProjectSettings();
        
        $index = array_search($instrument, $projectSettings["survey"], true);
        
        if ($index !== FALSE) {
            $id = $this->authenticate();
            $field = $projectSettings["id-field"][$index];
            
            if ($field !== NULL) {
                ?>
                <script type='text/javascript' defer>
                    setTimeout(function() {
                        console.log("<?=$field?>");
                        field = $(`input[name="<?=$field?>"]`);
                        if (field.length) {
                            field.val("<?=$id?>");
                            field.closest('tr').addClass('@READONLY');
                        }
                    }, 0);
                </script>
                <?php    
            }
            
        }
        
    }

    function authenticate() {
        require_once __DIR__ . '/vendor/jasig/phpcas/CAS.php';
        
        $cas_host = $this->getSystemSetting("cas-host");
        $cas_context = $this->getSystemSetting("cas-context");
        $cas_port = (int) $this->getSystemSetting("cas-port");
        $cas_server_ca_cert_id = $this->getSystemSetting("cas-server-ca-cert-pem");
        $cas_server_ca_cert_path = $this->getFile($cas_server_ca_cert_id);
        
        // Initialize phpCAS
        \phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context);

        // Set the CA certificate that is the issuer of the cert
        // on the CAS server
        \phpCAS::setCasServerCACert($cas_server_ca_cert_path);

        // force CAS authentication
        \phpCAS::forceAuthentication();

        return \phpCAS::getUser();
    }

    /**
     * Get url to file with provided edoc ID.
     * 
     * @param string $edocId ID of the file to find
     * 
     * @return string path to file in edoc folder
     */
    private function getFile(string $edocId) {
        if ($edocId === NULL) {
            return "";
        }
        $result = $this->query('SELECT stored_name FROM redcap_edocs_metadata WHERE doc_id = ?', $edocId);
        $filename = $result->fetch_assoc()["stored_name"];
        return EDOC_PATH . $filename;
    }
}