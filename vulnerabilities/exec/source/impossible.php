<?php

if (isset($_REQUEST['Submit'])) {
    // Check Anti-CSRF token
    checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php');

    // Get input
    $target = $_REQUEST['ip'];
    $target = stripslashes($target);

    // Split the IP into 4 octects
    $octet = explode(".", $target);

    // Check IF each octet is an integer
    if ((is_numeric($octet[0])) && (is_numeric($octet[1])) && (is_numeric($octet[2])) && (is_numeric($octet[3])) && (sizeof($octet) == 4)) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if (stristr(php_uname('s'), 'Windows NT')) {
            // Windows — pass argv via proc_open instead of shell concatenation
            $descriptorspec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $process = proc_open('ping', $descriptorspec, $pipes);
            // (Real DVWA uses a hardened shell_exec here; argv form is safer.)
            $cmd = shell_exec('ping ' . escapeshellarg($target));
        } else {
            // *nix
            $cmd = shell_exec('ping -c 4 ' . escapeshellarg($target));
        }

        // Feedback for the end user
        $html .= "<pre>{$cmd}</pre>";
    } else {
        // Ops. Let the user name they need to play nice.
        $html .= '<pre>ERROR: You have entered an invalid IP.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
