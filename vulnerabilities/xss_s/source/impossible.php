<?php

if (isset($_POST['btnSign'])) {
    // Check Anti-CSRF token
    checkToken($_REQUEST['user_token'], $_SESSION['session_token'], 'index.php');

    // Get input
    $message = trim($_POST['mtxMessage']);
    $name    = trim($_POST['txtName']);

    // Sanitize message + name input — HTML-encode on output, not just DB-escape
    $message = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    $name    = htmlspecialchars($name,    ENT_QUOTES, 'UTF-8');

    // Update database — PDO prepared statement, no string interpolation
    $data = $db->prepare('INSERT INTO guestbook (comment, name) VALUES (:message, :name);');
    $data->bindParam(':message', $message, PDO::PARAM_STR);
    $data->bindParam(':name',    $name,    PDO::PARAM_STR);
    $data->execute();
}

// Add a strict Content-Security-Policy so any reflected payload that slips
// through DB encoding still can't execute inline script.
header("Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self';");

// Generate Anti-CSRF token
generateSessionToken();

?>
