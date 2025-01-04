<?php
/*
Plugin Name: Autenticación JWT
Description: Plugin para autenticar usuarios usando JWT en la API REST de WordPress.
Version: 1.1
Author: Sergio Bernabé
*/

// Hook para inicializar el plugin
add_action('rest_api_init', 'mi_jwt_authenticate');

function mi_jwt_authenticate() {
    register_rest_route('mi-jwt/v1', '/token', array(
        'methods' => 'POST',
        'callback' => 'mi_jwt_generate_token',
        'permission_callback' => '__return_true',
    ));
}

// Generación del Token JWT
function mi_jwt_generate_token(WP_REST_Request $request) {
    $credentials = json_decode($request->get_body(), true);

    if (isset($credentials['username']) && isset($credentials['password'])) {
        $user = wp_authenticate($credentials['username'], $credentials['password']);

        if (is_wp_error($user)) {
            return new WP_Error('authentication_failed', 'Credenciales incorrectas', array('status' => 403));
        }

        // Obtener el nombre y apellido del usuario
        $first_name = get_user_meta($user->ID, 'first_name', true);
        $last_name = get_user_meta($user->ID, 'last_name', true);


        // Crear el payload del token
        $issued_at = time();
        $expiration_time = $issued_at + 3600; // Token expira en 1 hora

        $payload = array(
            'iss' => get_bloginfo('url'),
            'iat' => $issued_at,
            'exp' => $expiration_time,
            'usuario' => array(
                'id' => $user->ID,
                'user' => $user->user_login,
                'email' => $user->user_email, // Agregar el correo electrónico
                'nombre' => $first_name, // Agregar el nombre
                'apellidos' => $last_name, // Agregar los apellidos
            ),
        );

        // Crear el token usando la librería JWT
        $jwt_secret = 'tu_clave_secreta'; // Cambia esto a una clave secreta segura
        $token = mi_jwt_encode($payload, $jwt_secret);

        // Devuelve el token junto con el nombre de usuario, correo e ID
        return rest_ensure_response(array(
            'token' => $token,
            'usuario' => array(
                'id' => $user->ID,
                'user' => $user->user_login,
                'email' => $user->user_email, // Agregar el correo electrónico
                'nombre' => $first_name, // Agregar el nombre
                'apellidos' => $last_name, // Agregar los apellidos
            ),
        ));
    }

    return new WP_Error('missing_credentials', 'Credenciales no proporcionadas', array('status' => 400));
}

// Función para codificar el JWT
function mi_jwt_encode($payload, $key) {
    $header = json_encode(array('typ' => 'JWT', 'alg' => 'HS256'));
    $payload = json_encode($payload);
    
    $base64_url_header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64_url_payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    $signature = hash_hmac('sha256', "$base64_url_header.$base64_url_payload", $key, true);
    $base64_url_signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

    return "$base64_url_header.$base64_url_payload.$base64_url_signature";
}
