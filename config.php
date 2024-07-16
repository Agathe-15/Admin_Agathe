<?php
$host = 'localhost';
$db_name = 'AdminAgathe';
$username = 'Agathe';
$password = 'root'; // Remplacez par le mot de passe correct

try {
    $conn = new PDO("mysql:host=$host;dbname=$db_name", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    error_log("Connection successful to database '$db_name'"); // Log de succès de connexion
} catch (PDOException $exception) {
    error_log("Connection error: " . $exception->getMessage()); // Log d'erreur de connexion
    die("Connection error: " . $exception->getMessage());
}
