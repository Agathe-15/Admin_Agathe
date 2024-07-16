<?php
header('Content-Type: application/json');
include_once 'config.php';

try {
    // Essayez de vous connecter à la base de données
    $conn = new PDO("mysql:host=$host;dbname=$db_name", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo json_encode(["status" => "success", "message" => "Connection successful!"]);
} catch (PDOException $exception) {
    echo json_encode(["status" => "error", "message" => "Connection error: " . $exception->getMessage()]);
}
