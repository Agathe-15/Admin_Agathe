<?php
$host = 'localhost';
$db_name = 'monProjetDB';
$username = 'Agathe';
$password = 'root'; // Remplacez par le mot de passe correct

try {
    $conn = new PDO("mysql:host=$host;dbname=$db_name", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "Connection successful!";
} catch (PDOException $exception) {
    die("Connection error: " . $exception->getMessage());
}
