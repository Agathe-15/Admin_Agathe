<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $id = htmlspecialchars(strip_tags($_POST['id']));

    $query = "DELETE FROM animals WHERE id = :id";
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Animal supprimé avec succès.";
    } else {
        $_SESSION['error'] = "Erreur lors de la suppression de l'animal.";
    }

    header("Location: admin.php");
    exit();
}
