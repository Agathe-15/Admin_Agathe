<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $id = htmlspecialchars(strip_tags($_POST['id']));

    $query = "DELETE FROM users WHERE id = :id";
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Utilisateur supprimé avec succès.";
    } else {
        $_SESSION['error'] = "Erreur lors de la suppression de l'utilisateur.";
    }

    header("Location: admin.php");
    exit();
}
