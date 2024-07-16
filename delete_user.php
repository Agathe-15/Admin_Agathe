<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['user_id'])) {
    $user_id = htmlspecialchars(strip_tags($_POST['user_id']));

    if (!empty($user_id)) {
        $query = "DELETE FROM users WHERE id = :id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':id', $user_id);

        if ($stmt->execute()) {
            header("Location: admin.php?message=Utilisateur supprimé avec succès!");
        } else {
            header("Location: admin.php?message=Erreur lors de la suppression de l'utilisateur.");
        }
    } else {
        header("Location: admin.php?message=ID de l'utilisateur non fourni.");
    }
} else {
    header("Location: admin.php?message=Requête invalide.");
}
exit();

