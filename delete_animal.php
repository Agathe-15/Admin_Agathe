<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['animal_id'])) {
    $animal_id = htmlspecialchars(strip_tags($_POST['animal_id']));

    if (!empty($animal_id)) {
        $query = "DELETE FROM animaux WHERE id = :id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':id', $animal_id);

        if ($stmt->execute()) {
            header("Location: admin.php?message=Animal supprimé avec succès!");
        } else {
            header("Location: admin.php?message=Erreur lors de la suppression de l'animal.");
        }
    } else {
        header("Location: admin.php?message=ID de l'animal non fourni.");
    }
} else {
    header("Location: admin.php?message=Requête invalide.");
}
exit();
