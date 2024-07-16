<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $animal_id = htmlspecialchars(strip_tags($_POST['animal_id']));

    if (!empty($animal_id)) {
        $query = "DELETE FROM animaux WHERE id = :animal_id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':animal_id', $animal_id);

        if ($stmt->execute()) {
            header("Location: admin.php");
            exit();
        } else {
            $_SESSION['error'] = "Erreur lors de la suppression de l'animal.";
            header("Location: admin.php");
            exit();
        }
    } else {
        $_SESSION['error'] = "ID animal manquant.";
        header("Location: admin.php");
        exit();
    }
}
?>
