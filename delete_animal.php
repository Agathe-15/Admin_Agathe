<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user_id = htmlspecialchars(strip_tags($_POST['user_id']));

    if (!empty($user_id)) {
        $query = "DELETE FROM users WHERE id = :user_id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':user_id', $user_id);

        if ($stmt->execute()) {
            header("Location: admin.php");
            exit();
        } else {
            $_SESSION['error'] = "Erreur lors de la suppression de l'utilisateur.";
            header("Location: admin.php");
            exit();
        }
    } else {
        $_SESSION['error'] = "ID utilisateur manquant.";
        header("Location: admin.php");
        exit();
    }
}
?>
