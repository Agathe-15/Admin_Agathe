<?php
include_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $user_id = htmlspecialchars(strip_tags($_POST['user_id']));
    $nom = htmlspecialchars(strip_tags($_POST['nom']));
    $type = htmlspecialchars(strip_tags($_POST['type']));
    $race = htmlspecialchars(strip_tags($_POST['race']));
    $alimentation = htmlspecialchars(strip_tags($_POST['alimentation']));
    $nombre_de_repas = htmlspecialchars(strip_tags($_POST['nombre_de_repas']));

    if (!empty($user_id) && !empty($nom) && !empty($type) && !empty($race) && !empty($alimentation) && !empty($nombre_de_repas)) {
        $query = "INSERT INTO animaux (user_id, nom, type, race, alimentation, nombre_de_repas) VALUES (:user_id, :nom, :type, :race, :alimentation, :nombre_de_repas)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->bindParam(':nom', $nom);
        $stmt->bindParam(':type', $type);
        $stmt->bindParam(':race', $race);
        $stmt->bindParam(':alimentation', $alimentation);
        $stmt->bindParam(':nombre_de_repas', $nombre_de_repas);

        if ($stmt->execute()) {
            header("Location: ../views/user.php");
            exit();
        } else {
            $_SESSION['error'] = "Erreur lors de l'ajout de l'animal.";
        }
    } else {
        $_SESSION['error'] = "Veuillez remplir tous les champs.";
    }
}

header("Location: ../views/user.php");
exit();
