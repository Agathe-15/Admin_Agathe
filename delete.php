<?php
include_once 'config.php';

$data = json_decode(file_get_contents("php://input"));

if (!empty($data->id)) {
    $query = "DELETE FROM animaux WHERE id = :id";

    $stmt = $conn->prepare($query);

    // Nettoyage des données
    $id = htmlspecialchars(strip_tags($data->id));

    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        echo json_encode(array("message" => "L'animal a été supprimé."));
    } else {
        echo json_encode(array("message" => "Erreur lors de la suppression de l'animal."));
    }
} else {
    echo json_encode(array("message" => "Identifiant non fourni."));
}
