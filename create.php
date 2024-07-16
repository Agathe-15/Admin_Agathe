<?php
include_once 'config.php';

$data = json_decode(file_get_contents("php://input"));

if (!empty($data->nom) && !empty($data->type)) {
    $query = "INSERT INTO animaux (type, nom, alimentation, proprietaire) VALUES (:type, :nom, :alimentation, :proprietaire)";
    $stmt = $conn->prepare($query);

    // nettoyer les données
    $type = htmlspecialchars(strip_tags($data->type));
    $nom = htmlspecialchars(strip_tags($data->nom));
    $alimentation = htmlspecialchars(strip_tags($data->alimentation));
    $proprietaire = htmlspecialchars(strip_tags($data->proprietaire));

    $stmt->bindParam(':type', $type);
    $stmt->bindParam(':nom', $nom);
    $stmt->bindParam(':alimentation', $alimentation);
    $stmt->bindParam(':proprietaire', $proprietaire);

    if ($stmt->execute()) {
        echo json_encode(array("message" => "L'animal a été ajouté."));
    } else {
        echo json_encode(array("message" => "Erreur lors de l'ajout de l'animal."));
    }
} else {
    echo json_encode(array("message" => "Les données sont incomplètes."));
}
