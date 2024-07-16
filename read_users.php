<?php
include_once 'config.php';

$query = "SELECT id, type, nom, alimentation, proprietaire FROM animaux";
$stmt = $conn->prepare($query);
$stmt->execute();

$num = $stmt->rowCount();

if ($num > 0) {
    $animaux_arr = array();
    $animaux_arr["records"] = array();

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        extract($row);
        $animal_item = array(
            "id" => $id,
            "type" => $type,
            "nom" => $nom,
            "alimentation" => $alimentation,
            "proprietaire" => $proprietaire
        );

        array_push($animaux_arr["records"], $animal_item);
    }

    echo json_encode($animaux_arr);
} else {
    echo json_encode(array("message" => "Aucun animal trouvé."));
}
