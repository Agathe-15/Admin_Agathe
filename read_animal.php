<?php
include_once 'config.php';

$query = "SELECT * FROM animaux";
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
            "user_id" => $user_id,
            "nom" => $nom,
            "type" => $type,
            "race" => $race,
            "alimentation" => $alimentation,
            "nombre_de_repas" => $nombre_de_repas
        );
        array_push($animaux_arr["records"], $animal_item);
    }

    echo json_encode($animaux_arr);
} else {
    echo json_encode(array("message" => "Aucun animal trouvé."));
}
