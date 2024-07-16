<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $id = htmlspecialchars(strip_tags($_POST['id']));
    $nom = htmlspecialchars(strip_tags($_POST['nom']));
    $type = htmlspecialchars(strip_tags($_POST['type']));
    $race = htmlspecialchars(strip_tags($_POST['race']));
    $alimentation = htmlspecialchars(strip_tags($_POST['alimentation']));
    $nombre_de_repas = htmlspecialchars(strip_tags($_POST['nombre_de_repas']));

    $query = "UPDATE animals SET nom = :nom, type = :type, race = :race, alimentation = :alimentation, nombre_de_repas = :nombre_de_repas WHERE id = :id";
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $id);
    $stmt->bindParam(':nom', $nom);
    $stmt->bindParam(':type', $type);
    $stmt->bindParam(':race', $race);
    $stmt->bindParam(':alimentation', $alimentation);
    $stmt->bindParam(':nombre_de_repas', $nombre_de_repas);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Animal mis à jour avec succès.";
    } else {
        $_SESSION['error'] = "Erreur lors de la mise à jour de l'animal.";
    }

    header("Location: admin.php");
    exit();
}

if (isset($_GET['id'])) {
    $id = htmlspecialchars(strip_tags($_GET['id']));
    $query = "SELECT * FROM animals WHERE id = :id";
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $id);
    $stmt->execute();
    $animal = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../public/css/style.css">
    <title>Modifier Animal</title>
</head>

<body>
    <header>
        <div class="container">
            <h1>Modifier Animal</h1>
        </div>
    </header>
    <div class="container content">
        <form action="update_animal.php" method="POST">
            <input type="hidden" name="id" value="<?= htmlspecialchars($animal['id']) ?>">
            <input type="text" name="nom" value="<?= htmlspecialchars($animal['nom']) ?>" required><br>
            <input type="text" name="type" value="<?= htmlspecialchars($animal['type']) ?>" required><br>
            <input type="text" name="race" value="<?= htmlspecialchars($animal['race']) ?>" required><br>
            <input type="text" name="alimentation" value="<?= htmlspecialchars($animal['alimentation']) ?>" required><br>
            <input type="number" name="nombre_de_repas" value="<?= htmlspecialchars($animal['nombre_de_repas']) ?>" required><br>
            <button type="submit">Mettre à jour</button>
        </form>
    </div>
    <footer>
        <p>&copy; 2024</p>
    </footer>
</body>

</html>