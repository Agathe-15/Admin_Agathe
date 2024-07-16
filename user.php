<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['add_animal'])) {
        $user_id = $_SESSION['user_id'];
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
                $message = "Animal ajouté avec succès!";
            } else {
                $message = "Erreur lors de l'ajout de l'animal.";
            }
        } else {
            $message = "Veuillez remplir tous les champs.";
        }
    } elseif (isset($_POST['update_animal'])) {
        $animal_id = htmlspecialchars(strip_tags($_POST['animal_id']));
        $nom = htmlspecialchars(strip_tags($_POST['nom']));
        $type = htmlspecialchars(strip_tags($_POST['type']));
        $race = htmlspecialchars(strip_tags($_POST['race']));
        $alimentation = htmlspecialchars(strip_tags($_POST['alimentation']));
        $nombre_de_repas = htmlspecialchars(strip_tags($_POST['nombre_de_repas']));

        if (!empty($animal_id) && !empty($nom) && !empty($type) && !empty($race) && !empty($alimentation) && !empty($nombre_de_repas)) {
            $query = "UPDATE animaux SET nom = :nom, type = :type, race = :race, alimentation = :alimentation, nombre_de_repas = :nombre_de_repas WHERE id = :animal_id AND user_id = :user_id";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':animal_id', $animal_id);
            $stmt->bindParam(':nom', $nom);
            $stmt->bindParam(':type', $type);
            $stmt->bindParam(':race', $race);
            $stmt->bindParam(':alimentation', $alimentation);
            $stmt->bindParam(':nombre_de_repas', $nombre_de_repas);
            $stmt->bindParam(':user_id', $_SESSION['user_id']);

            if ($stmt->execute()) {
                $message = "Animal mis à jour avec succès!";
            } else {
                $message = "Erreur lors de la mise à jour de l'animal.";
            }
        } else {
            $message = "Veuillez remplir tous les champs.";
        }
    }
}

$query_animals = "SELECT * FROM animaux WHERE user_id = :user_id";
$stmt = $conn->prepare($query_animals);
$stmt->bindParam(':user_id', $_SESSION['user_id']);
$stmt->execute();
$animals = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../public/css/style.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <title>User Dashboard</title>
</head>

<body>
    <header>
        <div class="container">
            <h1>Dashboard Utilisateur - Gestion des Animaux</h1>
        </div>
    </header>
    <div class="container content">
        <?php if (isset($message)) : ?>
            <p><?= $message ?></p>
        <?php endif; ?>
        <?php if (isset($_GET['message'])) : ?>
            <p><?= htmlspecialchars($_GET['message']) ?></p>
        <?php endif; ?>
        <div>
            <h2>Ajouter un animal</h2>
            <form action="user.php" method="POST">
                <input type="hidden" name="user_id" value="<?= $_SESSION['user_id'] ?>">
                <input type="text" name="type" placeholder="Type" required><br>
                <input type="text" name="nom" placeholder="Nom" required><br>
                <input type="text" name="race" placeholder="Race" required><br>
                <input type="text" name="alimentation" placeholder="Alimentation" required><br>
                <input type="number" name="nombre_de_repas" placeholder="Nombre de repas" required><br>
                <button type="submit" name="add_animal">Ajouter</button>
            </form>
        </div>
        <div>
            <h2>Liste de vos animaux</h2>
            <ul>
                <?php foreach ($animals as $animal) : ?>
                    <li>
                        <form action="user.php" method="POST">
                            <input type="hidden" name="animal_id" value="<?= htmlspecialchars($animal['id']) ?>">
                            Nom : <input type="text" name="nom" value="<?= htmlspecialchars($animal['nom']) ?>"><br>
                            Type : <input type="text" name="type" value="<?= htmlspecialchars($animal['type']) ?>"><br>
                            Race : <input type="text" name="race" value="<?= htmlspecialchars($animal['race']) ?>"><br>
                            Alimentation : <input type="text" name="alimentation" value="<?= htmlspecialchars($animal['alimentation']) ?>"><br>
                            Nombre de repas : <input type="number" name="nombre_de_repas" value="<?= htmlspecialchars($animal['nombre_de_repas']) ?>"><br>
                            <button type="submit" name="update_animal">Mettre à jour</button>
                        </form>
                        <form action="../api/delete_animal.php" method="POST">
                            <input type="hidden" name="id" value="<?= htmlspecialchars($animal['id']) ?>">
                            <button type="submit" name="delete_animal">Supprimer</button>
                        </form>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <footer>
        <p>Dashboard Utilisateur &copy; 2023</p>
    </footer>
</body>

</html>
