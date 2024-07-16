<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_animal'])) {
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
            $message = "Animal ajouté avec succès!";
        } else {
            $message = "Erreur lors de l'ajout de l'animal.";
        }
    } else {
        $message = "Veuillez remplir tous les champs.";
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
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../public/css/user.css">
    <title>User Dashboard</title>
</head>

<body>
    <div class="container">
        <div class="row">
            <!-- Utilisateur Section -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Utilisateur</div>
                    <div class="card-body">
                        <h5><?= htmlspecialchars($_SESSION['username']) ?></h5>
                        <p>Nom: <?= htmlspecialchars($_SESSION['nom']) ?></p>
                        <p>Prénom: <?= htmlspecialchars($_SESSION['prenom']) ?></p>
                        <p>Email: <?= htmlspecialchars($_SESSION['email']) ?></p>
                        <form method="post" action="change_password.php">
                            <div class="form-group">
                                <label for="password">Changer de mot de passe:</label>
                                <input type="password" name="password" id="password" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Modifier</button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Animaux Section -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Animaux</div>
                    <div class="card-body">
                        <?php foreach ($animals as $animal) : ?>
                            <div class="animal-card">
                                <h5><?= htmlspecialchars($animal['nom']) ?></h5>
                                <p>Type: <?= htmlspecialchars($animal['type']) ?></p>
                                <p>Race: <?= htmlspecialchars($animal['race']) ?></p>
                                <p>Alimentation: <?= htmlspecialchars($animal['alimentation']) ?></p>
                                <p>Nombre de repas: <?= htmlspecialchars($animal['nombre_de_repas']) ?></p>
                                <form method="post" action="delete_animal.php">
                                    <input type="hidden" name="animal_id" value="<?= $animal['id'] ?>">
                                    <button type="submit" class="btn btn-danger btn-sm">Supprimer</button>
                                </form>
                            </div>
                            <hr>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="logout">
        <form action="logout.php" method="post">
            <button type="submit" class="btn btn-secondary">Déconnexion</button>
        </form>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>

</html>