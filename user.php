<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['change_password'])) {
    $new_password = htmlspecialchars(strip_tags($_POST['new_password']));
    $user_id = $_SESSION['user_id'];

    if (!empty($new_password)) {
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        $query = "UPDATE users SET password = :password WHERE id = :id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':password', $hashed_password);
        $stmt->bindParam(':id', $user_id);

        if ($stmt->execute()) {
            $message = "Mot de passe modifié avec succès!";
        } else {
            $message = "Erreur lors de la modification du mot de passe.";
        }
    } else {
        $message = "Veuillez entrer un nouveau mot de passe.";
    }
}

$query_user = "SELECT * FROM users WHERE id = :id";
$stmt = $conn->prepare($query_user);
$stmt->bindParam(':id', $_SESSION['user_id']);
$stmt->execute();
$user = $stmt->fetch(PDO::FETCH_ASSOC);

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
    <title>User Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>

<body>
    <header class="bg-primary text-white text-center py-3">
        <div class="container">
            <h1>Dashboard Utilisateur - Gestion des Animaux</h1>
        </div>
    </header>
    <div class="container mt-4">
        <?php if (isset($message)) : ?>
            <div class="alert alert-info"><?= $message ?></div>
        <?php endif; ?>
        <div class="row">
            <div class="col-md-4">
                <h2>Utilisateur</h2>
                <div class="card mb-3">
                    <div class="card-body">
                        <h5 class="card-title"><?= htmlspecialchars($user['nom']) ?> <?= htmlspecialchars($user['prenom']) ?></h5>
                        <p>Email: <?= htmlspecialchars($user['email']) ?></p>
                        <form action="user.php" method="POST">
                            <div class="form-group">
                                <label for="new_password">Changer de mot de passe :</label>
                                <input type="password" name="new_password" class="form-control" required>
                            </div>
                            <button type="submit" name="change_password" class="btn btn-primary">Modifier</button>
                        </form>
                    </div>
                </div>
                <a href="logout.php" class="btn btn-danger">Déconnexion</a>
            </div>
            <div class="col-md-8">
                <h2>Animaux</h2>
                <div class="card mb-3">
                    <div class="card-body">
                        <form action="user.php" method="POST">
                            <div class="form-group">
                                <input type="hidden" name="user_id" value="<?= $_SESSION['user_id'] ?>">
                                <label for="type">Type:</label>
                                <input type="text" name="type" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label for="nom">Nom:</label>
                                <input type="text" name="nom" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label for="race">Race:</label>
                                <input type="text" name="race" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label for="alimentation">Alimentation:</label>
                                <input type="text" name="alimentation" class="form-control" required>
                            </div>
                            <div class="form-group">
                                <label for="nombre_de_repas">Nombre de repas:</label>
                                <input type="number" name="nombre_de_repas" class="form-control" required>
                            </div>
                            <button type="submit" name="add_animal" class="btn btn-primary">Ajouter</button>
                        </form>
                    </div>
                </div>
                <h3>Liste de vos animaux</h3>
                <ul class="list-group">
                    <?php foreach ($animals as $animal) : ?>
                        <li class="list-group-item">
                            <?= htmlspecialchars($animal['nom']) ?> (<?= htmlspecialchars($animal['type']) ?>) - Race: <?= htmlspecialchars($animal['race']) ?> - Alimentation: <?= htmlspecialchars($animal['alimentation']) ?> - Nombre de repas: <?= htmlspecialchars($animal['nombre_de_repas']) ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <footer class="bg-primary text-white text-center py-3 mt-4">
        <p>Dashboard Utilisateur &copy; 2023</p>
    </footer>
</body>

</html>
