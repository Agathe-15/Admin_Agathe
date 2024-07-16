<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['delete_user'])) {
        $user_id = htmlspecialchars(strip_tags($_POST['user_id']));
        $query = "DELETE FROM users WHERE id = :user_id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
    }

    if (isset($_POST['delete_animal'])) {
        $animal_id = htmlspecialchars(strip_tags($_POST['animal_id']));
        $query = "DELETE FROM animaux WHERE id = :animal_id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':animal_id', $animal_id);
        $stmt->execute();
    }
}

try {
    $query_users = "SELECT * FROM users";
    $stmt_users = $conn->prepare($query_users);
    $stmt_users->execute();
    $users = $stmt_users->fetchAll(PDO::FETCH_ASSOC);

    $query_animals = "SELECT * FROM animaux";
    $stmt_animals = $conn->prepare($query_animals);
    $stmt_animals->execute();
    $animals = $stmt_animals->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $exception) {
    die("Query error: " . $exception->getMessage());
}
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../public/css/admin.css">
    <title>Admin Dashboard</title>
</head>

<body>
    <div class="container">
        <div class="row">
            <!-- Utilisateurs Section -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Utilisateurs</div>
                    <div class="card-body">
                        <?php foreach ($users as $user) : ?>
                            <div class="user-card">
                                <h5><?= htmlspecialchars($user['username']) ?></h5>
                                <p>Nom: <?= htmlspecialchars($user['nom']) ?></p>
                                <p>Prénom: <?= htmlspecialchars($user['prenom']) ?></p>
                                <p>Email: <?= htmlspecialchars($user['email']) ?></p>
                                <p>Rôle: <?= htmlspecialchars($user['role']) ?></p>
                                <form method="post" action="admin.php">
                                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                    <button type="submit" name="delete_user" class="btn btn-danger btn-sm">Supprimer</button>
                                </form>
                            </div>
                            <hr>
                        <?php endforeach; ?>
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
                                <form method="post" action="admin.php">
                                    <input type="hidden" name="animal_id" value="<?= $animal['id'] ?>">
                                    <button type="submit" name="delete_animal" class="btn btn-danger btn-sm">Supprimer</button>
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