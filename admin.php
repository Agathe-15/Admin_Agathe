<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
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
    <link rel="stylesheet" href="../public/css/style.css">
    <title>Admin Dashboard</title>
</head>

<body>
    <header>
        <div class="container">
            <h1>Admin - Gestion des Utilisateurs et des Animaux</h1>
        </div>
    </header>
    <div class="container content">
        <div>
            <h2>Liste des Utilisateurs</h2>
            <ul>
                <?php foreach ($users as $user) : ?>
                    <li><?= htmlspecialchars($user['username']) ?> - Email: <?= htmlspecialchars($user['email']) ?> - Role: <?= htmlspecialchars($user['role']) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
        <div>
            <h2>Liste des Animaux</h2>
            <ul>
                <?php foreach ($animals as $animal) : ?>
                    <li><?= htmlspecialchars($animal['nom']) ?> (<?= htmlspecialchars($animal['type']) ?>) - Race: <?= htmlspecialchars($animal['race']) ?> - Alimentation: <?= htmlspecialchars($animal['alimentation']) ?> - Nombre de repas: <?= htmlspecialchars($animal['nombre_de_repas']) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <footer>
        <p>Admin Panel &copy; 2023</p>
    </footer>
</body>

</html>