<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $id = htmlspecialchars(strip_tags($_POST['id']));
    $username = htmlspecialchars(strip_tags($_POST['username']));
    $email = htmlspecialchars(strip_tags($_POST['email']));
    $role = htmlspecialchars(strip_tags($_POST['role']));

    $query = "UPDATE users SET username = :username, email = :email, role = :role WHERE id = :id";
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $id);
    $stmt->bindParam(':username', $username);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':role', $role);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Utilisateur mis à jour avec succès.";
    } else {
        $_SESSION['error'] = "Erreur lors de la mise à jour de l'utilisateur.";
    }

    header("Location: admin.php");
    exit();
}

if (isset($_GET['id'])) {
    $id = htmlspecialchars(strip_tags($_GET['id']));
    $query = "SELECT * FROM users WHERE id = :id";
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $id);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../public/css/style.css">
    <title>Modifier Utilisateur</title>
</head>

<body>
    <header>
        <div class="container">
            <h1>Modifier Utilisateur</h1>
        </div>
    </header>
    <div class="container content">
        <form action="update_user.php" method="POST">
            <input type="hidden" name="id" value="<?= htmlspecialchars($user['id']) ?>">
            <input type="text" name="username" value="<?= htmlspecialchars($user['username']) ?>" required><br>
            <input type="email" name="email" value="<?= htmlspecialchars($user['email']) ?>" required><br>
            <input type="text" name="role" value="<?= htmlspecialchars($user['role']) ?>" required><br>
            <button type="submit">Mettre à jour</button>
        </form>
    </div>
    <footer>
        <p>&copy; 2024</p>
    </footer>
</body>

</html>