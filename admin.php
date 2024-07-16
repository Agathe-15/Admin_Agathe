<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_user'])) {
    $user_id = htmlspecialchars(strip_tags($_POST['user_id']));

    if (!empty($user_id)) {
        $query = "DELETE FROM users WHERE id = :id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':id', $user_id);

        if ($stmt->execute()) {
            $message = "Utilisateur supprimé avec succès!";
        } else {
            $message = "Erreur lors de la suppression de l'utilisateur.";
        }
    } else {
        $message = "ID de l'utilisateur non fourni.";
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_animal'])) {
    $animal_id = htmlspecialchars(strip_tags($_POST['animal_id']));

    if (!empty($animal_id)) {
        $query = "DELETE FROM animaux WHERE id = :id";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':id', $animal_id);

        if ($stmt->execute()) {
            $message = "Animal supprimé avec succès!";
        } else {
            $message = "Erreur lors de la suppression de l'animal.";
        }
    } else {
        $message = "ID de l'animal non fourni.";
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_user'])) {
    $nom = htmlspecialchars(strip_tags($_POST['nom']));
    $prenom = htmlspecialchars(strip_tags($_POST['prenom']));
    $email = htmlspecialchars(strip_tags($_POST['email']));
    $username = htmlspecialchars(strip_tags($_POST['username']));
    $password = htmlspecialchars(strip_tags($_POST['password']));
    $role = htmlspecialchars(strip_tags($_POST['role']));

    if (!empty($nom) && !empty($prenom) && !empty($email) && !empty($username) && !empty($password) && !empty($role)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $query = "INSERT INTO users (nom, prenom, email, username, password, role) VALUES (:nom, :prenom, :email, :username, :password, :role)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':nom', $nom);
        $stmt->bindParam(':prenom', $prenom);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $hashed_password);
        $stmt->bindParam(':role', $role);

        if ($stmt->execute()) {
            $message = "Utilisateur ajouté avec succès!";
        } else {
            $message = "Erreur lors de l'ajout de l'utilisateur.";
        }
    } else {
        $message = "Veuillez remplir tous les champs.";
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
    <link rel="stylesheet" href="../public/css/style.css">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>

<body>
    <header class="bg-primary text-white text-center py-3">
        <div class="container">
            <h1>Admin - Gestion des Utilisateurs et des Animaux</h1>
        </div>
    </header>
    <div class="container mt-4">
        <?php if (isset($message)) : ?>
            <div class="alert alert-info"><?= $message ?></div>
        <?php endif; ?>
        <div class="row">
            <div class="col-md-6">
                <h2>Liste des Utilisateurs</h2>
                <ul class="list-group mb-3">
                    <?php foreach ($users as $user) : ?>
                        <li class="list-group-item">
                            <?= htmlspecialchars($user['nom']) ?> <?= htmlspecialchars($user['prenom']) ?> - Email: <?= htmlspecialchars($user['email']) ?> - Role: <?= htmlspecialchars($user['role']) ?>
                            <form action="admin.php" method="POST" class="float-right">
                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                <button type="submit" name="delete_user" class="btn btn-danger btn-sm">Supprimer</button>
                            </form>
                        </li>
                    <?php endforeach; ?>
                </ul>
                <h3>Ajouter un utilisateur</h3>
                <form action="admin.php" method="POST">
                    <div class="form-group">
                        <label for="nom">Nom:</label>
                        <input type="text" name="nom" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="prenom">Prénom:</label>
                        <input type="text" name="prenom" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="username">Nom d'utilisateur:</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Mot de passe:</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="role">Rôle:</label>
                        <select name="role" class="form-control" required>
                            <option value="user">Utilisateur</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <button type="submit" name="add_user" class="btn btn-primary">Ajouter</button>
                </form>
            </div>
            <div class="col-md-6">
                <h2>Liste des Animaux</h2>
                <ul class="list-group">
                    <?php foreach ($animals as $animal) : ?>
                        <li class="list-group-item">
                            <?= htmlspecialchars($animal['nom']) ?> (<?= htmlspecialchars($animal['type']) ?>) - Race: <?= htmlspecialchars($animal['race']) ?> - Alimentation: <?= htmlspecialchars($animal['alimentation']) ?> - Nombre de repas: <?= htmlspecialchars($animal['nombre_de_repas']) ?>
                            <form action="admin.php" method="POST" class="float-right">
                                <input type="hidden" name="animal_id" value="<?= $animal['id'] ?>">
                                <button type="submit" name="delete_animal" class="btn btn-danger btn-sm">Supprimer</button>
                            </form>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    </div>
    <footer class="bg-primary text-white text-center py-3 mt-4">
        <p>Admin Panel &copy; 2023</p>
        <a href="logout.php" class="btn btn-danger">Déconnexion</a>
    </footer>
</body>

</html>
