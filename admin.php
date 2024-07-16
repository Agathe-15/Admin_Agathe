<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_user'])) {
    $nom = htmlspecialchars(strip_tags($_POST['nom']));
    $prenom = htmlspecialchars(strip_tags($_POST['prenom']));
    $email = htmlspecialchars(strip_tags($_POST['email']));
    $username = htmlspecialchars(strip_tags($_POST['username']));
    $password = password_hash(htmlspecialchars(strip_tags($_POST['password'])), PASSWORD_DEFAULT);
    $role = htmlspecialchars(strip_tags($_POST['role']));

    if (!empty($nom) && !empty($prenom) && !empty($email) && !empty($username) && !empty($password) && !empty($role)) {
        $query = "INSERT INTO users (nom, prenom, email, username, password, role) VALUES (:nom, :prenom, :email, :username, :password, :role)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':nom', $nom);
        $stmt->bindParam(':prenom', $prenom);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
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
                        <button class="btn btn-primary" data-toggle="modal" data-target="#addUserModal">Ajouter un utilisateur</button>
                        <?php if (isset($message)) : ?>
                            <p><?= $message ?></p>
                        <?php endif; ?>
                        <ul class="list-group">
                            <?php foreach ($users as $user) : ?>
                                <li class="list-group-item">
                                    <?= htmlspecialchars($user['nom']) ?> <?= htmlspecialchars($user['prenom']) ?> - <?= htmlspecialchars($user['email']) ?> - <?= htmlspecialchars($user['username']) ?> - <?= htmlspecialchars($user['role']) ?>
                                    <form action="admin.php" method="POST" class="float-right">
                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                        <button type="submit" name="delete_user" class="btn btn-danger btn-sm">Supprimer</button>
                                    </form>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Animaux Section -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Animaux</div>
                    <div class="card-body">
                        <ul class="list-group">
                            <?php foreach ($animals as $animal) : ?>
                                <li class="list-group-item">
                                    <?= htmlspecialchars($animal['nom']) ?> (<?= htmlspecialchars($animal['type']) ?>)
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
        </div>
        <a href="logout.php" class="btn btn-secondary mt-3">Déconnexion</a>
    </div>

    <!-- Modal Ajouter un Utilisateur -->
    <div class="modal fade" id="addUserModal" tabindex="-1" role="dialog" aria-labelledby="addUserModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addUserModalLabel">Ajouter un Utilisateur</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <form action="admin.php" method="POST">
                        <div class="form-group">
                            <label for="nom">Nom</label>
                            <input type="text" name="nom" id="nom" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="prenom">Prénom</label>
                            <input type="text" name="prenom" id="prenom" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="email">Email</label>
                            <input type="email" name="email" id="email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="username">Nom d'utilisateur</label>
                            <input type="text" name="username" id="username" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Mot de passe</label>
                            <input type="password" name="password" id="password" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="role">Rôle</label>
                            <select name="role" id="role" class="form-control" required>
                                <option value="user">Utilisateur</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <button type="submit" name="add_user" class="btn btn-primary">Ajouter</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.min.js"></script>
</body>

</html>
