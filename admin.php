<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_user'])) {
    $username = htmlspecialchars(strip_tags($_POST['username']));
    $password = password_hash(htmlspecialchars(strip_tags($_POST['password'])), PASSWORD_DEFAULT);
    $role = htmlspecialchars(strip_tags($_POST['role']));
    $email = htmlspecialchars(strip_tags($_POST['email']));
    $nom = htmlspecialchars(strip_tags($_POST['nom']));
    $prenom = htmlspecialchars(strip_tags($_POST['prenom']));

    if (!empty($username) && !empty($password) && !empty($role) && !empty($email) && !empty($nom) && !empty($prenom)) {
        $query = "INSERT INTO users (username, password, role, email, nom, prenom) VALUES (:username, :password, :role, :email, :nom, :prenom)";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':role', $role);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':nom', $nom);
        $stmt->bindParam(':prenom', $prenom);

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
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Nom d'utilisateur</th>
                                    <th>Rôle</th>
                                    <th>Nom</th>
                                    <th>Prénom</th>
                                    <th>Email</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($users as $user) : ?>
                                    <tr>
                                        <td><?= htmlspecialchars($user['id']) ?></td>
                                        <td><?= htmlspecialchars($user['username']) ?></td>
                                        <td><?= htmlspecialchars($user['role']) ?></td>
                                        <td><?= htmlspecialchars($user['nom']) ?></td>
                                        <td><?= htmlspecialchars($user['prenom']) ?></td>
                                        <td><?= htmlspecialchars($user['email']) ?></td>
                                        <td>
                                            <button class="btn btn-warning btn-sm" data-toggle="modal" data-target="#editUserModal<?= $user['id'] ?>">Modifier</button>
                                            <form action="delete_user.php" method="POST" style="display:inline;">
                                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                <button type="submit" class="btn btn-danger btn-sm">Supprimer</button>
                                            </form>
                                        </td>
                                    </tr>

                                    <!-- Modal Modifier Utilisateur -->
                                    <div class="modal fade" id="editUserModal<?= $user['id'] ?>" tabindex="-1" role="dialog" aria-labelledby="editUserModalLabel<?= $user['id'] ?>" aria-hidden="true">
                                        <div class="modal-dialog" role="document">
                                            <div class="modal-content">
                                                <div class="modal-header">
                                                    <h5 class="modal-title" id="editUserModalLabel<?= $user['id'] ?>">Modifier Utilisateur</h5>
                                                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                        <span aria-hidden="true">&times;</span>
                                                    </button>
                                                </div>
                                                <div class="modal-body">
                                                    <form action="admin.php" method="POST">
                                                        <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                        <div class="form-group">
                                                            <label for="username">Nom d'utilisateur</label>
                                                            <input type="text" name="username" id="username" class="form-control" value="<?= htmlspecialchars($user['username']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="nom">Nom</label>
                                                            <input type="text" name="nom" id="nom" class="form-control" value="<?= htmlspecialchars($user['nom']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="prenom">Prénom</label>
                                                            <input type="text" name="prenom" id="prenom" class="form-control" value="<?= htmlspecialchars($user['prenom']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="email">Email</label>
                                                            <input type="email" name="email" id="email" class="form-control" value="<?= htmlspecialchars($user['email']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="role">Rôle</label>
                                                            <select name="role" id="role" class="form-control" required>
                                                                <option value="user" <?= $user['role'] == 'user' ? 'selected' : '' ?>>Utilisateur</option>
                                                                <option value="admin" <?= $user['role'] == 'admin' ? 'selected' : '' ?>>Admin</option>
                                                            </select>
                                                        </div>
                                                        <button type="submit" name="update_user" class="btn btn-primary">Mettre à jour</button>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Animaux Section -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Animaux</div>
                    <div class="card-body">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Nom</th>
                                    <th>Type</th>
                                    <th>Race</th>
                                    <th>Alimentation</th>
                                    <th>Nombre de repas</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($animals as $animal) : ?>
                                    <tr>
                                        <td><?= htmlspecialchars($animal['id']) ?></td>
                                        <td><?= htmlspecialchars($animal['nom']) ?></td>
                                        <td><?= htmlspecialchars($animal['type']) ?></td>
                                        <td><?= htmlspecialchars($animal['race']) ?></td>
                                        <td><?= htmlspecialchars($animal['alimentation']) ?></td>
                                        <td><?= htmlspecialchars($animal['nombre_de_repas']) ?></td>
                                        <td>
                                            <button class="btn btn-warning btn-sm" data-toggle="modal" data-target="#editAnimalModal<?= $animal['id'] ?>">Modifier</button>
                                            <form action="delete_animal.php" method="POST" style="display:inline;">
                                                <input type="hidden" name="animal_id" value="<?= $animal['id'] ?>">
                                                <button type="submit" class="btn btn-danger btn-sm">Supprimer</button>
                                            </form>
                                        </td>
                                    </tr>

                                    <!-- Modal Modifier Animal -->
                                    <div class="modal fade" id="editAnimalModal<?= $animal['id'] ?>" tabindex="-1" role="dialog" aria-labelledby="editAnimalModalLabel<?= $animal['id'] ?>" aria-hidden="true">
                                        <div class="modal-dialog" role="document">
                                            <div class="modal-content">
                                                <div class="modal-header">
                                                    <h5 class="modal-title" id="editAnimalModalLabel<?= $animal['id'] ?>">Modifier Animal</h5>
                                                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                                                        <span aria-hidden="true">&times;</span>
                                                    </button>
                                                </div>
                                                <div class="modal-body">
                                                    <form action="admin.php" method="POST">
                                                        <input type="hidden" name="animal_id" value="<?= $animal['id'] ?>">
                                                        <div class="form-group">
                                                            <label for="nom">Nom</label>
                                                            <input type="text" name="nom" id="nom" class="form-control" value="<?= htmlspecialchars($animal['nom']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="type">Type</label>
                                                            <input type="text" name="type" id="type" class="form-control" value="<?= htmlspecialchars($animal['type']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="race">Race</label>
                                                            <input type="text" name="race" id="race" class="form-control" value="<?= htmlspecialchars($animal['race']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="alimentation">Alimentation</label>
                                                            <input type="text" name="alimentation" id="alimentation" class="form-control" value="<?= htmlspecialchars($animal['alimentation']) ?>" required>
                                                        </div>
                                                        <div class="form-group">
                                                            <label for="nombre_de_repas">Nombre de repas</label>
                                                            <input type="number" name="nombre_de_repas" id="nombre_de_repas" class="form-control" value="<?= htmlspecialchars($animal['nombre_de_repas']) ?>" required>
                                                        </div>
                                                        <button type="submit" name="update_animal" class="btn btn-primary">Mettre à jour</button>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
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
                            <label for="username">Nom d'utilisateur</label>
                            <input type="text" name="username" id="username" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Mot de passe</label>
                            <input type="password" name="password" id="password" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="email">Email</label>
                            <input type="email" name="email" id="email" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="nom">Nom</label>
                            <input type="text" name="nom" id="nom" class="form-control" required>
                        </div>
                        <div class="form-group">
                            <label for="prenom">Prénom</label>
                            <input type="text" name="prenom" id="prenom" class="form-control" required>
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

