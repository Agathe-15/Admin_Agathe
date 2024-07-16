<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = htmlspecialchars(strip_tags($_POST['username']));
    $password = password_hash(htmlspecialchars(strip_tags($_POST['password'])), PASSWORD_BCRYPT);
    $email = htmlspecialchars(strip_tags($_POST['email']));
    $nom = htmlspecialchars(strip_tags($_POST['nom']));
    $prenom = htmlspecialchars(strip_tags($_POST['prenom']));

    if (!empty($username) && !empty($password) && !empty($email) && !empty($nom) && !empty($prenom)) {
        $query = "INSERT INTO users (username, password, email, nom, prenom, role) VALUES (:username, :password, :email, :nom, :prenom, 'user')";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':nom', $nom);
        $stmt->bindParam(':prenom', $prenom);

        if ($stmt->execute()) {
            header("Location: login.php");
            exit();
        } else {
            $_SESSION['error'] = "Erreur lors de la création du compte.";
        }
    } else {
        $_SESSION['error'] = "Veuillez remplir tous les champs.";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../public/css/style.css">
    <title>Inscription</title>
</head>

<body>
    <header>
        <div class="container">
            <h1>Le Planning de mes Animaux</h1>
        </div>
    </header>
    <div class="container content">
        <div class="signup-form">
            <h2>Inscription</h2>
            <form action="signup.php" method="POST">
                <input type="text" name="nom" placeholder="Nom" required><br>
                <input type="text" name="prenom" placeholder="Prénom" required><br>
                <input type="email" name="email" placeholder="Email" required><br>
                <input type="password" name="password" placeholder="Mot de passe" required><br>
                <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
                <button type="submit">Inscription</button>
            </form>
            <?php if (isset($_SESSION['error'])) : ?>
                <p style="color: red;"><?= $_SESSION['error'] ?></p>
                <?php unset($_SESSION['error']); ?>
            <?php endif; ?>
        </div>
    </div>
    <footer>
        <p>&copy; 2023</p>
    </footer>
</body>

</html>
