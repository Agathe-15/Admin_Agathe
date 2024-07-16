<?php
session_start();
include_once __DIR__ . '/../api/config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = htmlspecialchars(strip_tags($_POST['username']));
    $password = htmlspecialchars(strip_tags($_POST['password']));

    if (!empty($username) && !empty($password)) {
        $query = "SELECT id, username, password, role FROM users WHERE username = :username";
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];

            if ($user['role'] == 'admin') {
                header("Location: admin.php");
            } else {
                header("Location: user.php");
            }
            exit();
        } else {
            $_SESSION['error'] = "Nom d'utilisateur ou mot de passe incorrect.";
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
    <title>Connexion</title>
</head>

<body>
    <header>
        <div class="container">
            <h1>Connexion</h1>
        </div>
    </header>
    <div class="container content">
        <div>
            <h2>Se connecter</h2>
            <form action="login.php" method="POST">
                <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
                <input type="password" name="password" placeholder="Mot de passe" required><br>
                <button type="submit">Se connecter</button>
            </form>
            <?php if (isset($_SESSION['error'])) : ?>
                <p style="color: red;"><?= $_SESSION['error'] ?></p>
                <?php unset($_SESSION['error']); ?>
            <?php endif; ?>
            <p>Pas encore de compte ? <a href="signup.php">S'inscrire</a></p>
        </div>
    </div>
    <footer>
        <p>&copy; 2023</p>
    </footer>
</body>

</html>