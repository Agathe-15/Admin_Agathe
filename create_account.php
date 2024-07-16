<?php
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
            header("Location: ../views/login.php");
            exit();
        } else {
            $_SESSION['error'] = "Erreur lors de la création du compte.";
        }
    } else {
        $_SESSION['error'] = "Veuillez remplir tous les champs.";
    }
}

header("Location: ../views/signup.php");
exit();
