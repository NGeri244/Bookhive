<?php
session_start();

// Check if the user is already logged in
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: ../index.php");
    exit;
}

$current_page = 'login';
$page_title = 'Bejelentkezés';

require_once "config/db.php";
require_once "includes/header.php";

$username = $password = "";
$username_err = $password_err = $login_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST"){
    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Kérem adja meg a felhasználónevét.";
    } else{
        // Sanitize username input
        $username = trim(htmlspecialchars($_POST["username"]));
        if(strlen($username) < 3 || strlen($username) > 50) {
            $username_err = "A felhasználónév 3-50 karakter hosszú lehet.";
        }
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Kérem adja meg a jelszavát.";
    } else{
        // Sanitize password input
        $password = trim($_POST["password"]);
        if(strlen($password) < 6) {
            $password_err = "A jelszónak legalább 6 karakter hosszúnak kell lennie.";
        }
    }
    
    if(empty($username_err) && empty($password_err)){
        $sql = "SELECT id, username, password, role, name FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($conn, $sql)){
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            $param_username = $username;
            
            if(mysqli_stmt_execute($stmt)){
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password, $role, $name);
                    if(mysqli_stmt_fetch($stmt)){
                        if(password_verify($password, $hashed_password)){
                            session_start();
                            
                            // Store data in session variables
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = htmlspecialchars($username);
                            $_SESSION["role"] = htmlspecialchars($role);
                            $_SESSION["name"] = htmlspecialchars($name);
                            
                            header("location: ../index.php");
                        } else{
                            $login_err = "Érvénytelen felhasználónév vagy jelszó.";
                        }
                    }
                } else{
                    $login_err = "Érvénytelen felhasználónév vagy jelszó.";
                }
            } else{
                echo "Hiba történt. Kérjük próbálja újra később.";
            }
            mysqli_stmt_close($stmt);
        }
    }
    mysqli_close($conn);
}
?>

<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h3 class="text-center mb-0">
                    <i class="fas fa-sign-in-alt me-2"></i>Bejelentkezés
                </h3>
            </div>
            <div class="card-body">
                <?php 
                if(!empty($login_err)){
                    echo '<div class="alert alert-danger alert-dismissible fade show" role="alert">
                            <i class="fas fa-exclamation-circle me-2"></i>' . $login_err . '
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                          </div>';
                }        
                ?>
                <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
                    <div class="form-group mb-3">
                        <label>
                            <i class="fas fa-user me-2"></i>Felhasználónév
                        </label>
                        <input type="text" name="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>" data-tooltip="Adja meg a felhasználónevét">
                        <span class="invalid-feedback"><?php echo $username_err; ?></span>
                    </div>    
                    <div class="form-group mb-3">
                        <label>
                            <i class="fas fa-lock me-2"></i>Jelszó
                        </label>
                        <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>" data-tooltip="Adja meg a jelszavát">
                        <span class="invalid-feedback"><?php echo $password_err; ?></span>
                    </div>
                    <div class="form-group text-center">
                        <button type="submit" class="btn btn-primary btn-block w-100" data-tooltip="Kattintson a bejelentkezéshez">
                            <i class="fas fa-sign-in-alt me-2"></i>Bejelentkezés
                        </button>
                    </div>
                    <p class="text-center mt-3">
                        Még nincs fiókja? 
                        <a href="register.php" class="text-decoration-none" data-tooltip="Hozzon létre új fiókot">
                            <i class="fas fa-user-plus me-1"></i>Regisztráljon itt
                        </a>
                    </p>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once "includes/footer.php"; ?> 