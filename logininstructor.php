<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$servername = "localhost";
$username = "root"; // Default XAMPP username
$password = ""; // Default XAMPP password is empty
$dbname = "instructor";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if (isset($_POST["submit"])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare the SQL statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT password FROM logininstructor WHERE username = ?");
    $stmt->bind_param("s", $username);

    // Execute the statement
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // Bind the result
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Verify the password
        if (password_verify($password, $hashed_password)) {
            echo "<script>alert('Login successful'); window.location.href = 'InstructorDashboard.html';</script>";
          
        } else {
            echo "<script>alert('Invalid password');</script>";
             echo "Entered Password: " . $password . "<br>";
    echo "Stored Hash: " . $hashed_password . "<br>";
    echo "Password Verify Result: " . (password_verify($password, $hashed_password) ? "true" : "false") . "<br>";
}
        }
    } else {
        echo "<script>alert('Invalid username');</script>";
    }

    // Close the statement and connection
    $stmt->close();
    $conn->close();
?>
