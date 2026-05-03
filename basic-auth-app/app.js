// 1. Import necessary modules
const express = require("express");
const session = require("express-session");
const path = require("path");

// 2. Initialize the Express application
const app = express();
const PORT = 3000; // You can change this port if needed

// 3. Setup Middleware
// This allows Express to read data sent from HTML forms
app.use(express.urlencoded({ extended: true }));

// Setup Session Handling
// A session stores data on the server for an individual user
app.use(
  session({
    secret: "mySimpleSecretKey123", // A secret string used to sign the session ID cookie
    resave: false,                  // Don't save session if unmodified
    saveUninitialized: false,       // Don't create session until something is stored
  })
);

// 4. Create Routes
// Route: Homepage -> Redirects to Login page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

// Route: Handle Login Form Submission
app.post("/login", (req, res) => {
  // Extract username and password from the submitted form (name attributes in HTML)
  const username = req.body.username;
  const password = req.body.password;

  // Simple hardcoded check for demonstration (username: "user", password: "password123")
  if (username === "user" && password === "password123") {
    // If successful, save the username in the session to "log them in"
    req.session.loggedInUser = username;
    
    // Redirect the user to the dashboard
    res.redirect("/dashboard");
  } else {
    // If failed, send an error message
    res.send("<h2>Invalid username or password. <a href='/'>Try again</a></h2>");
  }
});

// 5. Middleware to protect the Dashboard route
// This custom function checks if the user is authenticated
function checkLoginStatus(req, res, next) {
  // If the session has a loggedInUser, allow them to proceed
  if (req.session.loggedInUser) {
    next(); // Continue to the next route handler
  } else {
    // Otherwise, redirect them back to the login page
    res.redirect("/");
  }
}

// Route: Protected Dashboard
// Notice we pass our "checkLoginStatus" function before the handler
app.get("/dashboard", checkLoginStatus, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});

// Route: Logout
app.get("/logout", (req, res) => {
  // Destroy the session to log the user out
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      res.send("Error logging out");
    } else {
      res.redirect("/"); // Go back to the login page after logging out
    }
  });
});

// 6. Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
