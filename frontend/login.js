document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const message = document.getElementById("message");

  message.textContent = "Logging in...";
  message.className = "";

  try {
    const res = await fetch("http://127.0.0.1:5000/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (res.ok) {
      // ✅ Save login info in localStorage
      localStorage.setItem("token", data.token);
      localStorage.setItem("username", data.username);
      localStorage.setItem("user_id", data.user_id);

      message.textContent = data.message;
      message.className = "success";

      // ✅ Redirect after short delay
      setTimeout(() => {
        window.location.href = data.redirect;
      }, 1000);
    } else {
      message.textContent = data.error || "Invalid email or password";
      message.className = "error";
    }
  } catch (err) {
    console.error(err);
    message.textContent = "Error connecting to server.";
    message.className = "error";
  }
});
