document.getElementById("signupForm").addEventListener("submit", async function(e) {
  e.preventDefault();

  const data = {
    username: document.getElementById("username").value,
    email: document.getElementById("email").value,
    password: document.getElementById("password").value
  };

  try {
    const response = await fetch("http://vicyon.onrender.com/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      credentials: "include"
    });

    const result = await response.json();
    document.getElementById("message").innerText = result.message || result.error;

    if (response.ok) {
      document.getElementById("message").style.color = "#00e676";
    } else {
      document.getElementById("message").style.color = "#ff5252";
    }
  } catch (error) {
    document.getElementById("message").innerText = "⚠️ Server not responding";
    document.getElementById("message").style.color = "#ff5252";
  }
});
