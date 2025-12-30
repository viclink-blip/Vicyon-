document.getElementById("forgotForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("email").value;
  const newPassword = document.getElementById("newPassword").value;
  const message = document.getElementById("message");

  message.textContent = "Processing...";

  try {
    const response = await fetch("http://127.0.0.1:5000/forgot-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email: email, new_password: newPassword })
    });

    const data = await response.json();

    if (response.ok) {
      message.style.color = "green";
      message.textContent = data.message;
    } else {
      message.style.color = "red";
      message.textContent = data.error || "Something went wrong.";
    }
  } catch (err) {
    message.style.color = "red";
    message.textContent = "Server not responding.";
  }
});
