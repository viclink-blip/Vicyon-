// Wait until the page is fully loaded
document.addEventListener("DOMContentLoaded", () => {
  const logoutBtn = document.getElementById("logout-btn");

  // Only add the event if the button exists
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("http://127.0.0.1:5000/logout", {
          method: "POST",
          credentials: "include",
        });
        const data = await res.json();
        alert(data.message);
        window.location.href = "login.html"; // Redirect to login page
      } catch (err) {
        console.error("Logout error:", err);
        alert("Error logging out. Try again.");
      }
    });
  }
});
