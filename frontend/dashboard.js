document.addEventListener("DOMContentLoaded", () => {

  console.log("✅ Dashboard Loaded");

  // ================= ELEMENTS =================
  const buyPlanBtn = document.getElementById("buyPlanBtn");
  const logoutBtn = document.getElementById("logoutBtn");
  const planOptions = document.getElementById("planOptions");
  const mainButtons = document.getElementById("main-buttons");
  const backBtn = document.getElementById("backBtn");
  const message = document.getElementById("message");

  const sendRequestBtn = document.getElementById("sendRequestBtn");
  const popup = document.getElementById("connectionPopup");
  const submitRequest = document.getElementById("submitRequest");
  const closePopup = document.getElementById("closePopup");
  const receiverIdInput = document.getElementById("receiverId");
  const popupMessage = document.getElementById("popupMessage");

  const viewIncomingBtn = document.getElementById("viewIncomingBtn");
  const requestsSection = document.getElementById("incoming-requests-section");
  const requestsContainer = document.getElementById("incoming-requests");

  const sound = document.getElementById("vicyonSound");

  // ================= USER DATA =================
  const username = localStorage.getItem("username");
  const userId = localStorage.getItem("user_id");
  const token = localStorage.getItem("token");

  const userInfo = document.getElementById("username");
  const userIdField = document.getElementById("user-id");

  if (username && userId) {
    userInfo.textContent = username;
    userIdField.textContent = `Your ID: ${userId}`;
  } else {
    userInfo.textContent = "Please log in first.";
    userIdField.textContent = "";
  }

  // ================= CHECK CONNECTION STATUS =================
  async function checkConnectionStatus() {
    if (!token) return;

    try {
      const res = await fetch("http://127.0.0.1:5000/connection/status", {
        headers: { "Authorization": `Bearer ${token}` }
      });

      const data = await res.json();

      if (data.connected) {
        message.textContent = data.message;
        message.style.color = "lightgreen";
      }

    } catch (err) {
      console.log("Connection status error:", err);
    }
  }

  checkConnectionStatus();

  // ================= ANIMATION =================
  const rightPart = document.querySelector(".right");

  rightPart.addEventListener("animationend", async () => {
    try { await sound.play(); } catch {}

    setTimeout(() => {
      mainButtons.classList.remove("hidden");
      mainButtons.style.opacity = 0;
      mainButtons.style.transition = "opacity 1.5s";
      setTimeout(() => (mainButtons.style.opacity = 1), 50);
    }, 2500);
  });

  // ================= BUY PLAN =================
  buyPlanBtn.addEventListener("click", () => {
    mainButtons.classList.add("hidden");
    planOptions.classList.remove("hidden");
    message.textContent = "";
  });

  backBtn.addEventListener("click", () => {
    planOptions.classList.add("hidden");
    mainButtons.classList.remove("hidden");
  });

  document.querySelectorAll(".plan-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const planType = btn.dataset.plan;

      if (!token) {
        message.textContent = "Missing token.";
        return;
      }

      const res = await fetch("http://127.0.0.1:5000/buy_plan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ plan_type: planType })
      });

      const data = await res.json();
      message.textContent = res.ok ? `✅ ${data.message}` : `❌ ${data.error}`;

      planOptions.classList.add("hidden");
      mainButtons.classList.remove("hidden");
    });
  });

  // ================= SEND REQUEST =================
  sendRequestBtn.addEventListener("click", () => {
    popup.classList.remove("hidden");
    popupMessage.textContent = "";
  });

  closePopup.addEventListener("click", () => {
    popup.classList.add("hidden");
    receiverIdInput.value = "";
  });

  submitRequest.addEventListener("click", async () => {
    const receiverId = receiverIdInput.value.trim();

    if (!receiverId) {
      popupMessage.textContent = "Enter User ID.";
      return;
    }

    const res = await fetch(`http://127.0.0.1:5000/connection/request/${receiverId}`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    });

    const data = await res.json();
    popupMessage.textContent = data.message || data.error;
    popupMessage.style.color = res.ok ? "green" : "red";
  });

  // ================= VIEW INCOMING =================
  viewIncomingBtn.addEventListener("click", async () => {
    console.log("Checking incoming requests…");

    if (!token) {
      message.textContent = "Missing token. Login again.";
      return;
    }

    try {
      const res = await fetch("http://127.0.0.1:5000/connection/incoming", {
        headers: { "Authorization": `Bearer ${token}` }
      });

      const data = await res.json();

      const requests = Array.isArray(data) ? data : data.requests;
      requestsContainer.innerHTML = "";

      if (!requests || requests.length === 0) {
        requestsContainer.innerHTML = "<p>No incoming requests.</p>";
        requestsSection.classList.remove("hidden");
        return;
      }

      requests.forEach(r => {
        const box = document.createElement("div");
        box.innerHTML = `
          <p><strong>From:</strong> ${r.from_user_id}</p>
          <p><strong>Status:</strong> ${r.status}</p>
          <button class="accept-btn" data-id="${r.from_user_id}">Accept</button>
          <button class="decline-btn" data-id="${r.from_user_id}">Decline</button>
          <hr>
        `;
        requestsContainer.appendChild(box);
      });

      requestsSection.classList.remove("hidden");

      // ===== ACCEPT =====
      document.querySelectorAll(".accept-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          const fromId = btn.dataset.id;
          const res = await fetch(`http://127.0.0.1:5000/connection/accept/${fromId}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` }
          });

          const d = await res.json();
          alert(d.message || d.error);

          viewIncomingBtn.click();
        });
      });

      // ===== DECLINE (FIXED) =====
      document.querySelectorAll(".decline-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          const fromId = btn.dataset.id;

          const res = await fetch(`http://127.0.0.1:5000/connection/decline/${fromId}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` }
          });

          const d = await res.json();
          alert(d.message || d.error);

          viewIncomingBtn.click();
        });
      });

    } catch (err) {
      message.textContent = "Error loading requests.";
    }
  });

  // ================= LOGOUT =================
  logoutBtn.addEventListener("click", async () => {
    const res = await fetch("http://127.0.0.1:5000/logout", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` }
    });

    if (res.ok) {
      localStorage.clear();
      window.location.href = "login.html";
    } else {
      message.textContent = "Logout failed.";
    }
  });

});
