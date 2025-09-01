document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault(); 
    const formData = new FormData(e.target);
    const response = await fetch("/api/login", {
        method: "POST",
        body: new URLSearchParams(formData)
    });

    if (response.ok) {
        window.location.href = "/dashboard";
    } else {
        document.getElementById("error-message").textContent = "Invalid username or password.";
        document.getElementById("error-message").style.display = "block";
    }
});
