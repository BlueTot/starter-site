document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault(); 
    const formData = new FormData(e.target);
    const response = await fetch("/api/signup", {
        method: "POST",
        body: new URLSearchParams(formData)
    });

    if (response.ok) {
        window.location.href = "/";
    } else {
        document.getElementById("error-message").textContent = "Username already exists";
        document.getElementById("error-message").style.display = "block";
    }
});
