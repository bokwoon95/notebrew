const form = document.querySelector("form[data-login-validation]");
if (form) {
  const config = new Map();
  const obj = JSON.parse(form.getAttribute("data-login-validation") || "{}");
  for (const [key, value] of Object.entries(obj)) {
    config.set(key, value);
  }
  const statusText = config.get("statusText") || "submitting...";
  form.addEventListener("submit", function(event) {
    event.preventDefault();
    if (form.classList.contains("submitting")) {
      return;
    }
    form.classList.add("submitting", "o-70");
    const statusElement = form.querySelector("[role=status]");
    if (statusElement) {
      statusElement.textContent = statusText;
    }
    const dataCaptchaResponseName = document.querySelector("[data-captcha-response-name]");
    if (dataCaptchaResponseName) {
      const formData = new FormData(form);
      const captchaResponseName = dataCaptchaResponseName.getAttribute("data-captcha-response-name");
      if (captchaResponseName && formData.has(captchaResponseName) && formData.get(captchaResponseName) == "") {
        if (statusElement) {
          statusElement.textContent = "NOTE: Solve the captcha";
        } else {
          console.log("NOTE: Solve the captcha");
        }
        form.classList.remove("submitting", "o-70");
        return;
      }
    }
    form.submit();
  });
}
