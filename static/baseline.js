function humanReadableFileSize(size) {
  if (size < 0) {
    return "";
  }
  const unit = 1000;
  if (size < unit) {
    return size.toString() + " B";
  }
  let div = unit;
  let exp = 0;
  for (let n = size / unit; n >= unit; n /= unit) {
    div *= unit;
    exp++;
  }
  return (size / div).toFixed(1) + " " + ["kB", "MB", "GB", "TB", "PB", "EB"][exp];
}

document.body.parentElement.addEventListener("click", (event) => {
  let activeDetails = null;
  let element = event.target;
  while (element != null) {
    if (element.tagName != "DETAILS") {
      element = element.parentElement;
      continue;
    }
    activeDetails = element;
    break;
  }
  for (const dataAutocloseDetails of document.querySelectorAll("details[data-autoclose-details]")) {
    if (dataAutocloseDetails.open && dataAutocloseDetails != activeDetails) {
      dataAutocloseDetails.open = false;
    }
  }
});

for (const dataDismissAlert of document.querySelectorAll("[data-dismiss-alert]")) {
  dataDismissAlert.addEventListener("click", function() {
    let parentElement = dataDismissAlert.parentElement;
    while (parentElement != null) {
      const role = parentElement.getAttribute("role");
      if (role != "alert") {
        parentElement = parentElement.parentElement;
        continue;
      }
      parentElement.style.transition = "opacity 100ms linear";
      parentElement.style.opacity = "0";
      setTimeout(function() { parentElement.style.display = "none" }, 100);
      return;
    }
  });
}

for (const dataGoBack of document.querySelectorAll("[data-go-back]")) {
  if (dataGoBack.tagName != "A") {
    continue;
  }
  dataGoBack.addEventListener("click", function(event) {
    if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
      event.preventDefault();
      history.back();
    }
  });
}

for (const dataDisableClickSelection of document.querySelectorAll("[data-disable-click-selection]")) {
  dataDisableClickSelection.addEventListener("mousedown", function(event) {
    // https://stackoverflow.com/a/43321596
    if (event.detail > 1) {
      event.preventDefault();
    }
  });
}

for (const dataPaste of document.querySelectorAll("[data-paste]")) {
  let name = "";
  let validExt = new Set();
  try {
    const obj = JSON.parse(dataPaste.getAttribute("data-paste"));
    if (obj.name) {
      name = obj.name;
    }
    if (obj.exts) {
      for (let i = 0; i < obj.exts.length; i++) {
        validExt.add(obj.exts[i]);
      }
    }
  } catch (e) {
    console.error(e);
    continue;
  }
  let form = null;
  let element = dataPaste.parentElement;
  while (element != null) {
    if (element instanceof HTMLFormElement) {
      form = element;
      break;
    }
    element = element.parentElement;
  }
  if (!form) {
    continue;
  }
  const input = form.elements[name];
  if (!(input instanceof HTMLInputElement) || input.type != "file") {
    continue;
  }
  dataPaste.addEventListener("paste", function(event) {
    event.preventDefault();
    if (event.clipboardData.files.length == 0) {
      dataPaste.value = "no files in clipboard";
      setTimeout(function() { dataPaste.value = "" }, 800);
      return;
    }
    let dataTransfer = new DataTransfer();
    let invalidCount = 0;
    for (let i = 0; i < input.files.length; i++) {
      const file = input.files.item(i);
      dataTransfer.items.add(file);
    }
    const files = [];
    for (let i = 0; i < event.clipboardData.files.length; i++) {
      const file = event.clipboardData.files.item(i);
      const n = file.name.lastIndexOf(".");
      const ext = n < 0 ? "" : file.name.substring(n);
      if (!validExt.has(ext)) {
        invalidCount++;
        continue;
      }
      files.push(file);
    }
    files.sort(function(a, b) {
      if (a.lastModified == b.lastModified) {
        return 0;
      }
      if (a.lastModified < b.lastModified) {
        return -1;
      }
      return 1;
    });
    for (const file of files) {
      dataTransfer.items.add(file);
    }
    if (invalidCount > 0) {
      dataPaste.value = `${invalidCount} invalid file${invalidCount == 1 ? "" : "s"}`;
      setTimeout(function() { dataPaste.value = "" }, 800);
    }
    input.files = dataTransfer.files;
    input.dispatchEvent(new Event("input"));
  });
}

for (const dataPreventDoubleSubmit of document.querySelectorAll("[data-prevent-double-submit]")) {
  if (dataPreventDoubleSubmit.tagName != "FORM") {
    continue;
  }
  const config = new Map();
  const obj = JSON.parse(dataPreventDoubleSubmit.getAttribute("data-prevent-double-submit") || "{}");
  for (const [key, value] of Object.entries(obj)) {
    config.set(key, value);
  }
  const statusText = config.get("statusText") || "submitting...";
  dataPreventDoubleSubmit.addEventListener("submit", function(event) {
    event.preventDefault();
    if (dataPreventDoubleSubmit.classList.contains("submitting")) {
      return;
    }
    dataPreventDoubleSubmit.classList.add("submitting", "o-70");
    const statusElement = dataPreventDoubleSubmit.querySelector("[role=status]");
    if (statusElement) {
      statusElement.textContent = statusText;
    }
    // Include the submit button's value if it exists.
    if (event.submitter && event.submitter.name) {
      const input = document.createElement("input");
      input.setAttribute("type", "hidden");
      input.setAttribute("name", event.submitter.name);
      input.setAttribute("value", event.submitter.value);
      dataPreventDoubleSubmit.appendChild(input);
    }
    dataPreventDoubleSubmit.submit();
  });
}

for (const dataUploadFile of document.querySelectorAll("[data-upload-file]")) {
  const statusElement = dataUploadFile.querySelector("[role=status]");
  let uploadSize = 0;
  for (const fileInput of dataUploadFile.querySelectorAll("input[type=file]")) {
    fileInput.addEventListener("input", function() {
      const formData = new FormData(dataUploadFile);
      let size = 0;
      for (const [_, value] of formData.entries()) {
        if (value instanceof Blob) {
          size += value.size;
        }
      }
      uploadSize = size;
      if (statusElement) {
        if (size == 0) {
          statusElement.textContent = "";
        } else {
          statusElement.textContent = humanReadableFileSize(size);
        }
      }
    });
  }
  dataUploadFile.addEventListener("submit", function(event) {
    event.preventDefault();
    if (dataUploadFile.classList.contains("submitting")) {
      return;
    }
    dataUploadFile.classList.add("submitting", "o-70");
    // If no files to upload, submit the form the traditional way.
    if (uploadSize == 0) {
      if (statusElement) {
        statusElement.textContent = "submitting...";
      }
      // Include the submit button's value if it exists.
      if (event.submitter && event.submitter.name) {
        const input = document.createElement("input");
        input.setAttribute("type", "hidden");
        input.setAttribute("name", event.submitter.name);
        input.setAttribute("value", event.submitter.value);
        dataUploadFile.appendChild(input);
      }
      dataUploadFile.submit();
      return;
    }
    const xhr = new XMLHttpRequest();
    xhr.open("POST", dataUploadFile.action, true);
    xhr.upload.onprogress = function(event) {
      if (statusElement) {
        const percentage = event.loaded == event.total ? "100%" : ((event.loaded / event.total) * 100).toFixed(3) + "%";
        statusElement.textContent = humanReadableFileSize(event.loaded) + " / " + humanReadableFileSize(event.total) + " (" + percentage + ")";
      }
    };
    xhr.onload = function() {
      if (statusElement) {
        statusElement.textContent = "";
      }
      dataUploadFile.classList.remove("submitting", "o-70");
      history.pushState({}, "", xhr.responseURL);
      document.open();
      document.write(xhr.response);
      document.close();
      if (typeof globalThis.init == "function") {
        globalThis.init();
      }
    }
    const formData = new FormData(dataUploadFile);
    if (event.submitter && event.submitter.name) {
      formData.append(event.submitter.name, event.submitter.value);
    }
    xhr.send(formData);
  });
}

for (const dataCheckboxLeader of document.querySelectorAll("[data-checkbox-leader]")) {
  if (dataCheckboxLeader.tagName != "INPUT" || dataCheckboxLeader.getAttribute("type") != "checkbox") {
    continue;
  }
  const leaderGroup = dataCheckboxLeader.getAttribute("data-checkbox-leader");
  dataCheckboxLeader.addEventListener("change", function() {
    for (const dataCheckboxFollower of document.querySelectorAll("[data-checkbox-follower]")) {
      const followerGroup = dataCheckboxFollower.getAttribute("data-checkbox-follower");
      if (followerGroup != leaderGroup) {
        return;
      }
      dataCheckboxFollower.checked = dataCheckboxLeader.checked;
    }
  });
}

for (const dataCheckOnFocus of document.querySelectorAll("[data-check-on-focus]")) {
  dataCheckOnFocus.addEventListener("focus", function() {
    for (const element of document.querySelectorAll(dataCheckOnFocus.getAttribute("data-check-on-focus"))) {
      element.checked = true;
    }
  });
}
