function initDataInsert() {
  const dataEditor = document.querySelector("[data-editor]");
  if (dataEditor) {
    const config = new Map();
    const obj = JSON.parse(dataEditor.getAttribute("data-editor") || "{}");
    for (const [key, value] of Object.entries(obj)) {
      config.set(key, value);
    }
    const ext = config.get("ext");
    const textarea = dataEditor.querySelector("textarea");
    if (textarea && globalThis.editors && globalThis.editors.length > 0) {
      const editor = globalThis.editors[0];
      for (const dataInsert of document.querySelectorAll("[data-insert]")) {
        const config = new Map();
        const obj = JSON.parse(dataInsert.getAttribute("data-insert") || "{}");
        for (const [key, value] of Object.entries(obj)) {
          config.set(key, value);
        }
        const name = config.get("name");
        const altText = config.get("altText");
        let text = "";
        if (name.endsWith(".css")) {
          text = `\n<link rel='stylesheet' href='${name}'>\n`;
        } else if (name.endsWith(".js")) {
          text = `\n<script src='${name}'></script>\n`;
        } else if (name.endsWith(".jpeg") || name.endsWith(".jpg") || name.endsWith(".png") || name.endsWith(".webp") || name.endsWith(".gif") || name.endsWith(".svg")) {
          text = `\n<img src='${name}' alt='${altText}' style='max-width: 100%; height: auto;'>\n`;
        } else if (name.endsWith(".md")) {
          text = `\n{{ index $.Markdown "${name}" }}\n`;
        } else {
          continue;
        }
        dataInsert.addEventListener("click", function() {
          if (ext == ".html" || ext == ".css" || ext == ".js") {
            const range = editor.state.selection.ranges[0];
            editor.dispatch({
              changes: {
                from: range.from,
                to: range.to,
                insert: text,
              },
              selection: {
                anchor: range.from,
              }
            });
          } else {
            const cursorPosition = textarea.selectionStart;
            textarea.value = textarea.value.substring(0, cursorPosition) + text + textarea.value.substring(cursorPosition);
            textarea.style.height = `${textarea.scrollHeight}px`;
          }
          const innerText = dataInsert.innerText;
          dataInsert.innerText = "inserted!";
          setTimeout(function() { dataInsert.innerText = innerText }, 800);
        });
      }
    }
  }
}
initDataInsert();
if (typeof globalThis.init == "function") {
  const previousInit = globalThis.init;
  globalThis.init = function() {
    previousInit();
    initDataInsert();
  }
} else {
  globalThis.init = initDataInsert;
}
