// To build this file:
// - Navigate to the project root where package.json is located.
// - Run npm install
// - Run ./node_modules/.bin/esbuild --outdir=./static/ --bundle --minify ./static/*.ts
import { EditorState, Prec, Compartment } from '@codemirror/state';
import { EditorView, lineNumbers, keymap } from '@codemirror/view';
import { indentWithTab, history, defaultKeymap, historyKeymap } from '@codemirror/commands';
import { indentOnInput, indentUnit, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { autocompletion, completionKeymap } from '@codemirror/autocomplete';
import { html } from "@codemirror/lang-html";
import { css } from "@codemirror/lang-css";
import { javascript } from "@codemirror/lang-javascript";

function initDataEditor() {
  globalThis.editors = [];
  for (const [index, dataEditor] of document.querySelectorAll<HTMLElement>("[data-editor]").entries()) {
    globalThis.editors.push(null);
    const config = new Map<string, any>();
    try {
      let obj = JSON.parse(dataEditor.getAttribute("data-editor") || "{}");
      for (const [key, value] of Object.entries(obj)) {
        config.set(key, value);
      }
    } catch (e) {
      console.error(e);
      continue;
    }

    // Locate the textarea.
    const textarea = dataEditor.querySelector("textarea");
    if (!textarea) {
      continue;
    }

    // Locate the parent form that houses the textarea.
    let form: HTMLFormElement | undefined;
    let element = textarea.parentElement;
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

    // Determine the file extension.
    let ext = "";
    if (config.has("ext")) {
      ext = config.get("ext");
    } else if (config.has("extElementName")) {
      const extElementName = config.get("extElementName");
      const extElement = form.elements[extElementName] as HTMLInputElement | HTMLSelectElement;
      if (extElement) {
        ext = extElement.value;
      }
    }

    // Ctrl-s/Cmd-s to submit.
    textarea.addEventListener("keydown", function(event) {
      if (navigator.userAgent.includes("Macintosh")) {
        if (!event.metaKey || event.key != "s") {
          return;
        }
      } else {
        if (!event.ctrlKey || event.key != "s") {
          return;
        }
      }
      event.preventDefault();
      if (form) {
        form.dispatchEvent(new Event("submit"));
        if (!config.get("ajaxSubmission")) {
          form.submit();
        }
      }
    });

    // NOTE: Resetting the height with "auto" causes annoying viewport jumps when
    // typing on iOS Safari. Don't do it (like in answer
    // https://stackoverflow.com/a/48460773). Just set the scrollHeight directly.
    // This means the textarea will never shrink, only grow, but it's the price
    // to pay for not being annoying to type on mobile.
    textarea.addEventListener("input", function() {
      textarea.style.height = `${textarea.scrollHeight}px`;
    });

    // Create the codemirror editor.
    const wordwrap = new Compartment();
    const language = new Compartment();
    const editor = new EditorView({
      state: EditorState.create({
        doc: textarea.value,
        extensions: [
          // Basic extensions copied from basicSetup in
          // https://github.com/codemirror/basic-setup/blob/main/src/codemirror.ts.
          lineNumbers(),
          history(),
          indentUnit.of("  "),
          indentOnInput(),
          autocompletion(),
          keymap.of([
            indentWithTab,
            ...defaultKeymap,
            ...historyKeymap,
            ...completionKeymap,
          ]),
          syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
          // Dynamic settings.
          wordwrap.of([]),
          language.of([]),
          // Custom theme.
          EditorView.theme({
            "&": {
              fontSize: "11.5pt",
              border: "1px solid black",
              backgroundColor: "white",
            },
            ".cm-content": {
              fontFamily: "Menlo, Monaco, Lucida Console, monospace",
              minHeight: "16rem"
            },
            ".cm-scroller": {
              overflow: "auto",
            }
          }),
          // Custom keymaps.
          Prec.high(keymap.of([
            {
              // Ctrl-s/Cmd-s to submit.
              key: "Mod-s",
              run: function(_: EditorView): boolean {
                if (form) {
                  // manualSubmit:true
                  form.dispatchEvent(new Event("submit"));
                  if (!config.get("ajaxSubmission")) {
                    form.submit();
                  }
                }
                return true;
              },
            },
          ])),
        ],
      }),
    });

    // Register the codemirror editor in the global editors array.
    globalThis.editors[index] = editor;

    if (config.get("scrollIntoView")) {
      // Restore textarea cursor position from localStorage.
      const textareaCursorPosition = Number(localStorage.getItem(`textareaCursorPosition:${window.location.pathname}:${index}`));
      if (textareaCursorPosition && textareaCursorPosition <= textarea.value.length) {
        textarea.setSelectionRange(textareaCursorPosition, textareaCursorPosition);
      }

      // Restore editor cursor position from localStorage.
      const editorCursorPosition = Number(localStorage.getItem(`editorCursorPosition:${window.location.pathname}:${index}`));
      if (editorCursorPosition && editorCursorPosition <= textarea.value.length) {
        editor.dispatch({
          selection: { anchor: editorCursorPosition, head: editorCursorPosition },
        });
      }
    }

    // Configure word wrap.
    let wordwrapEnabled = localStorage.getItem(`wordwrap:${window.location.pathname}:${index}`);
    if (wordwrapEnabled == null) {
      if (ext == ".html" || ext == ".css" || ext == ".js") {
        wordwrapEnabled = "false";
      } else {
        wordwrapEnabled = "true";
      }
    }
    if (wordwrapEnabled == "true") {
      editor.dispatch({
        effects: wordwrap.reconfigure(EditorView.lineWrapping),
      });
      textarea.style.whiteSpace = "pre-wrap";
      textarea.style.overflow = "hidden";
      textarea.style.height = `${textarea.scrollHeight}px`;
    } else {
      editor.dispatch({
        effects: wordwrap.reconfigure([]),
      });
      textarea.style.whiteSpace = "pre";
      textarea.style.overflow = "auto";
      textarea.style.height = `${textarea.scrollHeight}px`;
    }
    if (config.has("wordwrapCheckboxID")) {
      const wordwrapCheckboxID = config.get("wordwrapCheckboxID");
      const wordwrapInput = document.getElementById(wordwrapCheckboxID) as HTMLInputElement;
      if (wordwrapInput) {
        wordwrapInput.checked = wordwrapEnabled == "true";
        wordwrapInput.addEventListener("click", function() {
          if (wordwrapInput.checked) {
            localStorage.setItem(`wordwrap:${window.location.pathname}:${index}`, "true");
            editor.dispatch({
              effects: wordwrap.reconfigure(EditorView.lineWrapping),
            });
            textarea.style.whiteSpace = "pre-wrap";
            textarea.style.overflow = "hidden";
            textarea.style.height = `${textarea.scrollHeight}px`;
          } else {
            localStorage.setItem(`wordwrap:${window.location.pathname}:${index}`, "false");
            editor.dispatch({
              effects: wordwrap.reconfigure([]),
            });
            textarea.style.whiteSpace = "pre";
            textarea.style.overflow = "auto";
            textarea.style.height = `${textarea.scrollHeight}px`;
          }
        });
      }
    }

    // On form submit, synchronize the codemirror editor's contents with the
    // textarea it is paired with (before the form is submitted).
    form.addEventListener("submit", function() {
      if (config.get("scrollIntoView")) {
        // Save the textarea cursor position to localStorage.
        localStorage.setItem(`textareaCursorPosition:${window.location.pathname}:${index}`, textarea.selectionStart.toString());
        // Save the editor cursor position to localStorage.
        const ranges = editor.state.selection.ranges;
        if (ranges.length > 0) {
          const editorCursorPosition = ranges[0].from;
          localStorage.setItem(`editorCursorPosition:${window.location.pathname}:${index}`, editorCursorPosition.toString());
        }
      }
      // Copy the codemirror editor's contents to the textarea.
      if (ext == ".html" || ext == ".css" || ext == ".js") {
        textarea.value = editor.state.doc.toString();
      }
    }, {
      capture: true,
    });

    // Insert the codemirror editor after the textarea.
    textarea.after(editor.dom);

    // Show the textarea or the codemirror editor depending on the extension.
    if (ext == ".html" || ext == ".css" || ext == ".js") {
      // Hide textarea.
      textarea.style.setProperty("display", "none");
      // Configure editor language.
      if (textarea.value.length <= 50000) {
        if (ext == ".html") {
          editor.dispatch({
            effects: language.reconfigure(html()),
          });
        } else if (ext == ".css") {
          editor.dispatch({
            effects: language.reconfigure(css()),
          });
        } else if (ext == ".js") {
          editor.dispatch({
            effects: language.reconfigure(javascript()),
          });
        }
      }
      // Scroll to editor cursor position.
      if (config.get("scrollIntoView")) {
        const editorCursorPosition = Number(localStorage.getItem(`editorCursorPosition:${window.location.pathname}:${index}`));
        if (editorCursorPosition && editorCursorPosition <= textarea.value.length) {
          editor.dispatch({
            effects: EditorView.scrollIntoView(editorCursorPosition, { y: "center" }),
          });
        }
      }
    } else {
      // Hide editor.
      editor.dom.style.setProperty("display", "none", "important");
      // Scroll to textarea cursor position.
      if (config.get("scrollIntoView")) {
        textarea.blur();
        textarea.focus();
        textarea.blur();
      }
    }

    if (config.has("extElementName")) {
      const extElementName = config.get("extElementName");
      const extElement = form.elements[extElementName] as HTMLInputElement | HTMLSelectElement;
      if (extElement) {
        extElement.addEventListener("change", function() {
          ext = extElement.value;
          if (ext == ".html" || ext == ".css" || ext == ".js") {
            // Hide textarea.
            textarea.style.setProperty("display", "none");
            // Show editor
            editor.dom.style.setProperty("display", "");
            // Configure editor language.
            if (ext == ".html") {
              editor.dispatch({
                effects: language.reconfigure(html()),
              });
            } else if (ext == ".css") {
              editor.dispatch({
                effects: language.reconfigure(css()),
              });
            } else if (ext == ".js") {
              editor.dispatch({
                effects: language.reconfigure(javascript()),
              });
            }
          } else {
            // Hide editor.
            editor.dom.style.setProperty("display", "none", "important");
            // Show textarea.
            textarea.style.setProperty("display", "");
          }
        });
      }
    }
  }
};
initDataEditor();
if (typeof globalThis.init == "function") {
  const previousInit = globalThis.init;
  globalThis.init = function() {
    previousInit();
    initDataEditor();
  }
} else {
  globalThis.init = initDataEditor;
}
