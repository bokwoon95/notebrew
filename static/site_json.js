const dataNavigationLinks = document.querySelector("[data-navigation-links]");
if (dataNavigationLinks) {
  const dataAddNavigationLink = document.querySelector("[data-add-navigation-link]");
  if (dataAddNavigationLink) {
    dataAddNavigationLink.addEventListener("click", function() {
      const items = document.querySelectorAll("[data-navigation-link]");
      const i = items.length;
      const fieldset = document.createElement("fieldset");
      fieldset.setAttribute("data-navigation-link", "");
      fieldset.innerHTML = `<legend>item ${i + 1}</legend>`
        + `\n<div class='mv1'>`
        + `\n<label for='navigationLinkName:${i}'>`
        + `\n<span class='b'>Name: </span>`
        + `\n<input id='navigationLinkName:${i}' name='navigationLinkName' class='pv1 ph2 br2 ba'>`
        + `\n</label>`
        + `\n</div>`
        + `\n<div class='mv1'>`
        + `\n<label for='navigationLinkURL:${i}'>`
        + `\n<span class='b'>URL: </span>`
        + `\n<input id='navigationLinkURL:${i}' name='navigationLinkURL' class='pv1 ph2 br2 ba'>`
        + `\n</label>`
        + `\n</div>`;
      dataNavigationLinks.appendChild(fieldset);
    });
  }
  const dataRemoveNavigationLink = document.querySelector("[data-remove-navigation-link]");
  if (dataRemoveNavigationLink) {
    dataRemoveNavigationLink.addEventListener("click", function() {
      const items = document.querySelectorAll("[data-navigation-link]");
      if (items.length == 0) {
        return;
      }
      items[items.length-1].remove();
    });
  }
}
