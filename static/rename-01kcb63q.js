const dataCopy = document.querySelector("[data-copy]");
const dataSrc = document.querySelector("input[data-src]");
const dataDest = document.querySelector("input[data-dest]");
if (dataCopy && dataSrc && dataDest) {
  dataCopy.addEventListener("click", function() {
    dataDest.value = dataSrc.value;
    dataDest.focus();
  });
}
