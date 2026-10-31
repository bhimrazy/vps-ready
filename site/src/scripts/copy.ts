// Copies text and flashes "Copied" on the button; if the clipboard is not
// available, selects the source element so the user can copy by hand.
export function copyText(text: string, button: HTMLElement, source: Node) {
  const label = button.textContent;
  const done = () => {
    button.textContent = 'Copied';
    setTimeout(() => (button.textContent = label), 1500);
  };
  const select = () => {
    const r = document.createRange();
    r.selectNodeContents(source);
    const s = getSelection();
    s?.removeAllRanges();
    s?.addRange(r);
  };
  try {
    navigator.clipboard.writeText(text).then(done, select);
  } catch {
    select();
  }
}
