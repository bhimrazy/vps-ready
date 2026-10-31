// HTML for a shell command that may wrap only at clean points: spaces, and
// after each "/" inside a URL path (via <wbr>), never mid-word. <wbr> has no
// text, so the element's textContent is still the exact command to copy.
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export const breakableCommand = (cmd: string) => esc(cmd).replace(/(?<!:\/)\/(?=[\w.-])/g, '/<wbr>');
