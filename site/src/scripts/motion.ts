// Terminal player and helpers for the landing page's animated widgets.
// Imported by component scripts (browser) and frontmatter (build), so it
// must not touch `window` at module load.

export const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

// Runs fn once, the first time el is at least 30% visible.
export function onView(el: Element, fn: () => void) {
  if (!('IntersectionObserver' in window)) return fn();
  const ob = new IntersectionObserver(
    (es) => {
      if (es.some((e) => e.isIntersecting)) {
        ob.disconnect();
        fn();
      }
    },
    { threshold: 0.3 },
  );
  ob.observe(el);
}

// Utility classes for spans in terminal output, as full literals so
// Tailwind's scanner sees them.
export const tone = {
  add: 'text-brand',
  addb: 'text-brand font-bold',
  chg: 'text-warn',
  dim: 'text-muted',
  dimb: 'text-muted font-bold',
  hunk: 'text-link',
  bad: 'text-danger',
  badb: 'text-danger font-bold',
  unkb: 'text-warn font-bold',
  b: 'font-bold',
  ask: 'text-brand font-bold',
  sel: 'rounded-[3px] bg-brand-soft px-1 text-brand-ink',
  prompt: 'text-brand font-bold',
  promptLaptop: 'text-link font-bold',
} as const;
export type Tone = keyof typeof tone;
export const sp = (t: Tone, html: string) => `<span class="${tone[t]}">${html}</span>`;

// Base utilities for a terminal's text area; each terminal adds its height.
// Once the text overflows, the player keeps the newest line in view and
// sets data-overflow, which fades the top edge.
export const SCREEN =
  'm-0 flex max-h-[360px] flex-col overflow-hidden px-[18px] py-3.5 font-mono text-[12.5px] leading-[1.7] wrap-anywhere whitespace-pre-wrap text-ink *:min-h-[1.7em] *:shrink-0 data-overflow:[mask-image:linear-gradient(to_bottom,transparent_0,#000_48px)]';
const SEP = 'mt-1.5 border-t border-dashed border-line pt-1.5 text-muted';
const CURSOR = 'inline-block h-[1.1em] w-[0.6em] bg-ink align-[-0.2em] animate-blink motion-reduce:animate-none';

// One terminal step. c: type a command. o: print a line (html). a: type an
// answer onto the last line (html: insert it at once). w: wait. title,
// clock, countdown: drive the window's title and status pill.
export type Step =
  | { c: string; p?: string; pc?: Tone; fast?: boolean }
  | { o: string; d?: number; sep?: boolean }
  | { a: string; fast?: boolean; html?: boolean }
  | { w: number }
  | { title: string }
  | { clock: string | null; ok?: boolean }
  | { countdown: [from: number, to: number] };

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
const promptHtml = (st: { p?: string; pc?: Tone }) => `${sp(st.pc ?? 'prompt', st.p ?? '$')} `;

/** The finished frame of a scene as HTML, for the server render and reduced motion. */
export function frameHtml(steps: Step[]) {
  const lines: string[] = [];
  const div = (html: string, sep = false) => `<div${sep ? ` class="${SEP}"` : ''}>${html || ' '}</div>`;
  for (const st of steps) {
    if ('c' in st) lines.push(div(promptHtml(st) + esc(st.c)));
    else if ('o' in st) lines.push(div(st.o, st.sep));
    else if ('a' in st) lines[lines.length - 1] = lines[lines.length - 1].replace(/<\/div>$/, `${st.html ? st.a : esc(st.a)}</div>`);
  }
  return lines.join('');
}

export interface Chrome {
  title?: (t: string) => void;
  clock?: (t: string | null, ok?: boolean) => void;
}

export class Player {
  tok = 0;
  constructor(
    public s: HTMLElement,
    private chrome: Chrome = {},
  ) {}

  sleep(ms: number, t: number) {
    return new Promise<void>((res, rej) => setTimeout(() => (t === this.tok ? res() : rej(0)), ms));
  }

  /** Scrolls to the newest line and marks whether the text overflows. */
  fit() {
    this.s.scrollTop = this.s.scrollHeight;
    this.s.toggleAttribute('data-overflow', this.s.scrollHeight > this.s.clientHeight);
  }

  private line(html: string, sep = false) {
    const d = document.createElement('div');
    if (sep) d.className = SEP;
    d.innerHTML = html || ' ';
    this.s.appendChild(d);
    while (this.s.children.length > 60) this.s.firstChild!.remove();
    this.fit();
    return d;
  }

  /** Shows the scene's last frame at once. */
  render(steps: Step[]) {
    this.tok++;
    this.s.innerHTML = frameHtml(steps);
    this.fit();
    for (const st of steps) {
      if ('title' in st) this.chrome.title?.(st.title);
      else if ('clock' in st) this.chrome.clock?.(st.clock, st.ok);
      else if ('countdown' in st) this.chrome.clock?.(`${mmss(st.countdown[1])} left`);
    }
  }

  async play(steps: Step[]) {
    const t = ++this.tok;
    this.s.textContent = '';
    this.fit();
    for (const st of steps) {
      if ('c' in st || ('a' in st && !st.html)) {
        const text = 'c' in st ? st.c : st.a;
        let el: Element;
        if ('c' in st) {
          el = this.line(promptHtml(st));
          await this.sleep(350, t);
        } else el = this.s.lastElementChild!;
        const span = document.createElement('span');
        const cur = document.createElement('span');
        cur.className = CURSOR;
        el.append(span, cur);
        for (let k = 1; k <= text.length; k++) {
          span.textContent = text.slice(0, k);
          this.fit();
          await this.sleep(st.fast ? 18 : 34, t);
        }
        await this.sleep(260, t);
        cur.remove();
      } else if ('a' in st) this.s.lastElementChild!.insertAdjacentHTML('beforeend', st.a);
      else if ('o' in st) {
        this.line(st.o, st.sep);
        await this.sleep(st.d ?? 70, t);
      } else if ('w' in st) await this.sleep(st.w, t);
      else if ('title' in st) this.chrome.title?.(st.title);
      else if ('clock' in st) this.chrome.clock?.(st.clock, st.ok);
      else if ('countdown' in st) {
        for (let s = st.countdown[0]; s >= st.countdown[1]; s -= 2) {
          this.chrome.clock?.(`${mmss(s)} left`);
          await this.sleep(55, t);
        }
      }
    }
  }
}
