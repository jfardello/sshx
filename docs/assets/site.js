// Apply the saved preference in the head, before the documentation renders.
const sshxTheme = (() => {
  const sheet = document.getElementById('dark-theme');
  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
  const storageKey = 'sshx-docs-theme';
  let preference;
  let toggle;

  try {
    const saved = localStorage.getItem(storageKey);
    if (saved === 'dark' || saved === 'light') preference = saved;
  } catch (_) {
    // Theme switching also works when browser storage is unavailable.
  }

  function apply() {
    const dark = preference ? preference === 'dark' : systemTheme.matches;
    sheet.media = dark ? 'all' : 'not all';
    if (toggle) toggle.checked = dark;
  }

  apply();
  systemTheme.addEventListener('change', apply);

  return {
    mount() {
      const sidebar = document.querySelector('.sidebar');
      if (!sidebar || toggle) return;
      const container = document.createElement('label');
      container.className = 'theme-control';
      toggle = document.createElement('input');
      toggle.type = 'checkbox';
      toggle.className = 'toggle theme-toggle';
      toggle.setAttribute('role', 'switch');
      toggle.addEventListener('change', () => {
        preference = toggle.checked ? 'dark' : 'light';
        try {
          localStorage.setItem(storageKey, preference);
        } catch (_) {
          // Keep the current choice for this page even without storage.
        }
        apply();
      });
      container.append(toggle, document.createTextNode('Dark theme'));
      sidebar.prepend(container);
      apply();
    }
  };
})();

window.$docsify = {
  name: 'sshx',
  repo: 'https://github.com/jfardello/sshx',
  logo: 'assets/sshx-icon.svg',
  homepage: 'README.md',
  loadNavbar: true,
  loadSidebar: true,
  tabs: {
    theme: 'material', 
  },
  relativePath: true,
  auto2top: true,
  subMaxLevel: 2,
  maxLevel: 3,
  nativeEmoji: true,
  copyCode: {
    buttonText: 'copy',
    errorText: 'Error',
    successText: 'Copied',
  },
  alias: {
    '/.*/_navbar.md': '/_navbar.md',
    '/.*/_sidebar.md': '/_sidebar.md'
  },
  // Docsify 4 resolves shared navigation relative to the active article.
  // Root its links before compilation; the source Markdown stays portable.
  // These two rendering hooks are tied to the pinned Docsify version.
  plugins: [function (hook, vm) {
    hook.mounted(() => sshxTheme.mount());
    hook.init(function () {
      ['_renderSidebar', '_renderNav'].forEach(function (method) {
        const render = vm[method];
        vm[method] = function (text) {
          const rooted = text && text.replace(/\]\((?![a-z]+:|[\/#])([^)]*)\)/gi, '](/$1)');
          return render.call(this, rooted);
        };
      });
    });
  }],
  search: {
    placeholder: 'Search documentation',
    noData: 'No matching documentation',
    depth: 3,
    namespace: 'sshx-docs'
  }
};
