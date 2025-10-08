// ==================== DARK MODE TOGGLE ====================
const darkToggle = document.getElementById('darkModeToggle');
const body = document.body;

// Cek localStorage untuk preferensi dark mode
if (localStorage.getItem('darkMode') === 'enabled') {
  body.classList.add('dark-mode');
  darkToggle.textContent = '☀️';
}

darkToggle.addEventListener('click', () => {
  body.classList.toggle('dark-mode');
  
  if (body.classList.contains('dark-mode')) {
    darkToggle.textContent = '☀️';
    localStorage.setItem('darkMode', 'enabled');
  } else {
    darkToggle.textContent = '🌙';
    localStorage.setItem('darkMode', 'disabled');
  }
});

// ==================== LIVE SEARCH ====================
const searchInput = document.getElementById('globalSearch');
const allTables = document.querySelectorAll('.resourceTable tbody');

searchInput.addEventListener('input', () => {
  const query = searchInput.value.trim().toLowerCase();

  allTables.forEach(tbody => {
    Array.from(tbody.rows).forEach(row => {
      const text = row.innerText.toLowerCase();
      row.classList.toggle('hide', query && !text.includes(query));
    });
  });
});

// ==================== SMOOTH SCROLL ====================
document.querySelectorAll('#toc a').forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const targetId = link.getAttribute('href');
    document.querySelector(targetId).scrollIntoView({
      behavior: 'smooth',
      block: 'start'
    });
  });
});

// ==================== EXPORT TO JSON ====================
document.getElementById('exportJSON').addEventListener('click', () => {
  const data = [];
  
  document.querySelectorAll('section').forEach(section => {
    const category = section.querySelector('h2').textContent.trim();
    const resources = [];
    
    section.querySelectorAll('tbody tr').forEach(row => {
      const cells = row.querySelectorAll('td');
      if (cells.length >= 2) {
        const link = cells[0].querySelector('a');
        resources.push({
          name: link ? link.textContent.trim() : cells[0].textContent.trim(),
          url: link ? link.href : '',
          description: cells[1].textContent.trim()
        });
      }
    });
    
    data.push({ category, resources });
  });

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'awesome-hacker-search-engines.json';
  a.click();
  URL.revokeObjectURL(url);
  
  alert('✅ JSON exported successfully!');
});

// ==================== EXPORT TO PDF ====================
document.getElementById('exportPDF').addEventListener('click', () => {
  alert('📑 PDF Export: Use your browser Print → Save as PDF for best results!\n\nOr integrate jsPDF library for automated PDF generation.');
  window.print();
});

// ==================== AUTO UPDATE INDICATOR (Optional) ====================
// Jika ingin menambahkan indikator "last updated" dari GitHub repo
const updateIndicator = document.createElement('div');
updateIndicator.style.cssText = 'position:fixed;top:10px;left:10px;padding:0.5rem;background:#0070c9;color:#fff;border-radius:5px;font-size:0.8rem;z-index:1000;';
updateIndicator.innerHTML = '🔄 Auto-updated from <a href="https://github.com/123tool" target="_blank" style="color:#fff;text-decoration:underline;">GitHub</a>';

// Uncomment jika ingin menampilkan
// document.body.appendChild(updateIndicator);

console.log('🔎 Awesome Hacker Search Engines loaded successfully!');
console.log('🌐 GitHub: https://github.com/123tool');