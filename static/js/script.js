/* ===================================
   Trust Me Bro
   Frontend JavaScript
   Vanilla JS Only
=================================== */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('urlForm');
  const urlInput = document.getElementById('url');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const loading = document.getElementById('loading');
  const copyBtn = document.getElementById('copyURLBtn');
  const displayURL = document.getElementById('display-url');
  const menuToggle = document.querySelector('.menu-toggle');
  const navLinks = document.querySelector('.nav-links');

  /* ==========================
       Mobile Navigation
    ========================== */

  if (menuToggle && navLinks) {
    menuToggle.addEventListener('click', () => {
      navLinks.classList.toggle('active');
    });
  }

  /* ==========================
       URL Validation
    ========================== */

  if (form) {
    form.addEventListener('submit', event => {
      const value = urlInput.value.trim();

      if (value === '') {
        event.preventDefault();

        alert('Please enter a URL.');

        urlInput.focus();

        return;
      }

      if (loading) {
        loading.style.display = 'block';
      }

      if (analyzeBtn) {
        analyzeBtn.disabled = true;

        analyzeBtn.textContent = 'Analyzing...';
      }

      /* Backend submission will be handled by Flask later */
    });
  }

  /* ==========================
       Copy URL
    ========================== */

  if (copyBtn && displayURL) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(displayURL.textContent.trim());

        const original = copyBtn.textContent;

        copyBtn.textContent = 'Copied!';

        setTimeout(() => {
          copyBtn.textContent = original;
        }, 2000);
      } catch {
        alert('Unable to copy URL.');
      }
    });
  }

  /* ==========================
       Smooth Scrolling
    ========================== */

  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', function (e) {
      const target = document.querySelector(this.getAttribute('href'));

      if (target) {
        e.preventDefault();

        target.scrollIntoView({
          behavior: 'smooth',
        });
      }
    });
  });

  /* ==========================
       Button Click Animation
    ========================== */

  document
    .querySelectorAll('button, .primary-btn, .secondary-btn')
    .forEach(btn => {
      btn.addEventListener('click', () => {
        btn.classList.add('clicked');

        setTimeout(() => {
          btn.classList.remove('clicked');
        }, 200);
      });
    });
});
