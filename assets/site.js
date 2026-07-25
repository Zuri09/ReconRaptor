(() => {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!reducedMotion && window.Lenis) {
    new window.Lenis({
      autoRaf: true,
      anchors: true,
      smoothWheel: true,
      duration: 1.05,
    });
  }

  const revealItems = document.querySelectorAll("[data-reveal]");
  if (reducedMotion || !("IntersectionObserver" in window)) {
    revealItems.forEach((item) => item.classList.add("is-visible"));
  } else {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -10% 0px", threshold: 0.16 },
    );
    revealItems.forEach((item) => observer.observe(item));
  }

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    const originalLabel = button.textContent;
    const selectText = (target) => {
      const range = document.createRange();
      range.selectNodeContents(target);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    };

    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;

      try {
        if (!navigator.clipboard || !window.isSecureContext) {
          throw new Error("Clipboard unavailable");
        }
        await navigator.clipboard.writeText(target.textContent.trim());
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = originalLabel;
        }, 1600);
      } catch {
        selectText(target);
        button.textContent = "Selected";
        window.setTimeout(() => {
          button.textContent = originalLabel;
        }, 1600);
      }
    });
  });
})();
