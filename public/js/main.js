/* ═══════════════════════════════════════════════════════════════
   SentinelProbe — main.js
   Landing page: Three.js sphere + scroll reveal + card tilt
═══════════════════════════════════════════════════════════════ */

// ── 3D Sphere ───────────────────────────────────────────────
(function initSphere() {
  const canvas = document.getElementById('hero-canvas');
  if (!canvas || typeof THREE === 'undefined') return;

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  const scene  = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
  camera.position.set(0, 0, 4.5);

  // Main sphere
  const sphereGeo = new THREE.SphereGeometry(1.18, 64, 64);
  const sphereMat = new THREE.MeshStandardMaterial({ color: new THREE.Color('#3D2B46'), roughness: 0.38, metalness: 0.18 });
  const sphere    = new THREE.Mesh(sphereGeo, sphereMat);
  sphere.position.x = 2.0;
  scene.add(sphere);

  // Inner glow
  const glowGeo = new THREE.SphereGeometry(1.12, 32, 32);
  const glowMat = new THREE.MeshStandardMaterial({ color: new THREE.Color('#B87968'), transparent: true, opacity: 0.065, roughness: 1 });
  const glow    = new THREE.Mesh(glowGeo, glowMat);
  glow.position.x = 2.0;
  scene.add(glow);

  // Primary ring
  const ring1 = new THREE.Mesh(
    new THREE.TorusGeometry(1.65, 0.004, 3, 220),
    new THREE.MeshBasicMaterial({ color: new THREE.Color('#C8B89A'), transparent: true, opacity: 0.22 })
  );
  ring1.position.x = 2.0;
  ring1.rotation.x = Math.PI * 0.2;
  ring1.rotation.y = Math.PI * 0.05;
  scene.add(ring1);

  // Halo ring
  const ring2 = new THREE.Mesh(
    new THREE.TorusGeometry(1.44, 0.002, 3, 200),
    new THREE.MeshBasicMaterial({ color: new THREE.Color('#7A9E8A'), transparent: true, opacity: 0.14 })
  );
  ring2.position.x = 2.0;
  ring2.rotation.x = Math.PI * 0.38;
  ring2.rotation.z = Math.PI * 0.1;
  scene.add(ring2);

  // Lights
  scene.add(new THREE.AmbientLight(0xffffff, 0.28));
  const keyL = new THREE.DirectionalLight(new THREE.Color('#F0E8DC'), 1.18);
  keyL.position.set(3, 4, 3);
  scene.add(keyL);
  const fillL = new THREE.DirectionalLight(new THREE.Color('#B87968'), 0.48);
  fillL.position.set(-3, -1, 2);
  scene.add(fillL);
  const rimL = new THREE.DirectionalLight(new THREE.Color('#7A9E8A'), 0.28);
  rimL.position.set(0, -3, -2);
  scene.add(rimL);

  // Resize
  function resize() {
    const w = canvas.parentElement.offsetWidth;
    const h = canvas.parentElement.offsetHeight;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize();
  window.addEventListener('resize', resize);

  // Animation
  let t = 0;
  (function animate() {
    requestAnimationFrame(animate);
    t += 0.004;
    sphere.rotation.y = t * 0.16;
    sphere.rotation.x = Math.sin(t * 0.28) * 0.04;
    ring1.rotation.y += 0.0014;
    ring1.rotation.z += 0.0007;
    ring2.rotation.x += 0.0005;
    ring2.rotation.y -= 0.001;
    renderer.render(scene, camera);
  })();
})();

// ── Scroll reveal ───────────────────────────────────────────
const observer = new IntersectionObserver(
  entries => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('in-view'); }),
  { threshold: 0.1 }
);
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

// ── Card tilt ───────────────────────────────────────────────
function tilt(e, card) {
  const r = card.getBoundingClientRect();
  card.style.setProperty('--mx', ((e.clientX - r.left) / r.width * 100) + '%');
  card.style.setProperty('--my', ((e.clientY - r.top)  / r.height * 100) + '%');
}

// ── Smooth nav scroll ───────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    const target = document.querySelector(a.getAttribute('href'));
    if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth' }); }
  });
});
