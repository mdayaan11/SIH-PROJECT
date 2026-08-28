import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

interface Hero3DCanvasProps {
  interactive?: boolean;
}

export const Hero3DCanvas: React.FC<Hero3DCanvasProps> = ({ interactive = true }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth || 500;
    const height = container.clientHeight || 400;

    // 1. Scene & Camera setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0, 8);

    // 2. WebGL Renderer with antialiasing and alpha transparency
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 3. Lighting setup
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
    scene.add(ambientLight);

    const pointLight1 = new THREE.PointLight(0x0284c7, 3, 50); // Deep Cyan
    pointLight1.position.set(5, 5, 5);
    scene.add(pointLight1);

    const pointLight2 = new THREE.PointLight(0x10b981, 2.5, 50); // Mint Emerald
    pointLight2.position.set(-5, -5, 5);
    scene.add(pointLight2);

    const pointLight3 = new THREE.PointLight(0x6366f1, 2, 50); // Indigo Accent
    pointLight3.position.set(0, 5, -5);
    scene.add(pointLight3);

    // 4. Create Main Group
    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // 5. Central 3D Cryptographic Shield Geometry (Octahedron / Icosahedron)
    const shieldGeometry = new THREE.OctahedronGeometry(1.6, 2);
    const shieldMaterial = new THREE.MeshPhysicalMaterial({
      color: 0xe0f2fe,
      roughness: 0.1,
      metalness: 0.1,
      transmission: 0.85, // Glass transparency
      ior: 1.5,
      reflectivity: 0.9,
      clearcoat: 1.0,
      clearcoatRoughness: 0.1,
      wireframe: false,
    });
    const shieldMesh = new THREE.Mesh(shieldGeometry, shieldMaterial);
    mainGroup.add(shieldMesh);

    // Wireframe overlay for cryptographic data grid aesthetic
    const wireframeMaterial = new THREE.MeshBasicMaterial({
      color: 0x0284c7,
      wireframe: true,
      transparent: true,
      opacity: 0.25,
    });
    const wireframeMesh = new THREE.Mesh(shieldGeometry, wireframeMaterial);
    wireframeMesh.scale.set(1.02, 1.02, 1.02);
    mainGroup.add(wireframeMesh);

    // Inner glowing core node
    const coreGeometry = new THREE.IcosahedronGeometry(0.7, 1);
    const coreMaterial = new THREE.MeshStandardMaterial({
      color: 0x06b6d4,
      emissive: 0x0284c7,
      emissiveIntensity: 0.8,
      roughness: 0.2,
      metalness: 0.8,
    });
    const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
    mainGroup.add(coreMesh);

    // 6. Orbiting Torus Rings (Cryptographic Data Key Rings)
    const ringGroup = new THREE.Group();
    mainGroup.add(ringGroup);

    const ring1Geo = new THREE.TorusGeometry(2.4, 0.03, 16, 100);
    const ring1Mat = new THREE.MeshStandardMaterial({ color: 0x0284c7, roughness: 0.3, metalness: 0.8 });
    const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
    ring1.rotation.x = Math.PI / 3;
    ringGroup.add(ring1);

    const ring2Geo = new THREE.TorusGeometry(3.0, 0.025, 16, 100);
    const ring2Mat = new THREE.MeshStandardMaterial({ color: 0x10b981, roughness: 0.3, metalness: 0.8 });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2.rotation.y = Math.PI / 4;
    ringGroup.add(ring2);

    const ring3Geo = new THREE.TorusGeometry(3.5, 0.015, 16, 100);
    const ring3Mat = new THREE.MeshStandardMaterial({ color: 0x6366f1, roughness: 0.3, metalness: 0.8 });
    const ring3 = new THREE.Mesh(ring3Geo, ring3Mat);
    ring3.rotation.x = -Math.PI / 4;
    ringGroup.add(ring3);

    // 7. Floating 3D Key Nodes
    const nodeCount = 12;
    const nodesGroup = new THREE.Group();
    mainGroup.add(nodesGroup);
    const nodeGeo = new THREE.OctahedronGeometry(0.15, 0);
    const nodeMat = new THREE.MeshStandardMaterial({ color: 0x0284c7, roughness: 0.2, metalness: 0.9 });

    for (let i = 0; i < nodeCount; i++) {
      const node = new THREE.Mesh(nodeGeo, nodeMat);
      const angle = (i / nodeCount) * Math.PI * 2;
      const radius = 2.8 + (i % 3) * 0.4;
      node.position.set(
        Math.cos(angle) * radius,
        (Math.sin(i) * 1.2),
        Math.sin(angle) * radius
      );
      nodesGroup.add(node);
    }

    // 8. Particle Cloud
    const particleCount = 120;
    const particleGeo = new THREE.BufferGeometry();
    const particlePos = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i += 3) {
      particlePos[i] = (Math.random() - 0.5) * 12;
      particlePos[i + 1] = (Math.random() - 0.5) * 12;
      particlePos[i + 2] = (Math.random() - 0.5) * 12;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePos, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0x0284c7,
      size: 0.05,
      transparent: true,
      opacity: 0.4,
    });
    const particleSystem = new THREE.Points(particleGeo, particleMat);
    scene.add(particleSystem);

    // Mouse Interaction
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      mouseX = (x / rect.width) * 1.5;
      mouseY = (y / rect.height) * 1.5;
    };

    if (interactive) {
      window.addEventListener('mousemove', handleMouseMove);
    }

    // Window Resize Listener
    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    // Animation Render Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Smooth lerp mouse tracking
      targetX += (mouseX - targetX) * 0.05;
      targetY += (mouseY - targetY) * 0.05;

      // Group rotation
      mainGroup.rotation.y = elapsedTime * 0.2 + targetX * 0.8;
      mainGroup.rotation.x = Math.sin(elapsedTime * 0.15) * 0.1 - targetY * 0.8;

      // Individual element rotations
      coreMesh.rotation.y = -elapsedTime * 0.4;
      wireframeMesh.rotation.y = elapsedTime * 0.1;

      ring1.rotation.z = elapsedTime * 0.3;
      ring2.rotation.z = -elapsedTime * 0.25;
      ring3.rotation.x = elapsedTime * 0.2;

      nodesGroup.rotation.y = elapsedTime * 0.15;
      particleSystem.rotation.y = elapsedTime * 0.03;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animationFrameId);
      if (interactive) {
        window.removeEventListener('mousemove', handleMouseMove);
      }
      window.removeEventListener('resize', handleResize);
      if (container && renderer.domElement) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [interactive]);

  return (
    <div className="relative w-full h-full min-h-[380px] flex items-center justify-center overflow-hidden rounded-3xl">
      <div ref={containerRef} className="w-full h-full absolute inset-0 cursor-grab active:cursor-grabbing" />
      
      {/* Light-theme subtle ambient glow backdrop */}
      <div className="absolute inset-0 pointer-events-none bg-radial from-cyan-400/10 via-emerald-400/5 to-transparent blur-3xl rounded-full transform -translate-y-4" />
      
      {/* Live 3D Overlay Badges */}
      <div className="absolute bottom-4 left-4 z-10 flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/70 backdrop-blur-md border border-slate-200/80 shadow-sm text-xs font-semibold text-slate-800 font-mono">
        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
        <span>3D WEBGL ACCELERATED • 60 FPS</span>
      </div>
      <div className="absolute top-4 right-4 z-10 flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/70 backdrop-blur-md border border-slate-200/80 shadow-sm text-xs font-semibold text-slate-800 font-mono">
        <span className="text-cyan-700">AES-256 GCM SHIELD</span>
      </div>
    </div>
  );
};
