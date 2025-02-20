import React from 'react';
import Spline from '@splinetool/react-spline';

export default function Background() {
  return (
    <div style={{ position: 'relative', width: '100vw', height: '100vh', overflow: 'hidden' }}>
      {/* Spline as the background */}
      <Spline
        scene="https://prod.spline.design/VpVWoO6JvK98jiHM/scene.splinecode"
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          zIndex: -1, // Ensure it's behind all other content
        }}
      />

      {/* Other foreground content */}
      <div style={{ zIndex: 1, position: 'relative', color: '#fff', textAlign: 'center', marginTop: '20vh' }}>
        <h1>Welcome to My Website</h1>
        <p>Interactive 3D background with Spline</p>
      </div>
    </div>
  );
}
