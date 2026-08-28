'use client';
import { useEffect } from 'react';

export default function Home() {
  useEffect(() => {
    window.location.href = '/spa.html';
  }, []);
  return <div style={{backgroundColor: '#0b0f19', height: '100vh'}}></div>;
}