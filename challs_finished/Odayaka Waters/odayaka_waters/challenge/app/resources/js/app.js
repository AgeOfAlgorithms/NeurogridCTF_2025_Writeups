import './bootstrap';
import { initAmbient } from './ambient';
import { initChat } from './chat/index';
import { initLogs } from './admin/logs';

document.addEventListener('DOMContentLoaded', () => {
  const ambientRoot = document.querySelector('#ambient-root');
  if (ambientRoot) {
    initAmbient(ambientRoot, {
      quality: 'standard',
      audioSrc: '/media/odayaka', // base path; .ogg/.mp3 auto-picked
    });
  }

  if (document.getElementById('ow-chat-root')) {
    initChat();
  }

  if (document.getElementById('ow-logs-root')) {
    initLogs();
  }
});
