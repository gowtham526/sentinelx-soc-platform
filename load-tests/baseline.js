import http from 'k6/http';
import { sleep, check } from 'k6';

// 100 virtual users running continuously for 1 minute
export const options = {
  vus: 100, 
  duration: '1m', 
  thresholds: {
    // 95% of requests must complete below 1.5s
    http_req_duration: ['p(95)<1500'], 
  },
};

export default function () {
  const res = http.get('http://127.0.0.1:5000');
  check(res, {
    'is status 200': (r) => r.status === 200,
    'response time < 1500ms': (r) => r.timings.duration < 1500,
  });
  // Simulate user think-time
  sleep(1);
}
