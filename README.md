# Complaint Management System (Node.js + Express + MongoDB + JWT)
1. Install Node.js 18+ and MongoDB (or use a free MongoDB Atlas URI).
2. `npm install`
3. Optional: set `MONGO_URI` and `JWT_SECRET` (see `.env.example`). Defaults to `mongodb://127.0.0.1:27017/cms`.
4. `npm start` then open http://localhost:3000
Demo logins (created on first run): citizen@cms.com / citizen123 · officer@cms.com / officer123 · admin@cms.com / admin123
Open http://localhost:3000 in the browser. Do NOT double-click index.html, the server must be running.
If you see "Could not start", MongoDB is not running: start it, or put a MongoDB Atlas link in MONGO_URI.
Login works with email **or** User ID (shown in Profile, e.g. USR-1001, OFF-1001, ADM-1001).
