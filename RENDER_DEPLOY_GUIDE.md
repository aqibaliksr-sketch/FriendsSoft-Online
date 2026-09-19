# FriendsSoft PostgreSQL + Render

This package is prepared for Render Node.js + PostgreSQL.
1. Create a Render PostgreSQL database.
2. Run/import schema.sql in that database.
3. Create the Web Service from this repository.
4. Set DB_HOST, DB_PORT=5432, DB_NAME, DB_USER, DB_PASSWORD, DB_SSL=true, SESSION_SECRET and DEVELOPER_KEY as environment variables.
5. Build: npm install
6. Start: npm start
7. Health check: /health
