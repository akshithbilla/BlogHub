BlogHub: A Modern Blogging Platform Inspired by Medium!

BlogHub—a full-featured blogging platform inspired by the simplicity and functionality of Medium. This project showcases a range of technologies working together to create a secure, efficient, and user-friendly experience.

Technologies Used
Frontend: EJS templating for seamless server-rendered views
Backend: Express.js for route handling and business logic
Database: PostgreSQL on a secure cloud instance (NeonDB)
Authentication: Local Strategy and Google OAuth 2.0 with Passport.js
Deployment: Vercel for fast and scalable hosting
Password Security: bcrypt for hashing user passwords
Session Management: express-session for secure and persistent user sessions
Key Features
Authentication with Google and Local Login: Users can log in or register using their Google account or an email and password.
Post Management: CRUD operations for blog posts—write, edit, delete, and view posts in a structured feed.
Role-Based Authorization: Secures pages and routes with middleware to protect data.
Data Security: Passwords are hashed using bcrypt, and sessions are managed for secure user data handling.
SQL Database: PostgreSQL for reliable data storage and retrieval, making it easy to scale and manage data.
Challenges & Learning
Session & State Management: Building and managing session storage to ensure a smooth user experience while maintaining security was a rewarding challenge.
Google OAuth: Integrating a third-party authentication provider like Google OAuth required a deep understanding of security best practices.
Database Connection Management: Ensuring database availability and responsiveness with connection pooling to prevent downtime.
GitHub and Website Links
[BlogHub GitHub Repository](https://github.com/akshithbilla/BlogHub)
[BlogHub on Vercel](https://bloghub-omega.vercel.app/)
