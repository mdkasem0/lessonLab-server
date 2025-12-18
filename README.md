# LessonLab Server 🚀

LessonLab is a full-featured backend API for a lesson sharing and reflection platform.  
It supports **user authentication**, **lesson management**, **likes & favorites**, **comments**, **reports**, **admin moderation**, and **Stripe payments** using **Firebase Auth**, **MongoDB**, and **Express.js**.

---

## 🔧 Tech Stack

- **Node.js**
- **Express.js**
- **MongoDB Atlas**
- **Firebase Admin SDK** (Auth verification)
- **Stripe** (Payments)
- **CORS**
- **dotenv**

---

---

## 🔐 Environment Variables

Create a `.env` file in the root directory:

```env
PORT=5000

DB_USER=your_mongodb_username
DB_PASSWORD=your_mongodb_password

STRIPE=your_stripe_secret_key

FIREBASEJDK=base64_encoded_firebase_admin_sdk_json


```
## Routes

| METHOD | ROUTE | DESCRIPTION |
|------|-------|-------------|
| GET | / | Server health check |
| POST | /register | Register user (if not exists) |
| GET | /me | Get logged-in user profile |
| PUT | /update | Update logged-in user profile |
| GET | /admin/users | Admin: get all users with lesson counts |
| PUT | /admin/users/:id/role | Admin: update user role |
| DELETE | /admin/users/:id | Admin: delete user |
| POST | /addlesson | Create a new lesson |
| GET | /publicLesson | Get public lessons (pagination, filter, sort) |
| GET | /my-public-lessons | Get user's public lessons + total count |
| GET | /lessons | Admin: all lessons / User: own lessons |
| GET | /lesson/:id | Get single lesson |
| PATCH | /lesson/:id | Update lesson (owner/admin) |
| DELETE | /lesson/:id | Delete lesson (owner/admin) |
| PUT | /like/:id | Toggle like on lesson |
| PUT | /save/:id | Toggle save (favorite) lesson |
| POST | /report/:id | Report a lesson |
| GET | /comments/:lessonId | Get lesson comments |
| POST | /comments/:lessonId | Add comment to lesson |
| GET | /lessons/similar/:lessonId | Get similar lessons |
| GET | /my-favorites | Get user's saved lessons |
| DELETE | /favorites/:id | Remove lesson from favorites |
| GET | /admin/dashboard | Admin dashboard statistics |
| GET | /admin/lessons | Admin: filter & manage lessons |
| DELETE | /admin/lessons/:lessonId | Admin: delete lesson |
| PUT | /admin/lessons/:lessonId/featured | Admin: mark lesson as featured |
| PUT | /admin/lessons/:lessonId/reviewed | Admin: mark lesson as reviewed |
| GET | /admin/lessons/stats | Admin: lesson statistics |
| GET | /admin/reported-lessons | Admin: list reported lessons |
| GET | /admin/reported-lessons/:lessonId | Admin: report details |
| DELETE | /admin/reported-lessons/:lessonId/ignore | Admin: clear lesson reports |
| POST | /create-payment-intent | Create Stripe payment intent |
| POST | /payment/confirm | Confirm payment & upgrade user |
| GET | /api/homepage-data | Homepage featured & trending data |
