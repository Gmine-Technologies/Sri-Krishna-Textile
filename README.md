# Sreekrishna Textiles: store + backend

Express + SQLite backend that also serves the website (`public/index.html`).
The site auto-detects the backend: if `/api/health` answers, it uses the live database;
otherwise it falls back to browser-only demo mode.

## Run
```bash
npm install
npm start            # http://localhost:3000
```
First start creates `data/store.db` and seeds 70 products, 5 sample customers
(password `customer123`), sample orders (Jan-Oct) and monthly expenses.
`npm run reseed` deletes the database so the next start re-seeds it.

## Logins
| Role | How |
|---|---|
| Admin | Login page, **Admin** tab: `admin@sreekrishna.demo` / `admin123` |
| Customer | Register on the site, or use e.g. `priya@example.com` / `customer123` |

## Configuration (environment variables)
| Variable | Purpose |
|---|---|
| `PORT` | default 3000 |
| `JWT_SECRET` | **set this in production** (long random string) |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | admin account created on first start (**change the default password**) |
| `DB_FILE` | custom SQLite file path |

## What the backend does
* Passwords hashed with bcrypt, JWT login (7 days), login rate limiting, admin/customer roles enforced on the server.
* Products: public list; admin create / edit price, discount, cost, stock, name / upload picture (stored in `data/uploads`) / delete. Cost price is only sent to admins.
* Orders: the server recomputes prices, checks stock inside a transaction (no overselling), reduces stock, and restores it when an order is cancelled. Customers see only their own orders; admin sees all and changes status.
* Admin analytics: monthly sales, cost of goods, gross profit, expenses (rent, salaries, marketing, other + 3% shipping estimate) and net profit/loss, category split, top sellers, customers; record expenses from the Profit & Loss tab.

## Order tracking and accounts
* Every order has a timeline (Order placed, Processing, Shipped, Out for delivery, Delivered, or Cancelled) with timestamps and notes.
* Admin: Orders tab, open **Manage**, set status, courier, tracking number, expected date and a note for the customer. Marking Shipped needs a tracking number.
* Customers: My Orders shows status and the full timeline; an in-app "Order updates" feed and a badge on the account icon show new updates. Customers can cancel while an order is still Processing (stock is restored).
* Guests: `#/track` with order ID + the phone number used at checkout.
* Admin **Profile & Settings**: change name, phone, password; edit store name/contact, delivery fee, free-delivery limit and low-stock alert level (applied to checkout and dashboard).
* Customers can save phone and default address (pre-fills checkout) and change their password.

## API (JSON, `Authorization: Bearer <token>`)
`POST /api/auth/register|login` · `GET /api/me` · `GET /api/products` · `POST|PUT|DELETE /api/products[/:id]` (admin) ·
`POST /api/orders` · `GET /api/orders` · `PATCH /api/orders/:id/status` (admin) ·
`PUT /api/me` · `POST /api/me/password` · `GET /api/settings` · `PUT /api/settings` (admin) · `GET /api/orders/:id` · `POST /api/orders/:id/cancel` · `GET /api/track?id=&phone=` ·
`PATCH /api/orders/:id/status` takes `{status, note, tracking, courier, eta}` ·
`GET /api/admin/dashboard?year=` · `GET /api/admin/customers` · `GET|POST /api/admin/expenses`

## Not included yet (for production)
Real payment gateway (payments are mocked), email notifications, password reset, HTTPS / reverse proxy,
a real AI try-on provider (the try-on screen is a mock), and moving images to S3/Cloudinary.
