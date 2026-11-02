# RMC update — users, appointment cash, patient statements

## First run (do this once)

1. Copy all files over your repo, keeping the `js/` and `css/` folders.
2. Open `index.html` and sign in with `admin` / `RMC123`.
3. Go to **Users** (new tile on the main page, administrators only) and click
   **Create starting accounts**. That creates:
   - `admin` — administrator
   - `Fadia` / `Fadia123$`
   - `Sarah` / `Sarah321#`
4. Change the admin password with **Set password** on the admin row. The page
   warns you while it is still the default.

The built-in `admin` / `RMC123` login only works while the `users` collection
is empty, so it closes itself as soon as step 3 is done.

## What changed

### New pages
- **`AppointmentCash.html`** — a day's appointments, each with what it was
  charged, the cash in and out recorded against it, and the balance. Record
  cash per appointment; cash-in prefills the outstanding balance. Expand a row
  to see and delete its individual entries.
- **`PatientStatement.html`** — pick a patient and see every appointment and
  every payment, with totals charged / paid / balance. Optional date range and
  a Print button.
- **`users.html`** — add staff accounts, set passwords, enable/disable, delete.
  Administrators only.

### Shared files (new)
- `js/rmc-auth.js` — sign-in session, PBKDF2-SHA256 password hashing, and
  `RMC.stamp()`, which attaches the signed-in user to every write.
- `js/rmc-helpers.js` — date/money formatting and the Firebase config.
- `css/rmc.css` — shared styles for the new pages.

Both JS files are plain (non-module) scripts on purpose: a relative `import`
is blocked by the browser when a page is opened as `file://`, so shared code
has to load this way to keep working off disk as well as from a server.

### Changes to existing pages
- **`index.html`** — signs in against the `users` collection instead of a
  hardcoded password, and records each user's last sign-in.
- **`createAppointment.html`** — new **Amount Charged** field, also editable
  inline in the day's schedule.
- **`CashInOut.html`** — stores the real clock time of the transaction instead
  of midnight, and records who entered it.
- **`CashDaily.html` / `CashMonthly.html`** — show date *and* time, plus a
  **Recorded by** column. Entries saved before this update kept only a midnight
  date, so those rows fall back to their `createdAt` time.
- **`Main.html`** — shows who is signed in; Users tile for administrators.
- **`CashHome.html` / `Home.html`** — tiles for the new pages.
- **`createPatient.html` / `createDoctor.html` / `AccountReceivables.html`** —
  every write now records the user who made it.

## Data model

- `appointments` gained `charge` (number or `null`).
- `cash` gained `appointmentId` and `appointmentAt`. Entries made from
  `CashInOut.html` have `appointmentId: null`.
- Every record gained `recordedById`, `recordedByName` and `recordedAtLocal`.
- New `users` collection, document id = lowercased username:
  `username`, `usernameLower`, `displayName`, `role` (`admin` | `user`),
  `active`, `pwAlgo`, `pwIterations`, `pwSalt`, `pwHash`, `createdAt`,
  `updatedAt`, `lastLoginAt`.

Nothing existing was renamed or removed, so old records keep working.

## Security — please read

Passwords are no longer in the source, and they are stored as PBKDF2-SHA256
hashes (100,000 iterations, random salt per user) rather than plaintext. But
the check still happens in the browser, and your Firestore rules let any
anonymous visitor read the database, so the `users` documents — hashes
included — are readable by anyone who finds the project. That is a real
improvement over a password sitting in `index.html`, not a solution.

The proper fix is Firebase Authentication with email/password accounts, where
Firestore rules enforce access on the server. Worth doing before this handles
anything you would mind losing.

Separately: `bash.exe.stackdump` in the repo root is a leftover crash file and
can be deleted.
