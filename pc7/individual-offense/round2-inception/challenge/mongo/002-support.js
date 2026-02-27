const dbName = process.env.APP_DB || "pccc";
const d = db.getSiblingDB(dbName);

// ---------- Collection validators ----------
const ticketValidator = {
  $jsonSchema: {
    bsonType: "object",
    required: ["key", "title", "summary", "user_id"],
    properties: {
      key: {
        bsonType: "string",
        description: "Ticket key used in URLs, e.g. PC-001",
        pattern: "^PC-\\d{1,6}$"
      },
      challenge: { bsonType: ["string", "null"] },
      title: { bsonType: "string", minLength: 1 },
      // Intentionally allow raw HTML/JS for XSS testing
      summary: { bsonType: "string" },
      user_id: { bsonType: "objectId" },
      status: { bsonType: "int", enum: [0, 1, 2], description: "0=Unseen,1=Seen,2=Resolved" },
      createdAt: { bsonType: ["date", "null"] },
      updatedAt: { bsonType: ["date", "null"] }
    },
    additionalProperties: true
  }
};

const commentValidator = {
  $jsonSchema: {
    bsonType: "object",
    required: ["ticket_key", "user_id", "text"],
    properties: {
      ticket_key: {
        bsonType: "string",
        pattern: "^PC-\\d{1,6}$"
      },
      user_id: { bsonType: "objectId" },
      text: { bsonType: "string" }, // may include HTML for XSS testing
      createdAt: { bsonType: ["date", "null"] }
    },
    additionalProperties: true
  }
};

// Create or tighten collections
function ensureCollection(name, validator) {
  if (!d.getCollectionNames().includes(name)) {
    d.createCollection(name, {
      validator,
      validationLevel: "strict",
      validationAction: "error"
    });
  } else {
    d.runCommand({
      collMod: name,
      validator,
      validationLevel: "strict",
      validationAction: "error"
    });
  }
}

ensureCollection("tickets", ticketValidator);
ensureCollection("comments", commentValidator);

// ---------- Indexes ----------
// tickets
d.tickets.createIndex({ key: 1 }, { unique: true });                  // lookup by PC-XXX
d.tickets.createIndex({ user_id: 1, createdAt: -1 });                  // list a user's tickets
d.tickets.createIndex({ challenge: 1, createdAt: -1 });                // filter by challenge
d.tickets.createIndex({ status: 1, createdAt: 1 });
// --- one-time backfill default for existing docs missing status ---
d.tickets.updateMany({ status: { $exists: false } }, { $set: { status: 0 } });
// Optional full-text search across title/summary (uncomment if wanted):
// d.tickets.createIndex({ title: "text", summary: "text" });

// comments
d.comments.createIndex({ ticket_key: 1, createdAt: 1 });               // load comments by ticket, ordered
d.comments.createIndex({ user_id: 1, createdAt: -1 });                 // user activity

// ---------- Counter for sequential keys ----------
if (!d.counters.findOne({ _id: "ticket" })) {
  d.counters.insertOne({ _id: "ticket", seq: 0, prefix: "PC-" });
}

print("[support] tickets/comments collections, indexes, and counter ensured.");
