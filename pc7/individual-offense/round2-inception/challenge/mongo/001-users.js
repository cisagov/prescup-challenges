
const dbName = process.env.APP_DB || "pccc";
const user   = process.env.APP_USER || "appuser";
const pass   = process.env.APP_PASS || "changeme";

const d = db.getSiblingDB(dbName);

// Create app user (idempotent-ish)
try {
  d.createUser({
    user: user,
    pwd:  pass,
    roles: [{ role: "readWrite", db: dbName }]
  });
  print(`Created user ${user} on ${dbName}`);
} catch (e) {
  print(`createUser skipped/failed: ${e}`);
}

// 1) Create/modify collection with a JSON Schema validator
const userValidator = {
  $jsonSchema: {
    bsonType: "object",
    required: ["email", "password_hash"],
    properties: {
      email: { bsonType: "string", pattern: "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$" },
      password_hash: { bsonType: "string", minLength: 20 }, // e.g., PBKDF2/BCrypt/Argon2 hash
      username: { bsonType: "string" }
    },
    additionalProperties: true
  }
};

// create if missing; otherwise tighten via collMod
if (!d.getCollectionNames().includes("users")) {
  d.createCollection("users", {
    validator: userValidator,
    validationLevel: "strict",
    validationAction: "error"
  });
} else {
  d.runCommand({
    collMod: "users",
    validator: userValidator,
    validationLevel: "strict",
    validationAction: "error"
  });
}

// 2) Indexes: uniqueness & (optional) case-insensitive email
d.users.createIndex({ email: 1 }, {
  unique: true,
  collation: { locale: "en", strength: 2 } // treats EMAIL == email
});
d.users.createIndex({ username: 1 }, { unique: true, sparse: true }); 
