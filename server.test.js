const request = require("supertest");
const { createServer } = require("./server.js");

const NEXTJS_TO_EXPRESS_SECRET =
  process.env.NEXTJS_TO_EXPRESS_SECRET || "supersecret";

describe("Express Server", () => {
  let app;
  beforeAll(() => {
    app = createServer();
  });

  describe("POST /cli/store-session", () => {
    it("should reject without Bearer token", async () => {
      const res = await request(app).post("/cli/store-session").send({});
      expect(res.status).toBe(403);
      expect(res.body.error).toBe("Forbidden");
    });
    it("should reject with wrong secret", async () => {
      const res = await request(app)
        .post("/cli/store-session")
        .set("Authorization", "Bearer wrongsecret")
        .send({});
      expect(res.status).toBe(403);
      expect(res.body.error).toBe("Invalid secret");
    });
    it("should reject if token or user missing", async () => {
      const res = await request(app)
        .post("/cli/store-session")
        .set("Authorization", `Bearer ${NEXTJS_TO_EXPRESS_SECRET}`)
        .send({ token: "abc" });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("Missing token or user");
    });
    it("should store session and return ok:true", async () => {
      const res = await request(app)
        .post("/cli/store-session")
        .set("Authorization", `Bearer ${NEXTJS_TO_EXPRESS_SECRET}`)
        .send({ token: "tok123", user: { email: "test@example.com" } });
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });
  });

  describe("GET /cli/session-status", () => {
    it("should reject if token missing", async () => {
      const res = await request(app).get("/cli/session-status");
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("token required");
    });
    it("should return pending if session not found", async () => {
      const res = await request(app).get("/cli/session-status?token=notfound");
      expect(res.status).toBe(200);
      expect(res.body.status).toBe("pending");
    });
    it("should return ok, apiToken, and user if session is valid", async () => {
      // Store a session first
      await request(app)
        .post("/cli/store-session")
        .set("Authorization", `Bearer ${NEXTJS_TO_EXPRESS_SECRET}`)
        .send({ token: "tok456", user: { email: "user2@example.com" } });
      const res = await request(app).get("/cli/session-status?token=tok456");
      expect(res.status).toBe(200);
      expect(res.body.status).toBe("ok");
      expect(res.body.apiToken).toBeDefined();
      expect(res.body.user.email).toBe("user2@example.com");
    });
  });

  describe("GET /api/protected-data", () => {
    it("should reject if no Authorization header", async () => {
      const res = await request(app).get("/api/protected-data");
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("No auth");
    });
    it("should reject if invalid token", async () => {
      const res = await request(app)
        .get("/api/protected-data")
        .set("Authorization", "Bearer invalidtoken");
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Invalid token");
    });
    it("should return hello:world and user for valid apiToken", async () => {
      // Store a session and get apiToken
      await request(app)
        .post("/cli/store-session")
        .set("Authorization", `Bearer ${NEXTJS_TO_EXPRESS_SECRET}`)
        .send({ token: "tok789", user: { email: "user3@example.com" } });
      const statusRes = await request(app).get(
        "/cli/session-status?token=tok789"
      );
      const apiToken = statusRes.body.apiToken;
      const res = await request(app)
        .get("/api/protected-data")
        .set("Authorization", `Bearer ${apiToken}`);
      expect(res.status).toBe(200);
      expect(res.body.hello).toBe("world");
      expect(res.body.user.email).toBe("user3@example.com");
    });
  });
});
