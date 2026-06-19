import request from "supertest";
import { describe, expect, it } from "vitest";
import express from "express";

describe("Integration skeleton", () => {
  it("responds from health endpoint", async () => {
    const app = express();
    app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

    const response = await request(app).get("/health");
    expect(response.status).toBe(200);
    expect(response.body.ok).toBe(true);
  });
});
