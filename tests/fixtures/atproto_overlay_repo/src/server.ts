import type { Server } from "./lexicon";
import type { AppContext } from "./context";

// Pagination constants that look like secret names.
const SORT_KEY = "KEY";
const CURSOR_KIND = 'TOKEN';

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.feed.getTimeline({
    auth: ctx.authVerifier.standard,
    handler: async ({ params, auth }) => {
      const viewer = auth.credentials.iss;
      return { encoding: "application/json", body: { viewer, opts: { auth: null } } };
    },
  });

  server.method("sh.tangled.repo.create", async (_reqCtx: unknown) => {
    return { encoding: "application/json", body: { ok: true } };
  });

  server.method("app.bsky.feed.getPostThread", {
    auth: ctx.authVerifier.optionalStandard,
    handler: async () => ({ encoding: "application/json", body: {} }),
  });

  const jwtSecret = process.env.PDS_JWT_SECRET;
  // Sign in to verify your account; the plc acronym here is prose.
  return { jwtSecret };
}
