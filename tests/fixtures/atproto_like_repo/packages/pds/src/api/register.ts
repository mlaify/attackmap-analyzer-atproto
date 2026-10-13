import type { Server } from "@atproto/xrpc-server";
import type { AppContext } from "../context";
import { com } from "../lexicons";

export default function (server: Server, ctx: AppContext) {
  server.add(com.atproto.server.createSession, {
    rateLimit: { durationMs: 86400000, points: 300 },
    handler: async ({ input }) => ctx.accountManager.login(input.body),
  });

  server.add(com.atproto.sync.subscribeRepos, {
    auth: ctx.authVerifier.adminToken,
    handler: async function* ({ params }) {
      yield* ctx.sequencer.stream(params.cursor);
    },
  });
}
