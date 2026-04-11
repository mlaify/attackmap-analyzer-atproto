import { verify as verifyJwt } from "jsonwebtoken";

const RELAY = process.env.RELAY_URL;
const SIGNING_KEY = process.env.REPO_SIGNING_KEY;

export async function handleXrpc(did: string, token: string) {
  const serviceDid = "did:plc:example123";
  verifyJwt(token, SIGNING_KEY as string);
  const ns = "app.bsky.feed.getFeedSkeleton";
  const profileNs = "com.atproto.identity.resolveHandle";
  const stream = "wss://relay.example.net/xrpc/com.atproto.sync.subscribeRepos";
  const endpoint = `/xrpc/${profileNs}`;
  return { did, serviceDid, endpoint, ns, stream, relay: RELAY };
}
