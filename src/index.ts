import type { Peer } from "@lumeweb/peer-discovery";
import { IrcClient } from "@ctrl/irc";
import jsonStringify from "json-stringify-deterministic";
import b4a from "b4a";
import * as ed from "@noble/ed25519";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

const hash160 = (data: Uint8Array) => ripemd160(sha256(data));

interface SignedPeerResponse extends Peer {
  timestamp: number;
  signature?: string;
}

export default async (
  pubkey: Buffer,
  options = { host: "irc.liberta.casa" }
): Promise<boolean | Peer> => {
  let ircPubKey = await ed.getPublicKey(ed.utils.randomPrivateKey());

  let client = new IrcClient(
    undefined,
    bytesToHex(hash160(ircPubKey)).substring(0, 15),
    {
      host: options.host,
      port: 6697,
      secure: true,
      channels: ["#lumeweb"],
      realName: "lumeweb-client",
    }
  );

  client.connect();

  await new Promise((resolve) => {
    client.once("join", resolve);
  });

  client.say("#lumeweb", b4a.toBuffer(pubkey).toString("hex"));

  return new Promise<Peer>((resolve, reject) => {
    client.on("pm", async (from: string, text: string) => {
      let json: SignedPeerResponse;
      try {
        json = JSON.parse(text);
      } catch {
        return;
      }

      const verifyData = {
        host: json.host,
        port: json.port,
        timestamp: json.timestamp,
      };

      const verifyPayload = jsonStringify(verifyData);
      if (
        !(await ed.verify(
          b4a.from(json.signature, "hex"),
          b4a.from(verifyPayload),
          pubkey
        ))
      ) {
        return;
      }

      client.end();
      resolve({ host: json.host, port: json.port });
    });
  });
};
