/// <reference types="node" resolution-mode="require"/>
import type { Peer } from "@lumeweb/peer-discovery";
declare const _default: (pubkey: Buffer, options?: {
    host: string;
}) => Promise<boolean | Peer>;
export default _default;
