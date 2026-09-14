import type { Env } from "./env";
import { error } from "./http";

export default {
  async fetch(_request: Request, _env: Env, _ctx: ExecutionContext): Promise<Response> {
    return error(404, "not_found", "No such route");
  },
} satisfies ExportedHandler<Env>;
