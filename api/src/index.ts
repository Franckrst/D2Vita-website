import type { Env } from "./env";
import { handle } from "./router";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handle(request, env, ctx, Math.floor(Date.now() / 1000));
  },
} satisfies ExportedHandler<Env>;
