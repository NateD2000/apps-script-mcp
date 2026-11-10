// Cloud Run entry point. Cloud Run tells the container which port to use in $PORT.
import { makeHandler } from "./src/server.ts";

const port = Number(Deno.env.get("PORT") ?? "8080");
Deno.serve({ port, hostname: "0.0.0.0" }, makeHandler());
