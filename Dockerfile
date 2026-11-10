FROM denoland/deno:2.9.6

WORKDIR /app
USER deno
COPY main.ts deno.json ./
COPY src/server.ts ./src/
RUN deno cache main.ts

ENV PORT=8080
EXPOSE 8080
CMD ["run", "--allow-net", "--allow-env", "main.ts"]
