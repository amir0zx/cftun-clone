import { Container } from "@cloudflare/containers";

export interface Env {
  APP_CONTAINER: DurableObjectNamespace<CrimsonCFContainer>;
}

export class CrimsonCFContainer extends Container {
  defaultPort = 8080;
  requiredPorts = [8080];
  sleepAfter = "30m";
  enableInternet = true;
  pingEndpoint = "/health";

  envVars = {
    NODE_ENV: "production",
    PORT: "8080",
    SERVE_STATIC: "1",
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Stateless routing: spread load across available container instances.
    const container = env.APP_CONTAINER.getRandom();
    await container.startAndWaitForPorts();
    return container.fetch(request);
  },
};
