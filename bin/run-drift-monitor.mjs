import { evaluateProviderDrift } from "../lib/drift-policy.mjs";
import { githubJson } from "../lib/github-api.mjs";

const targetRepository = process.env.TARGET_REPOSITORY ?? "Rockyyy-S/code-graph";
const expectedRepositoryId = process.env.TARGET_REPOSITORY_ID ?? "1303415307";
const controllerAppId = process.env.CONTROLLER_APP_ID;

if (!/^[1-9][0-9]*$/u.test(controllerAppId ?? "")) {
  throw new Error("CONTROLLER_APP_ID 缺失或非法。\n");
}

const repository = await githubJson(`repos/${targetRepository}`);
const summaries = await githubJson(`repos/${targetRepository}/rulesets?includes_parents=false`);
const detailedRulesets = await Promise.all(
  summaries.map(({ id }) => githubJson(`repos/${targetRepository}/rulesets/${id}`)),
);
const result = evaluateProviderDrift({
  controllerAppId,
  expectedRepositoryId,
  repository,
  rulesets: detailedRulesets,
});
console.log(JSON.stringify(result));
process.exitCode = result.status === "valid" ? 0 : 1;
