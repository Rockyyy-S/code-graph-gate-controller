import { evaluateProviderDrift } from "../lib/drift-policy.mjs";
import { githubGraphql, githubJson } from "../lib/github-api.mjs";

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
const [owner, repositoryName, ...extraSegments] = targetRepository.split("/");
if (!owner || !repositoryName || extraSegments.length > 0) {
  throw new Error("TARGET_REPOSITORY 必须是 owner/repository。\n");
}
const graphql = await githubGraphql(
  `query RulesetBypassActors($owner: String!, $repository: String!) {
    repository(owner: $owner, name: $repository) {
      databaseId
      rulesets(first: 100, includeParents: false) {
        nodes {
          databaseId
          bypassActors(first: 100) {
            totalCount
          }
        }
      }
    }
  }`,
  { owner, repository: repositoryName },
);
if (`${graphql?.repository?.databaseId ?? ""}` !== expectedRepositoryId) {
  throw new Error("GraphQL repository ID 与预期 provider repository 不一致。\n");
}
const bypassCounts = new Map(
  graphql.repository.rulesets.nodes.map((ruleset) => [
    `${ruleset.databaseId}`,
    ruleset.bypassActors.totalCount,
  ]),
);
const result = evaluateProviderDrift({
  controllerAppId,
  expectedRepositoryId,
  repository,
  rulesets: detailedRulesets.map((ruleset) => ({
    ...ruleset,
    bypassActorCount: bypassCounts.get(`${ruleset.id}`),
  })),
});
console.log(JSON.stringify(result));
process.exitCode = result.status === "valid" ? 0 : 1;
