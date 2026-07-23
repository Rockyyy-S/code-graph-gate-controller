import assert from "node:assert/strict";
import test from "node:test";
import { evaluateProviderDrift } from "../lib/drift-policy.mjs";

/** 创建符合 Story 1.3 provider 不变量的 ruleset fixture。 */
function createFixture() {
  return {
    controllerAppId: "12345",
    expectedRepositoryId: "1303415307",
    repository: {
      default_branch: "main",
      id: 1303415307,
      visibility: "public",
    },
    rulesets: [
      {
        bypassActorCount: 0,
        conditions: {
          ref_name: { exclude: [], include: ["refs/heads/main"] },
        },
        enforcement: "active",
        name: "architecture-required",
        rules: [
          {
            parameters: {
              required_status_checks: [
                { context: "architecture-required", integration_id: 12345 },
              ],
              strict_required_status_checks_policy: true,
            },
            type: "required_status_checks",
          },
        ],
        target: "branch",
      },
    ],
  };
}

test("drift monitor 接受 active、strict、无 bypass 且绑定 Controller App 的 ruleset", () => {
  assert.deepEqual(evaluateProviderDrift(createFixture()), { issues: [], status: "valid" });
});

test("ruleset、App identity、bypass、branch 或 repository 漂移均 invalid", () => {
  const mutations = [
    (fixture) => (fixture.repository.id = 1),
    (fixture) => (fixture.repository.default_branch = "develop"),
    (fixture) => (fixture.rulesets[0].bypassActorCount = 1),
    (fixture) => (fixture.rulesets[0].enforcement = "disabled"),
    (fixture) =>
      (fixture.rulesets[0].rules[0].parameters.required_status_checks[0].integration_id = 999),
  ];
  for (const mutate of mutations) {
    const fixture = createFixture();
    mutate(fixture);
    assert.equal(evaluateProviderDrift(fixture).status, "invalid");
  }
});
