/** 验证 provider repository、ruleset、required check source 与 bypass 均未漂移。 */
export function evaluateProviderDrift({
  controllerAppId,
  expectedRepositoryId,
  repository,
  rulesets,
}) {
  const issues = [];
  if (`${repository?.id ?? ""}` !== `${expectedRepositoryId}`) {
    issues.push("repository-id-drift");
  }
  if (repository?.default_branch !== "main") {
    issues.push("default-branch-drift");
  }
  if (repository?.visibility !== "public") {
    issues.push("visibility-drift");
  }
  const matching = rulesets.filter((ruleset) => ruleset.name === "architecture-required");
  if (matching.length !== 1) {
    issues.push("ruleset-count-drift");
    return { issues, status: "invalid" };
  }
  const ruleset = matching[0];
  if (ruleset.enforcement !== "active" || ruleset.target !== "branch") {
    issues.push("ruleset-enforcement-drift");
  }
  if (!Array.isArray(ruleset.bypass_actors) || ruleset.bypass_actors.length !== 0) {
    issues.push("ruleset-bypass-drift");
  }
  const include = ruleset.conditions?.ref_name?.include;
  const exclude = ruleset.conditions?.ref_name?.exclude;
  if (
    !Array.isArray(include) ||
    !include.includes("refs/heads/main") ||
    !Array.isArray(exclude) ||
    exclude.length !== 0
  ) {
    issues.push("ruleset-target-drift");
  }
  const statusRule = ruleset.rules?.find((rule) => rule.type === "required_status_checks");
  const requiredChecks = statusRule?.parameters?.required_status_checks;
  const matchingChecks = Array.isArray(requiredChecks)
    ? requiredChecks.filter(
        (check) =>
          check.context === "architecture-required" &&
          `${check.integration_id ?? ""}` === `${controllerAppId}`,
      )
    : [];
  if (
    matchingChecks.length !== 1 ||
    statusRule?.parameters?.strict_required_status_checks_policy !== true
  ) {
    issues.push("required-check-drift");
  }
  return {
    issues,
    status: issues.length === 0 ? "valid" : "invalid",
  };
}
