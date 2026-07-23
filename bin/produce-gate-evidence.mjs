import path from "node:path";
import { fileURLToPath } from "node:url";
import { produceGateEvidence } from "../lib/harness.mjs";

/** 将成对 CLI 参数解析为封闭选项对象。 */
function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || values.has(key)) {
      throw new Error("GateHarness 参数必须是唯一的 --key value 对。\n");
    }
    values.set(key, value);
  }
  const required = [
    "--artifact-directory",
    "--base-oid",
    "--candidate-root",
    "--controller-repository",
    "--head-oid",
    "--object-format",
    "--provider-repository-id",
    "--trusted-record",
    "--workflow-file",
    "--workflow-sha",
  ];
  if (values.size !== required.length || required.some((key) => !values.has(key))) {
    throw new Error("GateHarness 参数缺失或包含未知字段。\n");
  }
  return {
    artifactDirectory: path.resolve(values.get("--artifact-directory")),
    baseOid: values.get("--base-oid"),
    candidateRoot: path.resolve(values.get("--candidate-root")),
    controllerRepository: values.get("--controller-repository"),
    headOid: values.get("--head-oid"),
    objectFormat: values.get("--object-format"),
    providerRepositoryId: values.get("--provider-repository-id"),
    trustedRecordPath: path.resolve(values.get("--trusted-record")),
    workflowFile: values.get("--workflow-file"),
    workflowSha: values.get("--workflow-sha"),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await produceGateEvidence(parseArguments(process.argv.slice(2)));
    console.log(
      JSON.stringify({
        artifactDigest: result.artifactDigest,
        evidenceCount: result.artifact.evidence.length,
        passed: result.passed,
      }),
    );
    process.exitCode = result.passed ? 0 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "GateHarness 发生未知错误。");
    process.exitCode = 1;
  }
}
