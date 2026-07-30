import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";

/** Windows taskkill 在高进程负载下需要更长的有界树清理窗口。 */
export const DEFAULT_PROCESS_CLEANUP_GRACE_MS =
  process.platform === "win32" ? 10_000 : 2_000;
const MAX_NODE_TIMER_MS = 2_147_483_647;
const WINDOWS_JOB_CONTROL_START = Buffer.from([0x1e]);
const WINDOWS_JOB_CONTROL_END = Buffer.from([0x1f]);
const WINDOWS_JOB_CONTROL_TAIL_BYTES = 4 * 1024;
const WINDOWS_JOB_SHELL_EXECUTABLE = "pwsh.exe";

/**
 * Windows Job host 保留可审计源码与预编译程序集，避免每个短进程重复启动 Roslyn 编译。
 * 程序集由同一对象的 source 编译，摘要在 helper 加载前再次校验。
 */
const WINDOWS_JOB_HOST_ARTIFACT = Object.freeze({
  assemblyBase64: "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAHXBamoAAAAAAAAAAOAAAiELAQsAACAAAAAGAAAAAAAAPj4AAAAgAAAAQAAAAAAAEAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAPA9AABLAAAAAEAAAOACAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAARB4AAAAgAAAAIAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAOACAAAAQAAAAAQAAAAiAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAJgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAgPgAAAAAAAEgAAAACAAUAjCcAAGQWAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABswBQBlAAAAAQAAEQDQBgAAAigFAAAKKAYAAAoKBigHAAAKCwACFwcGEgIoBAAABhMFEQUtDAAoCAAACnMJAAAKegfQBgAAAigFAAAKKAoAAAqlBgAAAg0SA3suAAAEEwTeCgAHKAsAAAoAANwAEQQqAAAAARAAAAIAGAA/VwAKAAAAABMwAgBEAAAAAgAAEQAoDAAACgorNgACKA8AAAYW/gEW/gELBy0DACsmBm8NAAAKA2r+BAsHLQwAcgEAAHBzDgAACnobKA8AAAoAABcLK8YqGzADANgAAAADAAARAAMoEAAACi0IAygRAAAKKwEWABMFEQUtCQAWEwQ4sgAAAAADKBIAAAooEwAACm8UAAAKCgDeCiYAFhME3ZMAAAAABhIBKBUAAAosCQcW/gEW/gErARYAEwURBS0MAHJtAABwcxYAAAp6IAAQAAAWBygIAAAGDAh+FwAACigYAAAKFv4BEwURBS0MACgIAAAKcwkAAAp6AAgCEgMoBgAABhMFEQUtDAAoCAAACnMJAAAKegkTBREFLQwAcr8AAHBzGQAACnoHEwTeCgAIKA4AAAYmANwAEQQqARwAAAAAIgAVNwAKFgAAAQIAlgA0ygAKAAAAABMwBAA2AAAABAAAEQAoGgAACnIdAQBwAnIhAQBwKBsAAApvHAAACgooHQAACgsHBhYGjmlvHgAACgAHbx8AAAoAKgAAGzAKALEEAAAFAAARAH4XAAAKFCgCAAAGCgZ+FwAACigYAAAKFv4BExERES0MACgIAAAKcwkAAAp6EgH+FQQAAAIWDAASA/4VCAAAAhIDfDYAAAQgACAAAH0hAAAE0AgAAAIoBQAACigGAAAKEwQRBCgHAAAKEwUACREFFigBAAArAAYfCREFEQQoAwAABhMREREtDAAoCAAACnMJAAAKegDeCwARBSgLAAAKAADcABIG/hUDAAACEgbQAwAAAigFAAAKKAYAAAp9CQAABBIGIAABAAB9FAAABBIGH/YoDQAABn0YAAAEEgYf9SgNAAAGfRkAAAQSBh/0KA0AAAZ9GgAABAIoEAAACi0DAisBFAADcyEAAAp+FwAACn4XAAAKFyAEBAAAfhcAAAoEEgYSASgBAAAGExERES0MACgIAAAKcwkAAAp6FwwGEgF7GwAABCgFAAAGExERES0MACgIAAAKcwkAAAp6EgF7GwAABAYSBygGAAAGLAQRBysBFgATERERLQwAKAgAAApzCQAACnoGKA8AAAYTCBEIF/4BExERES0MAHIlAQBwcxkAAAp6HI0PAAABExIREhZyhQEAcKIREhcFohESGHK/AQBwohESGRIBfB0AAAQoIgAACqIREhpyvwEAcKIREhsSCCgiAAAKohESKCMAAAooEgAABgASAXscAAAEKAkAAAYV/gEW/gETERERLQwAKAgAAApzCQAACnooDAAAChMJFhMKFhMLFhMMOJAAAAAAEQwW/gEW/gETERERLQwABg4GKBEAAAYTDAAfCmoXag4EahEJbw0AAApZKCQAAAooJQAACm0TDRIBexsAAAQRDSgKAAAGEw4RDhb+ARb+ARMREREtBgAXEwsrPBEOIAIBAAD+ARMREREtDAAoCAAACnMJAAAKehEJbw0AAAoOBGr+BBMREREtBgAXEworCQAXExE4aP///xEMFv4BFv4BExERES0MAAYOBigRAAAGEwwADgYoEAAACi0KEQwW/gEW/gErARcAExERES0MAHLDAQBwcxkAAAp6FxMPEQssEBIBexsAAAQSDygLAAAGKwEXABMREREtDAAoCAAACnMJAAAKegYoDwAABhY2EwYRCi0EEQ8rAh98ACgHAAAGKwEXABMREREtDAAoCAAACnMJAAAKegYOBSgQAAAGAB8KjQ8AAAETEhESFnIhAgBwohESFwWiERIYcr8BAHCiERIZEQotB3JhAgBwKwVyawIAcACiERIacr8BAHCiERIbEg8oIgAACqIREhxyewIAcKIREh0SAXwdAAAEKCIAAAqiERIecr8BAHCiERIfCRIMKCIAAAqiERIoIwAACigSAAAGABYTEN23AAAAJgAILBYSAXsbAAAEfhcAAAooJgAAChb+ASsBFwATERERLTYAAAYoDwAABhb+Axb+ARMREREtCgAGFygHAAAGJgAA3hMmABIBexsAAAQXKAwAAAYmAN4AAAD+GgASAXscAAAEfhcAAAooJgAAChb+ARMREREtDwASAXscAAAEKA4AAAYmABIBexsAAAR+FwAACigmAAAKFv4BExERES0PABIBexsAAAQoDgAABiYABigOAAAGJgDcABEQKgAAAEFkAAACAAAAawAAACwAAACXAAAACwAAAAAAAAAAAAAAGgQAACAAAAA6BAAAEwAAAAEAAAEAAAAANwAAAL8DAAD2AwAAWwAAAAEAAAECAAAANwAAABoEAABRBAAAXAAAAAAAAABCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAAAcBwAAI34AAIgHAACICgAAI1N0cmluZ3MAAAAAEBIAAIQCAAAjVVMAlBQAABAAAAAjR1VJRAAAAKQUAADAAQAAI0Jsb2IAAAAAAAAAAgAAAVcdAhQJCgAAAPolMwAWAAABAAAAGwAAAAgAAAA7AAAAEwAAADUAAAAnAAAACAAAAAIAAAAFAAAAAQAAAA4AAAABAAAAAgAAAAYAAAABAAAAAAAKAAEAAAAAAAYA6ADhAAYA7wDhAAYArwGjAQYApwaIBgYA2ge6BwYA+ge6BwYAGAiIBgYAOAjhAAYAPQjhAAYAYQiIBgoApQiPCAoA4gjPCAYADQnhAAYALwkeCQYAPAnhAAYAWwlRCQYAZwmjAQYAignhAAoAmglRCQYArwnhAAYAxwnhAAYA4QlRCQYABwrhAAYADwpRCQYATArhAAYAZwqIBgYAfQqIBgAAAAABAAAAAAABAAEAgQEQACYAAAAFAAEAAQALARAAPgAAAAkACQAUAAsBEABKAAAACQAbABQACwEQAF4AAAAJAB8AFAALARAAgAAAAAkAKAAUAAsBEACnAAAACQAwABQACwEQALMAAAAJADYAFABRgPkACgBRgAoBCgBRgCUBCgBRgC4BCgBRgFEBCgBRgHMBCgBRgIgBCgBRgJYBCgAGAAYDCgAGAAkDswAGABQDswAGAB4DswAGACYDCgAGACoDCgAGAC4DCgAGADYDCgAGAD4DCgAGAEwDCgAGAFoDCgAGAGoDCgAGAHIDtgAGAH4DtgAGAIoDuQAGAJYDuQAGAKADuQAGAKsDuQAGALUDuQAGAL4DuQAGAMYDCgAGANIDCgAGAN0DvAAGAPUDvAAGAAkECgAGABQEvwAGACoEvwAGAEAECgAGAFMEvwAGAFwECgAGAGoECgAGAHoEvAAGAIgEvAAGAJgEvAAGALAEvAAGAMoECgAGAN4ECgAGAO0ECgAGAP0ECgAGABYFwgAGACkFwgAGAD0FwgAGAFEFwgAGAGMFwgAGAHYFwgAGAIkFxQAGAJ8FyQAGAKYFvwAGALkFvwAGAMgFvwAGAN4FvwAAAAAAgACRIL0BNQABAAAAAACAAJEgzAFIAAsAAAAAAIAAkSDcAU4ADQAAAAAAgACRIPQBVgARAAAAAACAAJEgDgJgABYAAAAAAIAAkSAnAmYAGAAAAAAAgACRIDYCbgAbAAAAAACAAJEgSQJ0AB0AAAAAAIAAkSBVAnsAIAAAAAAAgACRIGICgAAhAAAAAACAAJEgdgKGACMAAAAAAIAAkSCJAm4AJQAAAAAAgACRIJoCjQAnAAAAAACAAJEgpwKSACgAUCAAAAAAkQCzAnsAKQDUIAAAAACRAMgClwAqACQhAAAAAJEA4QKdACwAJCIAAAAAkQD1AqMALgBoIgAAAACWAAIDqAAvAAAAAQDwBQAAAgAABgAAAwAMBgAABAAeBgAABQAvBgAABgA+BgAABwBMBgAACABYBgAACQBpBgIACgB1BgAAAQC6BgAAAgDIBgAAAQDNBgAAAgDRBgAAAwDiBgAABADuBgAAAQDNBgAAAgDRBgAAAwDiBgAABADuBgIABQAABwAAAQDNBgAAAgANBwAAAQANBwAAAgDNBgIAAwAVBwAAAQDNBgAAAgAcBwAAAQAlBwAAAgAzBwAAAwBBBwAAAQBLBwAAAQBSBwAAAgBZBwAAAQANBwIAAgAcBwAAAQANBwAAAgAcBwAAAQBmBwAAAQBSBwAAAQDNBgAAAQDNBgAAAgB1BwAAAQDNBgAAAgB/BwAAAQCJBwAAAQDwBQAAAgAABgAAAwBYBgAABACPBwAABQB1BwAABgCVBwAABwCmByEAtAbNACkAtAbRADEAtAbNADkAtAbWAEEATwjbAFEAaQjiAFEAcAiNAFEAfQjoAFkAtAbRAFEAtAjsAFEAwwjzAGEA7AgCAWEA9QgHAWkAtAbWAHEANgkLAXkAQwkWAYEAYAkWAYkAcAkbAYEAeQkgAXkAhQknAZEAkQkrAZkAtAbWAKEAtgm5AKEAuwlgAKkAtAbWAIkA7QkbAXkA9wk7AYkA/glCAbkAFgpIAcEAKApNAcEALgrNAFEANApcARkAtAbWAJEAQwonAXkA9wlqAckAUQpwAckAVQpwAaEAWQpgANEAtAaRAQkABAANAAkACAASAAkADAAXAAkAEAAcAAkAFAAhAAkAGAAmAAkAHAArAAkAIAAwAC4AEwCXAS4AGwCgAfgAEAEyAVUBdgErCEQBAwC9AQEAQAEFAMwBAQBAAQcA3AEBAEABCQD0AQEAQAELAA4CAQBAAQ0AJwIBAEABDwA2AgEAQAERAEkCAQBAARMAVQIBAEABFQBiAgEAQAEXAHYCAQBAARkAiQIBAAABGwCaAgEAAAEdAKcCAQAEgAAAAAAAAAAAAAAAAAAAAAAmAAAABAAAAAAAAAAAAAAAAQDYAAAAAAAEAAAAAAAAAAAAAAABAOEAAAAAAAMAAgAEAAIABQACAAYAAgAHAAIACAACAEEAZQEAAAA8TW9kdWxlPgBDb2RlR3JhcGhXaW5kb3dzSm9iSG9zdC5kbGwAQ29kZUdyYXBoV2luZG93c0pvYkhvc3QAU1RBUlRVUElORk8AUFJPQ0VTU19JTkZPUk1BVElPTgBKT0JPQkpFQ1RfQkFTSUNfTElNSVRfSU5GT1JNQVRJT04ASk9CT0JKRUNUX0JBU0lDX0FDQ09VTlRJTkdfSU5GT1JNQVRJT04ASU9fQ09VTlRFUlMASk9CT0JKRUNUX0VYVEVOREVEX0xJTUlUX0lORk9STUFUSU9OAG1zY29ybGliAFN5c3RlbQBPYmplY3QAVmFsdWVUeXBlAENSRUFURV9TVVNQRU5ERUQAQ1JFQVRFX1VOSUNPREVfRU5WSVJPTk1FTlQASU5GSU5JVEUASk9CX09CSkVDVF9MSU1JVF9LSUxMX09OX0pPQl9DTE9TRQBQUk9DRVNTX1FVRVJZX0xJTUlURURfSU5GT1JNQVRJT04AU1RBUlRGX1VTRVNUREhBTkRMRVMAV0FJVF9PQkpFQ1RfMABXQUlUX1RJTUVPVVQAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBDcmVhdGVQcm9jZXNzVwBDcmVhdGVKb2JPYmplY3QAU2V0SW5mb3JtYXRpb25Kb2JPYmplY3QAUXVlcnlJbmZvcm1hdGlvbkpvYk9iamVjdABBc3NpZ25Qcm9jZXNzVG9Kb2JPYmplY3QASXNQcm9jZXNzSW5Kb2IAVGVybWluYXRlSm9iT2JqZWN0AE9wZW5Qcm9jZXNzAFJlc3VtZVRocmVhZABXYWl0Rm9yU2luZ2xlT2JqZWN0AEdldEV4aXRDb2RlUHJvY2VzcwBUZXJtaW5hdGVQcm9jZXNzAEdldFN0ZEhhbmRsZQBDbG9zZUhhbmRsZQBRdWVyeUFjdGl2ZVByb2Nlc3NlcwBXYWl0Rm9yQWN0aXZlUHJvY2Vzc1plcm8AVHJ5QXR0ZXN0RGVzY2VuZGFudABXcml0ZUNvbnRyb2wAUnVuAGNiAGxwUmVzZXJ2ZWQAbHBEZXNrdG9wAGxwVGl0bGUAZHdYAGR3WQBkd1hTaXplAGR3WVNpemUAZHdYQ291bnRDaGFycwBkd1lDb3VudENoYXJzAGR3RmlsbEF0dHJpYnV0ZQBkd0ZsYWdzAHdTaG93V2luZG93AGNiUmVzZXJ2ZWQyAGxwUmVzZXJ2ZWQyAGhTdGRJbnB1dABoU3RkT3V0cHV0AGhTdGRFcnJvcgBoUHJvY2VzcwBoVGhyZWFkAGR3UHJvY2Vzc0lkAGR3VGhyZWFkSWQAUGVyUHJvY2Vzc1VzZXJUaW1lTGltaXQAUGVySm9iVXNlclRpbWVMaW1pdABMaW1pdEZsYWdzAE1pbmltdW1Xb3JraW5nU2V0U2l6ZQBNYXhpbXVtV29ya2luZ1NldFNpemUAQWN0aXZlUHJvY2Vzc0xpbWl0AEFmZmluaXR5AFByaW9yaXR5Q2xhc3MAU2NoZWR1bGluZ0NsYXNzAFRvdGFsVXNlclRpbWUAVG90YWxLZXJuZWxUaW1lAFRoaXNQZXJpb2RUb3RhbFVzZXJUaW1lAFRoaXNQZXJpb2RUb3RhbEtlcm5lbFRpbWUAVG90YWxQYWdlRmF1bHRDb3VudABUb3RhbFByb2Nlc3NlcwBBY3RpdmVQcm9jZXNzZXMAVG90YWxUZXJtaW5hdGVkUHJvY2Vzc2VzAFJlYWRPcGVyYXRpb25Db3VudABXcml0ZU9wZXJhdGlvbkNvdW50AE90aGVyT3BlcmF0aW9uQ291bnQAUmVhZFRyYW5zZmVyQ291bnQAV3JpdGVUcmFuc2ZlckNvdW50AE90aGVyVHJhbnNmZXJDb3VudABCYXNpY0xpbWl0SW5mb3JtYXRpb24ASW9JbmZvAFByb2Nlc3NNZW1vcnlMaW1pdABKb2JNZW1vcnlMaW1pdABQZWFrUHJvY2Vzc01lbW9yeVVzZWQAUGVha0pvYk1lbW9yeVVzZWQAYXBwbGljYXRpb25OYW1lAGNvbW1hbmRMaW5lAHByb2Nlc3NBdHRyaWJ1dGVzAHRocmVhZEF0dHJpYnV0ZXMAaW5oZXJpdEhhbmRsZXMAY3JlYXRpb25GbGFncwBlbnZpcm9ubWVudABjdXJyZW50RGlyZWN0b3J5AHN0YXJ0dXBJbmZvAHByb2Nlc3NJbmZvcm1hdGlvbgBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAT3V0QXR0cmlidXRlAC5jdG9yAGpvYkF0dHJpYnV0ZXMAbmFtZQBqb2IAaW5mb3JtYXRpb25DbGFzcwBpbmZvcm1hdGlvbgBpbmZvcm1hdGlvbkxlbmd0aAByZXR1cm5MZW5ndGgAcHJvY2VzcwByZXN1bHQAZXhpdENvZGUAZGVzaXJlZEFjY2VzcwBpbmhlcml0SGFuZGxlAHByb2Nlc3NJZAB0aHJlYWQAaGFuZGxlAG1pbGxpc2Vjb25kcwBzdGFuZGFyZEhhbmRsZQB0aW1lb3V0TXMAcmVhZHlQYXRoAHZhbHVlAG5vbmNlAGNsZWFudXBUaW1lb3V0TXMAZGVzY2VuZGFudFJlYWR5UGF0aABTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUARGxsSW1wb3J0QXR0cmlidXRlAGtlcm5lbDMyLmRsbABUeXBlAFJ1bnRpbWVUeXBlSGFuZGxlAEdldFR5cGVGcm9tSGFuZGxlAE1hcnNoYWwAU2l6ZU9mAEFsbG9jSEdsb2JhbABHZXRMYXN0V2luMzJFcnJvcgBTeXN0ZW0uQ29tcG9uZW50TW9kZWwAV2luMzJFeGNlcHRpb24AUHRyVG9TdHJ1Y3R1cmUARnJlZUhHbG9iYWwAU3lzdGVtLkRpYWdub3N0aWNzAFN0b3B3YXRjaABTdGFydE5ldwBnZXRfRWxhcHNlZE1pbGxpc2Vjb25kcwBUaW1lb3V0RXhjZXB0aW9uAFN5c3RlbS5UaHJlYWRpbmcAVGhyZWFkAFNsZWVwAFN0cmluZwBJc051bGxPckVtcHR5AFN5c3RlbS5JTwBGaWxlAEV4aXN0cwBFbmNvZGluZwBnZXRfVVRGOABSZWFkQWxsVGV4dABUcmltAFVJbnQzMgBUcnlQYXJzZQBJbnZhbGlkRGF0YUV4Y2VwdGlvbgBJbnRQdHIAWmVybwBvcF9FcXVhbGl0eQBJbnZhbGlkT3BlcmF0aW9uRXhjZXB0aW9uAElPRXhjZXB0aW9uAGdldF9BU0NJSQBDb25jYXQAR2V0Qnl0ZXMAQ29uc29sZQBTdHJlYW0AT3BlblN0YW5kYXJkRXJyb3IAV3JpdGUARmx1c2gAU3RydWN0dXJlVG9QdHIAVG9TdHJpbmcATWF0aABNYXgATWluAG9wX0luZXF1YWxpdHkAU3RydWN0TGF5b3V0QXR0cmlidXRlAExheW91dEtpbmQAAGtXAGkAbgBkAG8AdwBzACAASgBvAGIAIABBAGMAdABpAHYAZQBQAHIAbwBjAGUAcwBzAGUAcwAgAGQAaQBkACAAbgBvAHQAIABjAG8AbgB2AGUAcgBnAGUAIAB0AG8AIAB6AGUAcgBvAC4AAFFXAGkAbgBkAG8AdwBzACAAZABlAHMAYwBlAG4AZABhAG4AdAAgAHIAZQBhAGQAeQAgAFAASQBEACAAaQBzACAAaQBuAHYAYQBsAGkAZAAuAABdVwBpAG4AZABvAHcAcwAgAGQAZQBzAGMAZQBuAGQAYQBuAHQAIABpAHMAIABuAG8AdAAgAGEAcwBzAGkAZwBuAGUAZAAgAHQAbwAgAHQAaABlACAASgBvAGIALgAAAx4AAQMfAAFfVwBpAG4AZABvAHcAcwAgAEoAbwBiACAAaQBuAGkAdABpAGEAbAAgAEEAYwB0AGkAdgBlAFAAcgBvAGMAZQBzAHMAZQBzACAAaQBzACAAbgBvAHQAIABvAG4AZQAuAAA5QwBPAEQARQBHAFIAQQBQAEgAXwBXAEkATgBEAE8AVwBTAF8ASgBPAEIAXwBSAEUAQQBEAFkAOgAAAzoAAF1XAGkAbgBkAG8AdwBzACAAZABlAHMAYwBlAG4AZABhAG4AdAAgAHIAZQBhAGQAaQBuAGUAcwBzACAAdwBhAHMAIABuAG8AdAAgAGEAdAB0AGUAcwB0AGUAZAAuAAA/QwBPAEQARQBHAFIAQQBQAEgAXwBXAEkATgBEAE8AVwBTAF8ASgBPAEIAXwBUAEUAUgBNAEkATgBBAEwAOgAACWUAeABpAHQAAA90AGkAbQBlAG8AdQB0AAAHOgAwADoAAAAu7j1Yj9exQr1SF6xcQXxdAAi3elxWGTTgiQIGCQQEAAAABAAEAAAE/////wQAIAAABAAQAAAEAAEAAAQAAAAABAIBAAASAAoCDhINGBgCCRgOEBEMEBEQBQACGBgOBwAEAhgIGAkJAAUCGAgYCRAJBQACAhgYBwADAhgYEAIFAAICGAkGAAMYCQIJBAABCRgFAAIJGAkGAAICGBAJBAABGAgEAAECGAUAAgEYCAUAAgkYDgQAAQEOCgAHCA4ODg4ICA4CBg4CBgYCBhgCBgoCBhkCBgsDBhEUAwYRHAMgAAEEIAEBCAQgAQEOBgABEiERJQUAAQgSIQMAAAgGAAIcGBIhBAABARgJBwYIGAkRGAkCBAAAEjEDIAAKBAABAQgFBwISMQIEAAECDgQAABJFBgACDg4SRQMgAA4GAAICDhAJCAcGDgkYAgkCBgADDg4ODgUgAR0FDgQAABJhByADAR0FCAgGBwIdBRJhCBABAwEeABgCBAoBESAFAAEOHQ4FAAIKCgoaBxMYERACESAIGBEMAgkSMQICCQkJCQgCHQ4FIAEBEW0IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBABg+AAAAAAAAAAAAAC4+AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgPgAAAAAAAAAAX0NvckRsbE1haW4AbXNjb3JlZS5kbGwAAAAAAP8lACAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAQAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQABAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAASAAAAFhAAACEAgAAAAAAAAAAAACEAjQAAABWAFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAAAAAAAAAAAAAAAAAAAPwAAAAAAAAAEAAAAAgAAAAAAAAAAAAAAAAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEAbgBzAGwAYQB0AGkAbwBuAAAAAAAAALAE5AEAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAAwAEAAAEAMAAwADAAMAAwADQAYgAwAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAABYABwAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAEMAbwBkAGUARwByAGEAcABoAFcAaQBuAGQAbwB3AHMASgBvAGIASABvAHMAdAAuAGQAbABsAAAAKAACAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcAaAB0AAAAIAAAAGAAHAABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABDAG8AZABlAEcAcgBhAHAAaABXAGkAbgBkAG8AdwBzAEoAbwBiAEgAbwBzAHQALgBkAGwAbAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADAALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAADAAAAEA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
  assemblySha256: "117e213700c359895de604df9e22c4933103f311b8a9c1418e94181020988805",
  source: String.raw`
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class CodeGraphWindowsJobHost {
  private const uint CREATE_SUSPENDED = 0x00000004;
  private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
  private const uint INFINITE = 0xFFFFFFFF;
  private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
  private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
  private const uint STARTF_USESTDHANDLES = 0x00000100;
  private const uint WAIT_OBJECT_0 = 0x00000000;
  private const uint WAIT_TIMEOUT = 0x00000102;

  [StructLayout(LayoutKind.Sequential)]
  private struct STARTUPINFO {
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    public long PerProcessUserTimeLimit;
    public long PerJobUserTimeLimit;
    public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize;
    public UIntPtr MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public UIntPtr Affinity;
    public uint PriorityClass;
    public uint SchedulingClass;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
    public long TotalUserTime;
    public long TotalKernelTime;
    public long ThisPeriodTotalUserTime;
    public long ThisPeriodTotalKernelTime;
    public uint TotalPageFaultCount;
    public uint TotalProcesses;
    public uint ActiveProcesses;
    public uint TotalTerminatedProcesses;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct IO_COUNTERS {
    public ulong ReadOperationCount;
    public ulong WriteOperationCount;
    public ulong OtherOperationCount;
    public ulong ReadTransferCount;
    public ulong WriteTransferCount;
    public ulong OtherTransferCount;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit;
    public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed;
    public UIntPtr PeakJobMemoryUsed;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CreateProcessW(
    string applicationName,
    StringBuilder commandLine,
    IntPtr processAttributes,
    IntPtr threadAttributes,
    bool inheritHandles,
    uint creationFlags,
    IntPtr environment,
    string currentDirectory,
    ref STARTUPINFO startupInfo,
    out PROCESS_INFORMATION processInformation);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool SetInformationJobObject(
    IntPtr job,
    int informationClass,
    IntPtr information,
    uint informationLength);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool QueryInformationJobObject(
    IntPtr job,
    int informationClass,
    IntPtr information,
    uint informationLength,
    out uint returnLength);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern uint ResumeThread(IntPtr thread);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool TerminateProcess(IntPtr process, uint exitCode);

  [DllImport("kernel32.dll")]
  private static extern IntPtr GetStdHandle(int standardHandle);

  [DllImport("kernel32.dll")]
  private static extern bool CloseHandle(IntPtr handle);

  private static uint QueryActiveProcesses(IntPtr job) {
    int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
    IntPtr pointer = Marshal.AllocHGlobal(size);
    try {
      uint returned;
      if (!QueryInformationJobObject(job, 1, pointer, (uint)size, out returned)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting =
        (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(
          pointer,
          typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
      return accounting.ActiveProcesses;
    } finally {
      Marshal.FreeHGlobal(pointer);
    }
  }

  private static void WaitForActiveProcessZero(IntPtr job, int timeoutMs) {
    Stopwatch timer = Stopwatch.StartNew();
    while (true) {
      if (QueryActiveProcesses(job) == 0) { return; }
      if (timer.ElapsedMilliseconds >= timeoutMs) {
        throw new TimeoutException("Windows Job ActiveProcesses did not converge to zero.");
      }
      Thread.Sleep(5);
    }
  }

  private static uint TryAttestDescendant(IntPtr job, string readyPath) {
    if (String.IsNullOrEmpty(readyPath) || !File.Exists(readyPath)) { return 0; }
    string text;
    try {
      text = File.ReadAllText(readyPath, Encoding.UTF8).Trim();
    } catch (IOException) {
      return 0;
    }
    uint descendantPid;
    if (!UInt32.TryParse(text, out descendantPid) || descendantPid == 0) {
      throw new InvalidDataException("Windows descendant ready PID is invalid.");
    }
    IntPtr descendant = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, descendantPid);
    if (descendant == IntPtr.Zero) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    try {
      bool belongsToJob;
      if (!IsProcessInJob(descendant, job, out belongsToJob)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      if (!belongsToJob) {
        throw new InvalidOperationException("Windows descendant is not assigned to the Job.");
      }
      return descendantPid;
    } finally {
      CloseHandle(descendant);
    }
  }

  private static void WriteControl(string value) {
    byte[] bytes = Encoding.ASCII.GetBytes("\u001e" + value + "\u001f");
    Stream output = Console.OpenStandardError();
    output.Write(bytes, 0, bytes.Length);
    output.Flush();
  }

  public static int Run(
    string applicationName,
    string commandLine,
    string currentDirectory,
    string nonce,
    int timeoutMs,
    int cleanupTimeoutMs,
    string descendantReadyPath) {
    IntPtr job = CreateJobObject(IntPtr.Zero, null);
    if (job == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
    PROCESS_INFORMATION process = new PROCESS_INFORMATION();
    bool created = false;
    try {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      int limitSize = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
      IntPtr limitPointer = Marshal.AllocHGlobal(limitSize);
      try {
        Marshal.StructureToPtr(limits, limitPointer, false);
        if (!SetInformationJobObject(job, 9, limitPointer, (uint)limitSize)) {
          throw new Win32Exception(Marshal.GetLastWin32Error());
        }
      } finally {
        Marshal.FreeHGlobal(limitPointer);
      }

      STARTUPINFO startup = new STARTUPINFO();
      startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
      startup.dwFlags = STARTF_USESTDHANDLES;
      startup.hStdInput = GetStdHandle(-10);
      startup.hStdOutput = GetStdHandle(-11);
      startup.hStdError = GetStdHandle(-12);
      if (!CreateProcessW(
        String.IsNullOrEmpty(applicationName) ? null : applicationName,
        new StringBuilder(commandLine),
        IntPtr.Zero,
        IntPtr.Zero,
        true,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        IntPtr.Zero,
        currentDirectory,
        ref startup,
        out process)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      created = true;
      if (!AssignProcessToJobObject(job, process.hProcess)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      bool rootInJob;
      if (!IsProcessInJob(process.hProcess, job, out rootInJob) || !rootInJob) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      uint initialActiveProcesses = QueryActiveProcesses(job);
      if (initialActiveProcesses != 1) {
        throw new InvalidOperationException("Windows Job initial ActiveProcesses is not one.");
      }
      WriteControl(
        "CODEGRAPH_WINDOWS_JOB_READY:" + nonce + ":" +
        process.dwProcessId.ToString() + ":" + initialActiveProcesses.ToString());
      if (ResumeThread(process.hThread) == UInt32.MaxValue) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }

      Stopwatch execution = Stopwatch.StartNew();
      bool timedOut = false;
      bool rootExited = false;
      uint descendantPid = 0;
      while (true) {
        if (descendantPid == 0) {
          descendantPid = TryAttestDescendant(job, descendantReadyPath);
        }
        uint waitMs = (uint)Math.Min(10, Math.Max(1, timeoutMs - execution.ElapsedMilliseconds));
        uint wait = WaitForSingleObject(process.hProcess, waitMs);
        if (wait == WAIT_OBJECT_0) {
          rootExited = true;
          break;
        }
        if (wait != WAIT_TIMEOUT) {
          throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if (execution.ElapsedMilliseconds >= timeoutMs) {
          timedOut = true;
          break;
        }
      }
      if (descendantPid == 0) {
        descendantPid = TryAttestDescendant(job, descendantReadyPath);
      }
      if (!String.IsNullOrEmpty(descendantReadyPath) && descendantPid == 0) {
        throw new InvalidOperationException("Windows descendant readiness was not attested.");
      }

      uint rootExitCode = 1;
      if (rootExited && !GetExitCodeProcess(process.hProcess, out rootExitCode)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      if (QueryActiveProcesses(job) > 0 &&
          !TerminateJobObject(job, timedOut ? 124U : rootExitCode)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      WaitForActiveProcessZero(job, cleanupTimeoutMs);
      WriteControl(
        "CODEGRAPH_WINDOWS_JOB_TERMINAL:" + nonce + ":" +
        (timedOut ? "timeout" : "exit") + ":" + rootExitCode.ToString() +
        ":0:" + process.dwProcessId.ToString() + ":" + descendantPid.ToString());
      return 0;
    } catch {
      if (created && process.hProcess != IntPtr.Zero) {
        try {
          if (QueryActiveProcesses(job) > 0) {
            TerminateJobObject(job, 1);
          }
        } catch {
          TerminateProcess(process.hProcess, 1);
        }
      }
      throw;
    } finally {
      if (process.hThread != IntPtr.Zero) { CloseHandle(process.hThread); }
      if (process.hProcess != IntPtr.Zero) { CloseHandle(process.hProcess); }
      // KILL_ON_JOB_CLOSE 仅作为异常路径最后保险，正常结果必须先证明 ActiveProcesses=0。
      CloseHandle(job);
    }
  }
}
`,
});


const WINDOWS_JOB_HOST_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$assemblyBytes = [Convert]::FromBase64String($env:CODEGRAPH_JOB_ASSEMBLY_BASE64)
$assemblyDigest = [Convert]::ToHexString(
  [Security.Cryptography.SHA256]::HashData($assemblyBytes)
).ToLowerInvariant()
if ($assemblyDigest -ne '${WINDOWS_JOB_HOST_ARTIFACT.assemblySha256}') {
  throw 'Windows Job host assembly digest mismatch.'
}
[void][Reflection.Assembly]::Load($assemblyBytes)

function Decode-CodeGraphValue([string] $name) {
  return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($name))
}

$applicationName = Decode-CodeGraphValue $env:CODEGRAPH_JOB_APPLICATION
$commandLine = Decode-CodeGraphValue $env:CODEGRAPH_JOB_COMMAND_LINE
$workingDirectory = Decode-CodeGraphValue $env:CODEGRAPH_JOB_WORKING_DIRECTORY
$nonce = Decode-CodeGraphValue $env:CODEGRAPH_JOB_NONCE
$descendantReadyPath = Decode-CodeGraphValue $env:CODEGRAPH_JOB_DESCENDANT_READY_PATH
$timeoutMs = [int]$env:CODEGRAPH_JOB_TIMEOUT_MS
$cleanupTimeoutMs = [int]$env:CODEGRAPH_JOB_CLEANUP_TIMEOUT_MS
Remove-Item Env:CODEGRAPH_JOB_ASSEMBLY_BASE64 -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_APPLICATION -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_COMMAND_LINE -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_WORKING_DIRECTORY -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_NONCE -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_DESCENDANT_READY_PATH -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_TIMEOUT_MS -ErrorAction SilentlyContinue
Remove-Item Env:CODEGRAPH_JOB_CLEANUP_TIMEOUT_MS -ErrorAction SilentlyContinue
$exitCode = [CodeGraphWindowsJobHost]::Run(
  $applicationName,
  $commandLine,
  $workingDirectory,
  $nonce,
  $timeoutMs,
  $cleanupTimeoutMs,
  $descendantReadyPath
)
exit $exitCode
`;
/** 预编码避免高并发时通过 PowerShell stdin 解析 host 脚本造成额外启动阻塞。 */
const WINDOWS_JOB_HOST_ENCODED_COMMAND = Buffer.from(
  WINDOWS_JOB_HOST_SCRIPT,
  "utf16le",
).toString("base64");

/**
 * 以 shell:false 执行进程，并用绝对 deadline、升级终止和有界输出保证最终收敛。
 *
 * @param {{args:string[],cleanupProcessTree?:(child:import("node:child_process").ChildProcess,timeoutMs:number)=>Promise<void>,cleanupProcessTreeOnExit?:boolean,cwd?:string,env?:NodeJS.ProcessEnv,executable:string,gid?:number,killGraceMs?:number,outputLimitBytes?:number,spawnProcess?:typeof spawn,timeoutMs:number,uid?:number,windowsDescendantReadyPath?:string,windowsVerbatimArguments?:boolean}} options 进程执行参数。
 */
export function runProcessWithDeadline(options) {
  const cwd = options.cwd ?? process.cwd();
  const timeoutMs = options.timeoutMs;
  const killGraceMs = options.killGraceMs ?? DEFAULT_PROCESS_CLEANUP_GRACE_MS;
  const outputLimitBytes = options.outputLimitBytes ?? 16 * 1024 * 1024;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > MAX_NODE_TIMER_MS ||
    !Number.isSafeInteger(killGraceMs) ||
    killGraceMs <= 0 ||
    killGraceMs > MAX_NODE_TIMER_MS ||
    !Number.isSafeInteger(outputLimitBytes) ||
    outputLimitBytes <= 0 ||
    (options.windowsDescendantReadyPath !== undefined &&
      !path.win32.isAbsolute(options.windowsDescendantReadyPath))
  ) {
    throw new TypeError("进程 deadline 与终止宽限必须是 Node timer 上限内的正安全整数，输出上限必须是正安全整数。");
  }
  if (process.platform === "win32" && options.spawnProcess === undefined) {
    return runWindowsJobProcessWithDeadline({ ...options, cwd }, {
      killGraceMs,
      outputLimitBytes,
      timeoutMs,
    });
  }
  return new Promise((resolve) => {
    const stdout = createBoundedCollector(outputLimitBytes);
    const stderr = createBoundedCollector(outputLimitBytes);
    let child;
    let deadline;
    let forceKill;
    let settleFallback;
    let postExitDeadline;
    let bootstrapDeadline;
    let settled = false;
    let timedOut = false;
    let closeObserved = false;
    let resolveRootClose;
    const rootClosePromise = new Promise((resolve) => {
      resolveRootClose = resolve;
    });
    let cleanupStarted = false;
    let cleanupSucceeded = options.cleanupProcessTreeOnExit === false;
    let exitResult = null;
    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(deadline);
      clearTimeout(forceKill);
      clearTimeout(settleFallback);
      clearTimeout(postExitDeadline);
      clearTimeout(bootstrapDeadline);
      resolve({
        ...result,
        stderr: stderr.bytes(),
        stderrBytes: stderr.totalBytes(),
        stderrTruncated: stderr.truncated(),
        stdout: stdout.bytes(),
        stdoutBytes: stdout.totalBytes(),
        stdoutTruncated: stdout.truncated(),
      });
    };
    const finishExitedProcess = () => {
      if (exitResult !== null && closeObserved && cleanupSucceeded) {
        finish(exitResult);
      }
    };
    const beginExitCleanup = () => {
      if (cleanupStarted) {
        finishExitedProcess();
        return;
      }
      cleanupStarted = true;
      /** close 依赖后代释放继承的 stdio；无论 cleanup Promise 如何结束都保留硬收敛上限。 */
      postExitDeadline = setTimeout(() => {
        finish(postExitFailure(cleanupSucceeded ? "EPIPEOPEN" : "EPROCESSCLEANUPTIMEOUT"));
      }, killGraceMs);
      if (cleanupSucceeded) {
        finishExitedProcess();
        return;
      }
      const cleanup = options.cleanupProcessTree ?? ((cleanupChild, cleanupTimeoutMs) =>
        cleanupProcessTreeAfterExit(
          cleanupChild,
          cleanupTimeoutMs,
          (remainingMs) => waitForRootClose(rootClosePromise, closeObserved, remainingMs),
        ));
      void Promise.resolve()
        .then(() => cleanup(child, killGraceMs))
        .then(() => {
          if (settled) {
            return;
          }
          cleanupSucceeded = true;
          finishExitedProcess();
        })
        .catch(() => {
          finish(postExitFailure("EPROCESSCLEANUP"));
        });
    };
    try {
      const spawnProcess = options.spawnProcess ?? spawn;
      child = spawnProcess(options.executable, options.args, {
        cwd,
        /** Windows 也建立独立进程组，使 deadline 能先广播 SIGBREAK 阻止后代继续执行。 */
        detached: true,
        env: options.env ?? process.env,
        gid: options.gid,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        uid: options.uid,
        windowsHide: true,
        windowsVerbatimArguments: options.windowsVerbatimArguments === true,
      });
    } catch (error) {
      finish(spawnError(error));
      return;
    }
    const startExecutionDeadline = () => {
      if (deadline !== undefined || settled || exitResult !== null) {return;}
      deadline = setTimeout(() => {
        if (settled || exitResult !== null) {
          return;
        }
        timedOut = true;
        if (process.platform === "win32") {
          /** 先向独立进程组广播终止，再由 taskkill /T /F 验证并收敛完整进程树。 */
          void terminateProcessTree(
            child,
            "SIGKILL",
            killGraceMs,
            (remainingMs) => waitForRootClose(rootClosePromise, closeObserved, remainingMs),
          )
            .then(
              () => finish(timeoutResult()),
              () => finish(postExitFailure("EPROCESSCLEANUP")),
            );
          return;
        }
        void terminateProcessTree(child, "SIGTERM", killGraceMs).catch(() => undefined).finally(() => {
          forceKill = setTimeout(() => {
            void terminateProcessTree(child, "SIGKILL", killGraceMs).catch(() => undefined).finally(() => {
              settleFallback = setTimeout(() => finish(timeoutResult()), killGraceMs);
            });
          }, killGraceMs);
        });
      }, timeoutMs);
    };
    let waitingForJobReady = child.codegraphWindowsJobHosted === true;
    let readinessBytes = Buffer.alloc(0);
    child.stdout.on("data", (chunk) => {
      if (!waitingForJobReady) {
        stdout.append(chunk);
        return;
      }
      readinessBytes = Buffer.concat([readinessBytes, Buffer.from(chunk)]);
      if (readinessBytes.length < WINDOWS_JOB_READY_MARKER.length) {return;}
      if (!readinessBytes.subarray(0, WINDOWS_JOB_READY_MARKER.length)
        .equals(WINDOWS_JOB_READY_MARKER)) {
        timedOut = true;
        void terminateProcessTree(child, "SIGKILL", killGraceMs).catch(() => undefined)
          .finally(() => finish(postExitFailure("EPROCESSCLEANUP")));
        return;
      }
      waitingForJobReady = false;
      clearTimeout(bootstrapDeadline);
      const remaining = readinessBytes.subarray(WINDOWS_JOB_READY_MARKER.length);
      if (remaining.length > 0) {stdout.append(remaining);}
      readinessBytes = Buffer.alloc(0);
      startExecutionDeadline();
    });
    child.stderr.on("data", (chunk) => stderr.append(chunk));
    child.once("error", (error) => {
      if (!timedOut) {
        finish(spawnError(error));
      }
    });
    child.once("exit", (code, signal) => {
      if (timedOut || settled) {
        return;
      }
      clearTimeout(bootstrapDeadline);
      /** 主进程已经退出后，原执行 deadline 不得再覆盖其真实退出结论。 */
      clearTimeout(deadline);
      exitResult = processExitResult(code, signal);
      beginExitCleanup();
    });
    child.once("close", (code, signal) => {
      closeObserved = true;
      resolveRootClose();
      if (timedOut) {
        return;
      }
      clearTimeout(bootstrapDeadline);
      if (exitResult === null) {
        clearTimeout(deadline);
        exitResult = processExitResult(code, signal);
        beginExitCleanup();
      }
      finishExitedProcess();
    });
    if (waitingForJobReady) {
      /** helper 启动也只能消费既有 cleanup grace；未建立 Job 时必须 fail closed。 */
      bootstrapDeadline = setTimeout(() => {
        timedOut = true;
        void terminateProcessTree(child, "SIGKILL", killGraceMs).catch(() => undefined)
          .finally(() => finish(postExitFailure("EPROCESSCLEANUP")));
      }, killGraceMs);
    } else {
      startExecutionDeadline();
    }
  });
}

/**
 * 由 Windows Job helper 独占执行 deadline 与树终止，并只在 ActiveProcesses=0 后发布结果。
 *
 * @param {{args:string[],cwd:string,env?:NodeJS.ProcessEnv,executable:string,windowsDescendantReadyPath?:string,windowsVerbatimArguments?:boolean}} options 进程执行参数。
 * @param {{killGraceMs:number,outputLimitBytes:number,timeoutMs:number}} limits 已验证的有界资源参数。
 * @returns {Promise<object>} 绑定 Job 终态证明的执行结果。
 */
function runWindowsJobProcessWithDeadline(options, limits) {
  return new Promise((resolve) => {
    const stdout = createBoundedCollector(limits.outputLimitBytes);
    const stderr = createBoundedCollector(limits.outputLimitBytes);
    const nonce = randomBytes(16).toString("hex");
    let protocol = Buffer.alloc(0);
    let readyProof = null;
    let child;
    let outerGuard;
    let settled = false;
    const outerGuardMs = Math.min(
      MAX_NODE_TIMER_MS,
      limits.timeoutMs + limits.killGraceMs + 5_000,
    );
    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(outerGuard);
      resolve({
        ...result,
        stderr: stderr.bytes(),
        stderrBytes: stderr.totalBytes(),
        stderrTruncated: stderr.truncated(),
        stdout: stdout.bytes(),
        stdoutBytes: stdout.totalBytes(),
        stdoutTruncated: stdout.truncated(),
      });
    };
    try {
      child = spawnWindowsJobHostedProcess(options, limits, nonce);
    } catch (error) {
      finish(spawnError(error));
      return;
    }
    child.stdout.on("data", (chunk) => stdout.append(chunk));
    child.stderr.on("data", (chunk) => {
      protocol = Buffer.concat([protocol, Buffer.from(chunk)]);
      const parsed = consumeWindowsJobReadyControl(protocol, nonce);
      if (parsed !== null) {
        readyProof = parsed.proof;
        protocol = parsed.remaining;
      }
      if (protocol.length > WINDOWS_JOB_CONTROL_TAIL_BYTES) {
        const flushBytes = protocol.length - WINDOWS_JOB_CONTROL_TAIL_BYTES;
        stderr.append(protocol.subarray(0, flushBytes));
        protocol = protocol.subarray(flushBytes);
      }
    });
    child.once("error", (error) => finish(spawnError(error)));
    child.once("close", (code, signal) => {
      if (settled) {
        return;
      }
      const terminal = consumeWindowsJobTerminalControl(protocol, nonce);
      if (terminal !== null) {
        stderr.append(terminal.payload);
      } else if (protocol.length > 0) {
        stderr.append(protocol);
      }
      if (readyProof === null) {
        finish(postExitFailure("EPROCESSBOOTSTRAP"));
        return;
      }
      if (
        code !== 0 ||
        signal !== null ||
        terminal === null ||
        terminal.proof.activeProcesses !== 0
      ) {
        finish(postExitFailure("EPROCESSCLEANUP"));
        return;
      }
      const windowsJob = {
        activeProcesses: terminal.proof.activeProcesses,
        descendantPid: terminal.proof.descendantPid,
        rootPid: readyProof.rootPid,
        terminalProof: "query-information-job-object",
      };
      finish(terminal.proof.kind === "timeout"
        ? { ...timeoutResult(), windowsJob }
        : { ...processExitResult(terminal.proof.exitCode, null), windowsJob });
    });
    /** helper 失控时关闭其最后 Job 句柄仅作保险，未取得终态证明必须 fail closed。 */
    outerGuard = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /** close 事件仍负责发布唯一失败结果。 */
      }
      finish(postExitFailure("EPROCESSCLEANUPTIMEOUT"));
    }, outerGuardMs);
  });
}

/**
 * 解析 helper 在目标进程 ResumeThread 前发布的 root Job 归属证明。
 *
 * @param {Buffer} bytes 待解析的控制流尾部。
 * @param {string} nonce 当前 helper 唯一随机绑定值。
 * @returns {{proof:{activeProcesses:number,rootPid:number},remaining:Buffer}|null} 完整证明或未完成状态。
 */
function consumeWindowsJobReadyControl(bytes, nonce) {
  if (!bytes.subarray(0, 1).equals(WINDOWS_JOB_CONTROL_START)) {
    return null;
  }
  const end = bytes.indexOf(WINDOWS_JOB_CONTROL_END, 1);
  if (end < 0) {
    return null;
  }
  const fields = bytes.subarray(1, end).toString("ascii").split(":");
  if (
    fields.length !== 4 ||
    fields[0] !== "CODEGRAPH_WINDOWS_JOB_READY" ||
    fields[1] !== nonce ||
    !/^[1-9][0-9]*$/u.test(fields[2]) ||
    fields[3] !== "1"
  ) {
    return null;
  }
  return {
    proof: { activeProcesses: 1, rootPid: Number.parseInt(fields[2], 10) },
    remaining: bytes.subarray(end + 1),
  };
}

/**
 * 解析 helper 在 QueryInformationJobObject 证明零活动进程后发布的唯一终态帧。
 *
 * @param {Buffer} bytes 已保留控制帧尾部的 stderr 字节。
 * @param {string} nonce 当前 helper 唯一随机绑定值。
 * @returns {{payload:Buffer,proof:{activeProcesses:number,descendantPid:number,exitCode:number,kind:"exit"|"timeout",rootPid:number}}|null} 终态证明。
 */
function consumeWindowsJobTerminalControl(bytes, nonce) {
  const marker = Buffer.from(
    `\u001eCODEGRAPH_WINDOWS_JOB_TERMINAL:${nonce}:`,
    "ascii",
  );
  const start = bytes.lastIndexOf(marker);
  if (start < 0) {
    return null;
  }
  const end = bytes.indexOf(WINDOWS_JOB_CONTROL_END, start + marker.length);
  if (end < 0 || end !== bytes.length - 1) {
    return null;
  }
  const fields = bytes.subarray(start + marker.length, end).toString("ascii").split(":");
  if (
    fields.length !== 5 ||
    !["exit", "timeout"].includes(fields[0]) ||
    !fields.slice(1).every((value) => /^(?:0|[1-9][0-9]*)$/u.test(value))
  ) {
    return null;
  }
  const [kind, exitCode, activeProcesses, rootPid, descendantPid] = fields;
  return {
    payload: bytes.subarray(0, start),
    proof: {
      activeProcesses: Number.parseInt(activeProcesses, 10),
      descendantPid: Number.parseInt(descendantPid, 10),
      exitCode: Number.parseInt(exitCode, 10),
      kind,
      rootPid: Number.parseInt(rootPid, 10),
    },
  };
}

/** 正常退出后使用独立 deadline 清理残留后代，不复用已完成的执行 deadline。 */
function cleanupProcessTreeAfterExit(child, timeoutMs, waitForRootClose) {
  if (process.platform !== "win32") {
    return terminateProcessTree(child, "SIGTERM", timeoutMs).then(() =>
      terminateProcessTree(child, "SIGKILL", timeoutMs),
    );
  }
  if (!Number.isSafeInteger(child.pid) || child.pid <= 0) {
    return Promise.resolve();
  }
  return terminateWindowsProcessTree(
    child,
    timeoutMs,
    runWindowsTaskkill,
    verifyWindowsDescendantsConverged,
    waitForRootClose,
  );
}

/**
 * Windows 先广播独立进程组信号；taskkill 128 仅说明根 PID 不存在，必须在同一宽限内
 * 追加后代级只读快照证明，才能结算完整进程树已经收敛。
 */
async function terminateWindowsProcessTree(
  child,
  timeoutMs,
  runTaskkill = runWindowsTaskkill,
  verifyDescendants = verifyWindowsDescendantsConverged,
  waitForRootClose = async (_timeoutMs) => undefined,
) {
  const cleanupDeadline = Date.now() + timeoutMs;
  if (child.codegraphWindowsJobHosted === true) {
    if (child.exitCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        /** close 等待仍会在同一 cleanup grace 内证明 helper 与 Job 已收敛。 */
      }
    }
    const remainingMs = cleanupDeadline - Date.now();
    if (remainingMs <= 0) {
      throw new Error("Windows Job Object cleanup deadline exhausted.");
    }
    await waitForRootClose(remainingMs);
    return;
  }
  const taskkillOutcome = runTaskkill(child.pid, timeoutMs);
  try {
    child.kill("SIGBREAK");
  } catch {
    /** taskkill 仍是权威树级收敛路径，广播失败不能提前结算。 */
  }
  const outcome = await taskkillOutcome;
  const code = outcome?.code ?? 0;
  if (code === 0) {return;}
  if (code !== 128) {
    throw new Error(`taskkill exited with code ${code ?? "unknown"}.`);
  }
  let remainingMs = cleanupDeadline - Date.now();
  if (remainingMs <= 0) {
    throw new Error("Windows process tree cleanup deadline exhausted.");
  }
  await waitForRootClose(remainingMs);
  remainingMs = cleanupDeadline - Date.now();
  if (remainingMs <= 0 || !await verifyDescendants(child.pid, remainingMs)) {
    throw new Error("Windows detached descendants remain after taskkill root disappearance.");
  }
}

/**
 * 启动只负责 Job 生命周期的固定 helper，目标进程由 helper 使用 CREATE_SUSPENDED 创建。
 *
 * @param {{args:string[],cwd:string,env?:NodeJS.ProcessEnv,executable:string,windowsDescendantReadyPath?:string,windowsVerbatimArguments?:boolean}} options 目标执行参数。
 * @param {{killGraceMs:number,timeoutMs:number}} limits helper 自持有的 deadline 参数。
 * @param {string} nonce 不传播给目标进程的控制帧绑定值。
 * @returns {import("node:child_process").ChildProcess} Windows helper 子进程。
 */
function spawnWindowsJobHostedProcess(options, limits, nonce) {
  const commandLine = buildWindowsCommandLine(
    options.executable,
    options.args,
    options.windowsVerbatimArguments === true,
  );
  const applicationName = path.win32.isAbsolute(options.executable) ? options.executable : "";
  const env = {
    ...(options.env ?? process.env),
    CODEGRAPH_JOB_APPLICATION: Buffer.from(applicationName, "utf8").toString("base64"),
    CODEGRAPH_JOB_ASSEMBLY_BASE64: WINDOWS_JOB_HOST_ARTIFACT.assemblyBase64,
    CODEGRAPH_JOB_CLEANUP_TIMEOUT_MS: `${limits.killGraceMs}`,
    CODEGRAPH_JOB_COMMAND_LINE: Buffer.from(commandLine, "utf8").toString("base64"),
    CODEGRAPH_JOB_DESCENDANT_READY_PATH: Buffer.from(
      options.windowsDescendantReadyPath ?? "",
      "utf8",
    ).toString("base64"),
    CODEGRAPH_JOB_NONCE: Buffer.from(nonce, "utf8").toString("base64"),
    CODEGRAPH_JOB_TIMEOUT_MS: `${limits.timeoutMs}`,
    CODEGRAPH_JOB_WORKING_DIRECTORY: Buffer.from(options.cwd, "utf8").toString("base64"),
  };
  /** helper 不进入目标目录，避免启动阶段失败时自身工作目录阻塞临时仓库回收。 */
  const helperCwd = process.env.SystemRoot ?? path.win32.parse(options.cwd).root;
  const helper = spawn(
    WINDOWS_JOB_SHELL_EXECUTABLE,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", WINDOWS_JOB_HOST_ENCODED_COMMAND],
    {
      cwd: helperCwd,
      detached: false,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      windowsVerbatimArguments: false,
    },
  );
  return helper;
}

/** 复刻 CreateProcess/CommandLineToArgvW 的反斜线与引号规则。 */
function buildWindowsCommandLine(executable, args, verbatimArguments) {
  const executableText = quoteWindowsCommandArgument(executable);
  if (verbatimArguments) {
    return [executableText, ...args].join(" ");
  }
  return [executableText, ...args.map(quoteWindowsCommandArgument)].join(" ");
}

/** 单个 Windows argv 元素在空白、引号和尾随反斜线处必须保持可逆。 */
function quoteWindowsCommandArgument(value) {
  if (value.length === 0) {return '\"\"';}
  if (!/[\s"]/u.test(value)) {return value;}
  let quoted = '\"';
  let backslashes = 0;
  for (const character of value) {
    if (character === "\\") {
      backslashes += 1;
    } else if (character === '\"') {
      quoted += "\\".repeat(backslashes * 2 + 1) + '\"';
      backslashes = 0;
    } else {
      quoted += "\\".repeat(backslashes) + character;
      backslashes = 0;
    }
  }
  return `${quoted}${"\\".repeat(backslashes * 2)}\"`;
}

/** 测试注入只替换 taskkill 与后代验证结果，生产调用仍使用真实异步系统命令。 */
export function terminateWindowsProcessTreeForTests(
  child,
  timeoutMs,
  runTaskkill,
  verifyDescendants = async (_rootPid, _timeoutMs) => true,
  waitForRootClose = async (_timeoutMs) => undefined,
) {
  return terminateWindowsProcessTree(
    child,
    timeoutMs,
    () => runTaskkill(),
    verifyDescendants,
    waitForRootClose,
  );
}

/** 使用异步 taskkill 和独立 timeout 回收 Windows 进程树，禁止阻塞事件循环。 */
function runWindowsTaskkill(pid, timeoutMs) {
  return new Promise((resolve, reject) => {
    let complete = false;
    let cleanupChild;
    const finish = (error, outcome) => {
      if (complete) {
        return;
      }
      complete = true;
      clearTimeout(fallback);
      if (error === undefined) {
        resolve(outcome);
      } else {
        reject(error);
      }
    };
    const fallback = setTimeout(() => {
      cleanupChild?.kill();
      finish(new Error("Windows process tree cleanup timed out."));
    }, timeoutMs);
    try {
      cleanupChild = spawn(
        "taskkill.exe",
        ["/PID", `${pid}`, "/T", "/F"],
        { stdio: "ignore", windowsHide: true },
      );
      cleanupChild.once("error", (error) => finish(error));
      cleanupChild.once("close", (code) => {
        /** 128 只证明根 PID 不存在，调用方必须继续验证后代快照。 */
        finish(
          code === 0 || code === 128
            ? undefined
            : new Error(`taskkill exited with code ${code ?? "unknown"}.`),
          Object.freeze({ code }),
        );
      });
    } catch (error) {
      finish(error instanceof Error ? error : new Error("taskkill spawn failed."));
    }
  });
}

/**
 * 通过单次 CIM 进程快照递归检查原根 PID 的全部后代；任何查询失败都拒绝提供收敛证明。
 */
function verifyWindowsDescendantsConverged(rootPid, timeoutMs) {
  return new Promise((resolve, reject) => {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
      reject(new Error("Windows descendant verification deadline exhausted."));
      return;
    }
    const script = [
      "$ErrorActionPreference='Stop'",
      `$rootProcessId=[uint32]${rootPid}`,
      "$processes=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId)",
      "$frontier=[System.Collections.Generic.Queue[uint32]]::new()",
      "$seen=[System.Collections.Generic.HashSet[uint32]]::new()",
      "$frontier.Enqueue($rootProcessId)",
      "$found=$false",
      "while($frontier.Count -gt 0){$parent=$frontier.Dequeue();foreach($process in $processes){$processId=[uint32]$process.ProcessId;if([uint32]$process.ParentProcessId -eq $parent -and $seen.Add($processId)){$found=$true;$frontier.Enqueue($processId)}}}",
      "if($found){exit 1}else{exit 0}",
    ].join(";");
    let complete = false;
    let verifier;
    const finish = (error, converged) => {
      if (complete) {return;}
      complete = true;
      clearTimeout(fallback);
      if (error === undefined) {resolve(converged);}
      else {reject(error);}
    };
    const fallback = setTimeout(() => {
      verifier?.kill();
      finish(new Error("Windows descendant verification timed out."), false);
    }, timeoutMs);
    try {
      verifier = spawn(
        "powershell.exe",
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        { stdio: "ignore", windowsHide: true },
      );
      verifier.once("error", (error) => finish(error, false));
      verifier.once("close", (code) => {
        if (code === 0) {finish(undefined, true);}
        else if (code === 1) {finish(undefined, false);}
        else {finish(new Error(`descendant verification exited with code ${code ?? "unknown"}.`), false);}
      });
    } catch (error) {
      finish(
        error instanceof Error ? error : new Error("descendant verification spawn failed."),
        false,
      );
    }
  });
}

/** 终止完整进程树；POSIX 使用独立进程组，Windows 使用 taskkill /T。 */
async function terminateProcessTree(child, signal, timeoutMs, waitForRootClose) {
  if (!Number.isSafeInteger(child.pid) || child.pid <= 0) {
    return;
  }
  if (process.platform === "win32") {
    await terminateWindowsProcessTree(
      child,
      timeoutMs,
      runWindowsTaskkill,
      verifyWindowsDescendantsConverged,
      waitForRootClose,
    );
    return;
  }
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (!(error && typeof error === "object" && error.code === "ESRCH")) {
      child.kill(signal);
    }
  }
}

/**
 * 在既有清理宽限内等待根进程 close；只消费同一 deadline，不增加轮询或重试。
 */
function waitForRootClose(rootClosePromise, closeObserved, timeoutMs) {
  if (closeObserved) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    let complete = false;
    const finish = (error) => {
      if (complete) {return;}
      complete = true;
      clearTimeout(fallback);
      if (error === undefined) {resolve();}
      else {reject(error);}
    };
    const fallback = setTimeout(
      () => finish(new Error("Windows root process close timed out.")),
      timeoutMs,
    );
    void rootClosePromise.then(() => finish(undefined));
  });
}

/** 缓存主进程的真实退出结论，供 close 与独立 cleanup 完成后统一发布。 */
function processExitResult(code, signal) {
  return {
    status: code === 0 ? "pass" : "fail",
    termination:
      signal === null
        ? { code: code ?? 1, kind: "exit" }
        : { kind: "signal", signalName: signal },
  };
}

/** 创建只保留固定上限、同时记录原始总字节数的 collector。 */
function createBoundedCollector(limitBytes) {
  const chunks = [];
  let capturedBytes = 0;
  let totalBytes = 0;
  return {
    append(chunk) {
      const buffer = Buffer.from(chunk);
      totalBytes += buffer.length;
      const remaining = limitBytes - capturedBytes;
      if (remaining > 0) {
        const captured = buffer.subarray(0, remaining);
        chunks.push(captured);
        capturedBytes += captured.length;
      }
    },
    bytes: () => Buffer.concat(chunks),
    totalBytes: () => totalBytes,
    truncated: () => totalBytes > capturedBytes,
  };
}

/** 将启动异常收敛为不泄露本机路径或堆栈的稳定 invalid。 */
function spawnError(error) {
  return {
    status: "invalid",
    termination: {
      kind: "spawn-error",
      stableCode:
        typeof error === "object" && error !== null && typeof error.code === "string"
          ? error.code
          : "UNKNOWN",
    },
  };
}

/** deadline 到期统一使用稳定 ETIMEDOUT，不依赖平台信号名称。 */
function timeoutResult() {
  return {
    status: "invalid",
    termination: { kind: "spawn-error", stableCode: "ETIMEDOUT" },
  };
}

/** cleanup 或 stdio 收敛失败统一返回稳定 invalid，不得保留原进程 pass。 */
function postExitFailure(stableCode) {
  return {
    status: "invalid",
    termination: { kind: "spawn-error", stableCode },
  };
}
